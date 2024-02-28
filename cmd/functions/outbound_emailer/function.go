package outboundemailerfunction

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	analyticsconfig "github.com/verygoodsoftwarenotvirus/starter/internal/analytics/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/database/postgres"
	"github.com/verygoodsoftwarenotvirus/starter/internal/email"
	emailconfig "github.com/verygoodsoftwarenotvirus/starter/internal/email/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	loggingcfg "github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"

	_ "github.com/GoogleCloudPlatform/functions-framework-go/funcframework"
	"github.com/GoogleCloudPlatform/functions-framework-go/functions"
	_ "github.com/KimMachineGun/automemlimit"
	"github.com/cloudevents/sdk-go/v2/event"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	_ "go.uber.org/automaxprocs"
)

func init() {
	// Register a CloudEvent function with the Functions Framework
	functions.CloudEvent("SendEmail", SendEmail)
}

// MessagePublishedData contains the full Pub/Sub message
// See the documentation for more details:
// https://cloud.google.com/eventarc/docs/cloudevents#pubsub
type MessagePublishedData struct {
	Message PubSubMessage
}

// PubSubMessage is the payload of a Pub/Sub event.
// See the documentation for more details:
// https://cloud.google.com/pubsub/docs/reference/rest/v1/PubsubMessage
type PubSubMessage struct {
	Data []byte `json:"data"`
}

// SendEmail handles sending an email.
func SendEmail(ctx context.Context, e event.Event) error {
	if strings.TrimSpace(strings.ToLower(os.Getenv("CEASE_OPERATION"))) == "true" {
		slog.Info("CEASE_OPERATION is set to true, exiting")
		return nil
	}

	logger := (&loggingcfg.Config{Level: logging.DebugLevel, Provider: loggingcfg.ProviderSlog}).ProvideLogger()

	envCfg := email.GetConfigForEnvironment(os.Getenv("COMPANY_NAME_SERVICE_ENVIRONMENT"))
	if envCfg == nil {
		return observability.PrepareAndLogError(email.ErrMissingEnvCfg, logger, nil, "getting environment config")
	}

	cfg, err := config.GetOutboundEmailerConfigFromGoogleCloudSecretManager(ctx)
	if err != nil {
		return fmt.Errorf("error getting config: %w", err)
	}

	tracerProvider, err := cfg.Observability.Tracing.ProvideTracerProvider(ctx, logger)
	if err != nil {
		logger.Error(err, "initializing tracer")
	}
	otel.SetTracerProvider(tracerProvider)

	ctx, span := tracing.NewTracer(tracing.EnsureTracerProvider(tracerProvider).Tracer("outbound_emailer_job")).StartSpan(ctx)
	defer span.End()

	analyticsEventReporter, err := analyticsconfig.ProvideEventReporter(&cfg.Analytics, logger, tracerProvider)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "setting up customer data collector")
	}

	defer analyticsEventReporter.Close()

	// manual db timeout until I find out what's wrong
	dbConnectionContext, cancel := context.WithTimeout(ctx, 15*time.Second)
	dataManager, err := postgres.ProvideDatabaseClient(dbConnectionContext, logger, tracerProvider, &cfg.Database)
	if err != nil {
		cancel()
		return observability.PrepareAndLogError(err, logger, span, "establishing database connection")
	}

	cancel()
	defer dataManager.Close()

	emailer, err := emailconfig.ProvideEmailer(&cfg.Email, logger, tracerProvider, otelhttp.DefaultClient)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "configuring outbound emailer")
	}

	var msg MessagePublishedData
	if err = e.DataAs(&msg); err != nil {
		return fmt.Errorf("event.DataAs: %w", err)
	}

	var emailDeliveryRequest email.DeliveryRequest
	if err = json.Unmarshal(msg.Message.Data, &emailDeliveryRequest); err != nil {
		logger = logger.WithValue("raw_data", msg.Message.Data)
		return observability.PrepareAndLogError(err, logger, span, "unmarshalling delivery request message")
	}

	logger = logger.WithValue("template", emailDeliveryRequest.Template)

	user, err := dataManager.GetUser(ctx, emailDeliveryRequest.UserID)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "getting user")
	}

	var (
		mail                   *email.OutboundEmailMessage
		shouldSkipIfUnverified = true
		emailType              string
	)

	switch emailDeliveryRequest.Template {
	case email.TemplateTypeInvite:
		if emailDeliveryRequest.Invitation == nil {
			return observability.PrepareAndLogError(err, logger, span, "missing account invitation")
		}

		mail, err = email.BuildInviteMemberEmail(emailDeliveryRequest.Invitation, envCfg)
		if err != nil {
			return observability.PrepareAndLogError(err, logger, span, "building email message")
		}
		emailType = "invite"
	case email.TemplateTypeUsernameReminder:
		mail, err = email.BuildUsernameReminderEmail(user, envCfg)
		if err != nil {
			return observability.PrepareAndLogError(err, logger, span, "building username reminder email")
		}
		emailType = "username reminder"
	case email.TemplateTypePasswordResetTokenCreated:
		if emailDeliveryRequest.PasswordResetToken == nil {
			return observability.PrepareAndLogError(err, logger, span, "missing password reset token")
		}

		mail, err = email.BuildGeneratedPasswordResetTokenEmail(user, emailDeliveryRequest.PasswordResetToken, envCfg)
		if err != nil {
			return observability.PrepareAndLogError(err, logger, span, "building password reset token created email")
		}
		emailType = "password reset token"
	case email.TemplateTypePasswordReset:
		mail, err = email.BuildPasswordChangedEmail(user, envCfg)
		if err != nil {
			return observability.PrepareAndLogError(err, logger, span, "building password reset token email")
		}
		emailType = "password reset token"
	case email.TemplateTypePasswordResetTokenRedeemed:
		mail, err = email.BuildPasswordResetTokenRedeemedEmail(user, envCfg)
		if err != nil {
			return observability.PrepareAndLogError(err, logger, span, "building password reset token redemption email")
		}
		emailType = "password reset token redemption"
	case email.TemplateTypeVerifyEmailAddress:
		shouldSkipIfUnverified = false
		mail, err = email.BuildVerifyEmailAddressEmail(user, emailDeliveryRequest.EmailVerificationToken, envCfg)
		if err != nil {
			return observability.PrepareAndLogError(err, logger, span, "building address verification email")
		}
		emailType = "email address verification"
	}

	if shouldSkipIfUnverified && user.EmailAddressVerifiedAt == nil {
		logger.Info("user email address not verified, skipping email delivery")
		return nil
	}

	logger.Info("sending email")

	if err = emailer.SendEmail(ctx, mail); err != nil {
		observability.AcknowledgeError(err, logger, span, "sending %s email", emailType)
	}

	if err = analyticsEventReporter.EventOccurred(ctx, email.SentEventType, emailDeliveryRequest.UserID, emailDeliveryRequest.TemplateParams); err != nil {
		observability.AcknowledgeError(err, logger, span, "notifying customer data platform")
	}

	return nil
}
