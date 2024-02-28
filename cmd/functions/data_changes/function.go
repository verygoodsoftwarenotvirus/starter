package datachangesfunction

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/verygoodsoftwarenotvirus/starter/internal/analytics"
	analyticsconfig "github.com/verygoodsoftwarenotvirus/starter/internal/analytics/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/database/postgres"
	"github.com/verygoodsoftwarenotvirus/starter/internal/email"
	"github.com/verygoodsoftwarenotvirus/starter/internal/messagequeue"
	msgconfig "github.com/verygoodsoftwarenotvirus/starter/internal/messagequeue/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	loggingcfg "github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/internal/search"
	"github.com/verygoodsoftwarenotvirus/starter/internal/search/indexing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"

	_ "github.com/GoogleCloudPlatform/functions-framework-go/funcframework"
	"github.com/GoogleCloudPlatform/functions-framework-go/functions"
	_ "github.com/KimMachineGun/automemlimit"
	"github.com/cloudevents/sdk-go/v2/event"
	"go.opentelemetry.io/otel"
	_ "go.uber.org/automaxprocs"
)

func init() {
	// Register a CloudEvent function with the Functions Framework
	functions.CloudEvent("ProcessDataChange", ProcessDataChange)
}

var (
	errRequiredDataIsNil = errors.New("required data is nil")

	nonWebhookEventTypes = []types.ServiceEventType{
		types.UserSignedUpCustomerEventType,
		types.UserArchivedCustomerEventType,
		types.TwoFactorSecretVerifiedCustomerEventType,
		types.TwoFactorDeactivatedCustomerEventType,
		types.TwoFactorSecretChangedCustomerEventType,
		types.PasswordResetTokenCreatedEventType,
		types.PasswordResetTokenRedeemedEventType,
		types.PasswordChangedEventType,
		types.EmailAddressChangedEventType,
		types.UsernameChangedEventType,
		types.UserDetailsChangedEventType,
		types.UsernameReminderRequestedEventType,
		types.UserLoggedInCustomerEventType,
		types.UserLoggedOutCustomerEventType,
		types.UserChangedActiveAccountCustomerEventType,
		types.UserEmailAddressVerifiedEventType,
		types.UserEmailAddressVerificationEmailRequestedEventType,
		types.AccountMemberRemovedCustomerEventType,
		types.AccountMembershipPermissionsUpdatedCustomerEventType,
		types.AccountOwnershipTransferredCustomerEventType,
		types.OAuth2ClientCreatedCustomerEventType,
		types.OAuth2ClientArchivedCustomerEventType,
	}
)

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

// ProcessDataChange handles a data change.
func ProcessDataChange(ctx context.Context, e event.Event) error {
	if strings.TrimSpace(strings.ToLower(os.Getenv("CEASE_OPERATION"))) == "true" {
		slog.Info("CEASE_OPERATION is set to true, exiting")
		return nil
	}

	logger := (&loggingcfg.Config{Level: logging.DebugLevel, Provider: loggingcfg.ProviderSlog}).ProvideLogger()

	var msg MessagePublishedData
	if err := e.DataAs(&msg); err != nil {
		return fmt.Errorf("event.DataAs: %w", err)
	}

	cfg, err := config.GetDataChangesWorkerConfigFromGoogleCloudSecretManager(ctx)
	if err != nil {
		return fmt.Errorf("error getting config: %w", err)
	}

	tracerProvider, initializeTracerErr := cfg.Observability.Tracing.ProvideTracerProvider(ctx, logger)
	if initializeTracerErr != nil {
		logger.Error(initializeTracerErr, "initializing tracer")
	}
	otel.SetTracerProvider(tracerProvider)

	tracer := tracing.NewTracer(tracing.EnsureTracerProvider(tracerProvider).Tracer("data_changes_job"))

	ctx, span := tracer.StartSpan(ctx)
	defer span.End()

	analyticsEventReporter, err := analyticsconfig.ProvideEventReporter(&cfg.Analytics, logger, tracerProvider)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "setting up customer data collector")
	}

	defer analyticsEventReporter.Close()

	publisherProvider, err := msgconfig.ProvidePublisherProvider(ctx, logger, tracerProvider, &cfg.Events)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "configuring queue manager")
	}

	defer publisherProvider.Close()

	outboundEmailsPublisher, err := publisherProvider.ProvidePublisher(os.Getenv("OUTBOUND_EMAILS_TOPIC_NAME"))
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "configuring outbound emails publisher")
	}

	defer outboundEmailsPublisher.Stop()

	searchDataIndexPublisher, err := publisherProvider.ProvidePublisher(os.Getenv("SEARCH_INDEXING_TOPIC_NAME"))
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "configuring search indexing publisher")
	}

	defer searchDataIndexPublisher.Stop()

	webhookExecutionRequestPublisher, err := publisherProvider.ProvidePublisher(os.Getenv("WEBHOOK_EXECUTION_REQUESTS_TOPIC_NAME"))
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "configuring search indexing publisher")
	}

	defer webhookExecutionRequestPublisher.Stop()

	// manual db timeout until I find out what's wrong
	dbConnectionContext, cancel := context.WithTimeout(ctx, 15*time.Second)
	dataManager, err := postgres.ProvideDatabaseClient(dbConnectionContext, logger, tracerProvider, &cfg.Database)
	if err != nil {
		cancel()
		return observability.PrepareAndLogError(err, logger, span, "establishing database connection")
	}

	cancel()
	defer dataManager.Close()

	var changeMessage types.DataChangeMessage
	if err = json.Unmarshal(msg.Message.Data, &changeMessage); err != nil {
		logger = logger.WithValue("raw_data", msg.Message.Data)
		return observability.PrepareAndLogError(err, logger, span, "unmarshalling data change message")
	}

	logger = logger.WithValue("event_type", changeMessage.EventType)

	if changeMessage.UserID != "" && changeMessage.EventType != "" {
		if err = analyticsEventReporter.EventOccurred(ctx, changeMessage.EventType, changeMessage.UserID, changeMessage.Context); err != nil {
			observability.AcknowledgeError(err, logger, span, "notifying customer data platform")
		}
	}

	var wg sync.WaitGroup

	go func() {
		wg.Add(1)
		if changeMessage.AccountID != "" && !slices.Contains(nonWebhookEventTypes, changeMessage.EventType) {
			var relevantWebhooks []*types.Webhook
			relevantWebhooks, err = dataManager.GetWebhooksForAccountAndEvent(ctx, changeMessage.AccountID, changeMessage.EventType)
			if err != nil {
				observability.AcknowledgeError(err, logger, span, "getting webhooks")
			}

			for _, webhook := range relevantWebhooks {
				if err = webhookExecutionRequestPublisher.Publish(ctx, &types.WebhookExecutionRequest{
					WebhookID: webhook.ID,
					AccountID: changeMessage.AccountID,
					Payload:   changeMessage,
				}); err != nil {
					observability.AcknowledgeError(err, logger, span, "publishing webhook execution request")
				}
			}
		}
		wg.Done()
	}()

	go func() {
		wg.Add(1)
		if err = handleOutboundNotifications(ctx, logger, tracer, outboundEmailsPublisher, analyticsEventReporter, &changeMessage); err != nil {
			observability.AcknowledgeError(err, logger, span, "notifying customer(s)")
		}
		wg.Done()
	}()

	go func() {
		wg.Add(1)
		if err = handleSearchIndexUpdates(ctx, logger, tracer, searchDataIndexPublisher, &changeMessage); err != nil {
			observability.AcknowledgeError(err, logger, span, "updating search index)")
		}
		wg.Done()
	}()

	wg.Wait()

	return nil
}

func handleSearchIndexUpdates(
	ctx context.Context,
	l logging.Logger,
	tracer tracing.Tracer,
	searchDataIndexPublisher messagequeue.Publisher,
	changeMessage *types.DataChangeMessage,
) error {
	ctx, span := tracer.StartSpan(ctx)
	defer span.End()

	logger := l.WithValue("event_type", changeMessage.EventType)

	switch changeMessage.EventType {
	case types.UserSignedUpCustomerEventType,
		types.UserArchivedCustomerEventType,
		types.EmailAddressChangedEventType,
		types.UsernameChangedEventType,
		types.UserDetailsChangedEventType,
		types.UserEmailAddressVerifiedEventType:
		if changeMessage.UserID == "" {
			observability.AcknowledgeError(errRequiredDataIsNil, logger, span, "updating search index for User")
		}

		if err := searchDataIndexPublisher.Publish(ctx, &indexing.IndexRequest{
			RowID:     changeMessage.UserID,
			IndexType: search.IndexTypeUsers,
			Delete:    changeMessage.EventType == types.UserArchivedCustomerEventType,
		}); err != nil {
			return observability.PrepareAndLogError(err, logger, span, "publishing search index update")
		}

		return nil
	default:
		logger.Debug("event type not handled for search indexing")
		return nil
	}
}

func handleOutboundNotifications(
	ctx context.Context,
	l logging.Logger,
	tracer tracing.Tracer,
	outboundEmailsPublisher messagequeue.Publisher,
	analyticsEventReporter analytics.EventReporter,
	changeMessage *types.DataChangeMessage,
) error {
	ctx, span := tracer.StartSpan(ctx)
	defer span.End()

	var (
		emailType string
		edrs      []*email.DeliveryRequest
	)

	logger := l.WithValue("event_type", changeMessage.EventType)

	switch changeMessage.EventType {
	case types.UserSignedUpCustomerEventType:
		emailType = "user signup"
		if err := analyticsEventReporter.AddUser(ctx, changeMessage.UserID, changeMessage.Context); err != nil {
			observability.AcknowledgeError(err, logger, span, "notifying customer data platform")
		}

		edrs = append(edrs, &email.DeliveryRequest{
			UserID:                 changeMessage.UserID,
			Template:               email.TemplateTypeVerifyEmailAddress,
			EmailVerificationToken: changeMessage.EmailVerificationToken,
		})
	case types.UserEmailAddressVerificationEmailRequestedEventType:
		emailType = "email address verification"

		edrs = append(edrs, &email.DeliveryRequest{
			UserID:                 changeMessage.UserID,
			Template:               email.TemplateTypeVerifyEmailAddress,
			EmailVerificationToken: changeMessage.EmailVerificationToken,
		})
	case types.PasswordResetTokenCreatedEventType:
		emailType = "password reset request"
		if changeMessage.PasswordResetToken == nil {
			return observability.PrepareError(fmt.Errorf("password reset token is nil"), span, "publishing password reset token email")
		}

		edrs = append(edrs, &email.DeliveryRequest{
			UserID:             changeMessage.UserID,
			Template:           email.TemplateTypePasswordResetTokenCreated,
			PasswordResetToken: changeMessage.PasswordResetToken,
		})

	case types.UsernameReminderRequestedEventType:
		emailType = "username reminder"
		edrs = append(edrs, &email.DeliveryRequest{
			UserID:   changeMessage.UserID,
			Template: email.TemplateTypeUsernameReminder,
		})

	case types.PasswordResetTokenRedeemedEventType:
		emailType = "password reset token redeemed"
		edrs = append(edrs, &email.DeliveryRequest{
			UserID:   changeMessage.UserID,
			Template: email.TemplateTypePasswordResetTokenRedeemed,
		})

	case types.PasswordChangedEventType:
		emailType = "password reset token redeemed"
		edrs = append(edrs, &email.DeliveryRequest{
			UserID:   changeMessage.UserID,
			Template: email.TemplateTypePasswordReset,
		})

	case types.AccountInvitationCreatedCustomerEventType:
		emailType = "account invitation created"
		if changeMessage.AccountInvitation == nil {
			return observability.PrepareError(fmt.Errorf("account invitation is nil"), span, "publishing password reset token redemption email")
		}

		edrs = append(edrs, &email.DeliveryRequest{
			UserID:     changeMessage.UserID,
			Template:   email.TemplateTypeInvite,
			Invitation: changeMessage.AccountInvitation,
		})
	}

	if len(edrs) == 0 {
		logger.WithValue("email_type", emailType).WithValue("outbound_emails_to_send", len(edrs)).Info("publishing email requests")
	}

	for _, edr := range edrs {
		if err := outboundEmailsPublisher.Publish(ctx, edr); err != nil {
			observability.AcknowledgeError(err, logger, span, "publishing %s request email", emailType)
		}
	}

	return nil
}
