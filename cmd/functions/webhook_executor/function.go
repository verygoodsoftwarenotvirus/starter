package webhookexecutor

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/verygoodsoftwarenotvirus/starter/internal/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/database/postgres"
	"github.com/verygoodsoftwarenotvirus/starter/internal/email"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	loggingcfg "github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"

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
	functions.CloudEvent("ExecuteWebhook", ExecuteWebhook)
}

type MessagePublishedData struct {
	Message PubSubMessage
}

type PubSubMessage struct {
	Data []byte `json:"data"`
}

// ExecuteWebhook handles a data change.
func ExecuteWebhook(ctx context.Context, e event.Event) error {
	if strings.TrimSpace(strings.ToLower(os.Getenv("CEASE_OPERATION"))) == "true" {
		slog.Info("CEASE_OPERATION is set to true, exiting")
		return nil
	}

	logger := (&loggingcfg.Config{Level: logging.DebugLevel, Provider: loggingcfg.ProviderSlog}).ProvideLogger()

	envCfg := email.GetConfigForEnvironment(os.Getenv("COMPANY_NAME_SERVICE_ENVIRONMENT"))
	if envCfg == nil {
		return observability.PrepareAndLogError(email.ErrMissingEnvCfg, logger, nil, "getting environment config")
	}

	cfg, err := config.GetSearchDataIndexerConfigFromGoogleCloudSecretManager(ctx)
	if err != nil {
		return fmt.Errorf("error getting config: %w", err)
	}

	tracerProvider, err := cfg.Observability.Tracing.ProvideTracerProvider(ctx, logger)
	if err != nil {
		logger.Error(err, "initializing tracer")
	}
	otel.SetTracerProvider(tracerProvider)

	tracer := tracing.NewTracer(tracing.EnsureTracerProvider(tracerProvider).Tracer("search_indexer_cloud_function"))
	ctx, span := tracer.StartSpan(ctx)
	defer span.End()

	// manual db timeout until I find out what's wrong
	dbConnectionContext, cancel := context.WithTimeout(ctx, 15*time.Second)
	dataManager, err := postgres.ProvideDatabaseClient(dbConnectionContext, logger, tracerProvider, &cfg.Database)
	if err != nil {
		cancel()
		return observability.PrepareAndLogError(err, logger, span, "establishing database connection")
	}

	cancel()
	defer dataManager.Close()

	var msg MessagePublishedData
	if err = e.DataAs(&msg); err != nil {
		return fmt.Errorf("event.DataAs: %w", err)
	}

	var webhookExecutionRequest *types.WebhookExecutionRequest
	if err = json.Unmarshal(msg.Message.Data, &webhookExecutionRequest); err != nil {
		logger = logger.WithValue("raw_data", msg.Message.Data)
		return observability.PrepareAndLogError(err, logger, span, "unmarshalling data change message")
	}

	account, err := dataManager.GetAccount(ctx, webhookExecutionRequest.AccountID)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "getting account")
	}
	_ = account

	webhook, err := dataManager.GetWebhook(ctx, webhookExecutionRequest.WebhookID, webhookExecutionRequest.AccountID)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "getting webhook")
		return nil
	}

	var payloadBody []byte
	switch webhook.ContentType {
	case "application/json":
		payloadBody, err = json.Marshal(webhookExecutionRequest.Payload)
		if err != nil {
			return observability.PrepareAndLogError(err, logger, span, "marshalling webhook payload")
		}
	case "application/xml":
		payloadBody, err = xml.Marshal(webhookExecutionRequest.Payload)
		if err != nil {
			return observability.PrepareAndLogError(err, logger, span, "marshalling webhook payload")
		}
	}

	req, err := http.NewRequest(webhook.Method, webhook.URL, bytes.NewReader(payloadBody))
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "creating webhook request")
	}

	req.Header.Set("Content-Type", webhook.ContentType)

	decryptedKey, err := hex.DecodeString(account.WebhookEncryptionKey)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "decoding webhook encryption key")
	}

	digest := hmac.New(sha256.New, decryptedKey)
	digest.Write(payloadBody)
	req.Header.Set("X-Service-Signature", hex.EncodeToString(digest.Sum(nil)))

	res, err := otelhttp.DefaultClient.Do(req)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "executing webhook request")
		return nil
	}

	logger = logger.WithResponse(res)
	tracing.AttachResponseToSpan(span, res)

	if res.StatusCode < 200 || res.StatusCode > 299 {
		observability.AcknowledgeError(err, logger, span, "invalid response type")
		return nil
	}

	return nil
}
