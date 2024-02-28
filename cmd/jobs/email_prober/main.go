package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strings"

	"github.com/verygoodsoftwarenotvirus/starter/internal/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/email"
	emailconfig "github.com/verygoodsoftwarenotvirus/starter/internal/email/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	loggingcfg "github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"

	_ "github.com/KimMachineGun/automemlimit"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	_ "go.uber.org/automaxprocs"
)

func doTheThing() error {
	ctx := context.Background()

	if strings.TrimSpace(strings.ToLower(os.Getenv("CEASE_OPERATION"))) == "true" {
		slog.Info("CEASE_OPERATION is set to true, exiting")
		return nil
	}

	logger := (&loggingcfg.Config{Level: logging.DebugLevel, Provider: loggingcfg.ProviderSlog}).ProvideLogger()

	cfg, err := config.GetEmailProberConfigFromGoogleCloudSecretManager(ctx)
	if err != nil {
		return fmt.Errorf("error getting config: %w", err)
	}

	tracerProvider, initializeTracerErr := cfg.Observability.Tracing.ProvideTracerProvider(ctx, logger)
	if initializeTracerErr != nil {
		logger.Error(initializeTracerErr, "initializing tracer")
	}
	otel.SetTracerProvider(tracerProvider)

	ctx, span := tracing.NewTracer(tracing.EnsureTracerProvider(tracerProvider).Tracer("email_prober_job")).StartSpan(ctx)
	defer span.End()

	emailer, err := emailconfig.ProvideEmailer(&cfg.Email, logger, tracerProvider, otelhttp.DefaultClient)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "configuring outbound emailer")
	}

	return emailer.SendEmail(ctx, &email.OutboundEmailMessage{
		ToAddress:   "something@somethingelse.com",
		ToName:      "Alice",
		FromAddress: "email@whatever.dev",
		FromName:    "Testing",
		Subject:     "Testing",
		HTMLContent: "Hi",
	})
}

func main() {
	if err := doTheThing(); err != nil {
		log.Fatal(err)
	}
}
