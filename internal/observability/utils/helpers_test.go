package o11yutils

import (
	"context"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging/slog"
	tracingcfg "github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing/oteltracehttp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestObserveValue(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		exampleValue := t.Name()

		logger := slog.NewSlogLogger(logging.DebugLevel)
		tracerProvider, err := (&tracingcfg.Config{
			Provider: tracingcfg.ProviderOtel,
			Otel: &oteltracehttp.Config{
				CollectorEndpoint:         "http://localhost:4317",
				SpanCollectionProbability: 1,
			},
		}).ProvideTracerProvider(ctx, logger)
		require.NoError(t, err)
		require.NotNil(t, tracerProvider)

		tracer := tracerProvider.Tracer("test")
		_, span := tracer.Start(ctx, t.Name())

		logger.Debug("things")

		logger, span = ObserveValue(logger, span, "example", exampleValue)
		assert.NotNil(t, logger)
		assert.NotNil(t, span)

		logger.Debug("stuff")
	})
}
