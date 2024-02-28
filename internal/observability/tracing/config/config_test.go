package config

import (
	"context"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing/oteltracehttp"

	"github.com/stretchr/testify/assert"
)

func TestConfig_ProvideTracerProvider(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{}

		tracerProvider, err := cfg.ProvideTracerProvider(
			context.Background(),
			logging.NewNoopLogger(),
		)

		assert.NoError(t, err)
		assert.NotNil(t, tracerProvider)
	})
}

func TestConfig_ValidateWithContext(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			Provider: ProviderOtel,
			Otel: &oteltracehttp.Config{
				CollectorEndpoint:         t.Name(),
				ServiceName:               t.Name(),
				SpanCollectionProbability: 1,
			},
		}

		assert.NoError(t, cfg.ValidateWithContext(context.Background()))
	})
}
