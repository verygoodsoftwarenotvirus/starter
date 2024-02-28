package observability

import (
	"context"
	"testing"

	tracingcfg "github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing/oteltracehttp"

	"github.com/stretchr/testify/assert"
)

func TestConfig_ValidateWithContext(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		cfg := &Config{
			Tracing: tracingcfg.Config{
				Provider: tracingcfg.ProviderOtel,
				Otel: &oteltracehttp.Config{
					CollectorEndpoint:         "0.0.0.0",
					ServiceName:               t.Name(),
					SpanCollectionProbability: 1,
				},
			},
		}

		assert.NoError(t, cfg.ValidateWithContext(ctx))
	})
}
