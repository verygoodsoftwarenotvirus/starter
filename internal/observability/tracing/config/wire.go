package config

import (
	"context"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"

	"github.com/google/wire"
)

var (
	// ProvidersTracing is a Wire provider set that provides a tracing.TracerProvider.
	ProvidersTracing = wire.NewSet(
		ProvideTracerProvider,
	)
)

func ProvideTracerProvider(ctx context.Context, c *Config, l logging.Logger) (traceProvider tracing.TracerProvider, err error) {
	return c.ProvideTracerProvider(ctx, l)
}
