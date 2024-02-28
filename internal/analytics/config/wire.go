package config

import (
	"github.com/verygoodsoftwarenotvirus/starter/internal/analytics"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"

	"github.com/google/wire"
)

var (
	// ProvidersAnalytics are what we provide to dependency injection.
	ProvidersAnalytics = wire.NewSet(
		ProvideEventReporter,
	)
)

// ProvideEventReporter provides a analytics.EventReporter from a config.
func ProvideEventReporter(cfg *Config, logger logging.Logger, tracerProvider tracing.TracerProvider) (analytics.EventReporter, error) {
	return cfg.ProvideCollector(logger, tracerProvider)
}
