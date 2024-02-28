package config

import (
	"net/http"

	"github.com/verygoodsoftwarenotvirus/starter/internal/featureflags"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"

	"github.com/google/wire"
)

var (
	ProvidersFeatureFlags = wire.NewSet(
		ProvideFeatureFlagManager,
	)
)

func ProvideFeatureFlagManager(c *Config, logger logging.Logger, tracerProvider tracing.TracerProvider, httpClient *http.Client) (featureflags.FeatureFlagManager, error) {
	return c.ProvideFeatureFlagManager(logger, tracerProvider, httpClient)
}
