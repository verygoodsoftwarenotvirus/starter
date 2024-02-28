package config

import (
	"net/http"

	"github.com/verygoodsoftwarenotvirus/starter/internal/email"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"

	"github.com/google/wire"
)

var (
	// ProvidersEmail are what we provide to dependency injection.
	ProvidersEmail = wire.NewSet(
		ProvideEmailer,
	)
)

// ProvideEmailer provides an email.Emailer from a config.
func ProvideEmailer(cfg *Config, logger logging.Logger, tracerProvider tracing.TracerProvider, client *http.Client) (email.Emailer, error) {
	return cfg.ProvideEmailer(logger, tracerProvider, client)
}
