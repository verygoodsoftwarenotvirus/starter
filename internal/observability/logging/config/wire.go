package config

import (
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"

	"github.com/google/wire"
)

var (
	ProvidersLogConfig = wire.NewSet(
		ProvideLogger,
	)
)

func ProvideLogger(cfg *Config) logging.Logger {
	return cfg.ProvideLogger()
}
