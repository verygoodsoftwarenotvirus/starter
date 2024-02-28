package config

import (
	"strings"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging/slog"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging/zap"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging/zerolog"
)

const (
	// ProviderZerolog indicates you'd like to use the zerolog logger.
	ProviderZerolog = "zerolog"
	// ProviderZap indicates you'd like to use the zap logger.
	ProviderZap = "zap"
	// ProviderSlog indicates you'd like to use the slog logger.
	ProviderSlog = "slog"
)

type (
	// Config configures a Logger.
	Config struct {
		_ struct{} `json:"-"`

		Level    logging.Level `json:"level,omitempty"    toml:"level"`
		Provider string        `json:"provider,omitempty" toml:"provider"`
	}
)

// ProvideLogger builds a logger according to the provided config.
func (cfg *Config) ProvideLogger() logging.Logger {
	switch strings.TrimSpace(strings.ToLower(cfg.Provider)) {
	case ProviderZerolog:
		return zerolog.NewZerologLogger(cfg.Level)
	case ProviderZap:
		return zap.NewZapLogger(cfg.Level)
	case ProviderSlog:
		return slog.NewSlogLogger(cfg.Level)
	default:
		return logging.NewNoopLogger()
	}
}
