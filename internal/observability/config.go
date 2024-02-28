package observability

import (
	"context"

	loggingcfg "github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging/config"
	tracingcfg "github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing/config"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// Config contains settings about how we report our metrics.
	Config struct {
		_ struct{} `json:"-"`

		Logging loggingcfg.Config `json:"logging" toml:"logging,omitempty"`
		Tracing tracingcfg.Config `json:"tracing" toml:"tracing,omitempty"`
	}
)

var _ validation.ValidatableWithContext = (*Config)(nil)

// ValidateWithContext validates a Config struct.
func (cfg *Config) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(ctx, cfg,
		validation.Field(&cfg.Tracing),
	)
}
