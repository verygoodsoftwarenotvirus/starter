package routing

import (
	"context"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

const (
	// ChiProvider is the string we use to refer to chi.
	ChiProvider = "chi"
)

// Config configures our router.
type Config struct {
	_ struct{} `json:"-"`

	Provider               string `json:"provider,omitempty"            toml:"provider,omitempty"`
	EnableCORSForLocalhost bool   `json:"enableCORSForLocalhost"        toml:"enable_cors_for_localhost"`
	SilenceRouteLogging    bool   `json:"silenceRouteLogging,omitempty" toml:"silence_route_logging,omitempty"`
}

var _ validation.ValidatableWithContext = (*Config)(nil)

// ValidateWithContext validates a router config struct.
func (cfg *Config) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(ctx, cfg,
		validation.Field(&cfg.Provider, validation.In(ChiProvider)),
	)
}
