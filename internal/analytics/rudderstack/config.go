package rudderstack

import (
	"context"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type Config struct {
	APIKey       string `json:"apiKey"       toml:"api_key"`
	DataPlaneURL string `json:"dataPlaneURL" toml:"data_plane_url,omitempty"`
}

var _ validation.ValidatableWithContext = (*Config)(nil)

// ValidateWithContext validates a Config struct.
func (cfg *Config) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(ctx, cfg,
		validation.Field(&cfg.APIKey, validation.Required),
		validation.Field(&cfg.DataPlaneURL, validation.Required),
	)
}
