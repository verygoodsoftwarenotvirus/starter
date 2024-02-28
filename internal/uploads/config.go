package uploads

import (
	"context"

	"github.com/verygoodsoftwarenotvirus/starter/internal/objectstorage"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

// Config contains settings regarding search indices.
type Config struct {
	_ struct{} `json:"-"`

	Storage objectstorage.Config `json:"storageConfig" toml:"storage_config,omitempty"`
	Debug   bool                 `json:"debug"         toml:"debug,omitempty"`
}

var _ validation.ValidatableWithContext = (*Config)(nil)

// ValidateWithContext validates a Config struct.
func (cfg *Config) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(ctx, cfg,
		validation.Field(&cfg.Storage),
	)
}
