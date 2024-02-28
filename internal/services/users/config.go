package users

import (
	"context"

	"github.com/verygoodsoftwarenotvirus/starter/internal/uploads"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// Config configures the users service.
	Config struct {
		DataChangesTopicName string         `json:"dataChangesTopicName,omitempty" toml:"data_changes_topic_name,omitempty"`
		PublicMediaURLPrefix string         `json:"publicMediaURLPrefix"           toml:"public_media_url_prefix"`
		Uploads              uploads.Config `json:"uploads"                        toml:"uploads,omitempty"`
	}
)

var _ validation.ValidatableWithContext = (*Config)(nil)

// ValidateWithContext validates a Config struct.
func (cfg *Config) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(
		ctx,
		cfg,
		validation.Field(&cfg.DataChangesTopicName, validation.Required),
		validation.Field(&cfg.Uploads, validation.Required),
	)
}
