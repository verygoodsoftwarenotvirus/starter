package oauth2clients

import (
	"context"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

// Config manages our body validation.
type Config struct {
	DataChangesTopicName string `json:"dataChangesTopicName,omitempty" toml:"data_changes_topic_name,omitempty"`
	CreationEnabled      bool   `json:"creationEnabled"                toml:"creation_enabled"`
}

func (c *Config) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(ctx, c,
		validation.Field(&c.DataChangesTopicName, validation.Required),
	)
}
