package pubsub

import (
	"context"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

// Config configures a PubSub-backed pubSubConsumer.
type Config struct{}

var _ validation.ValidatableWithContext = (*Config)(nil)

// ValidateWithContext validates a Config struct.
func (cfg *Config) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(ctx, cfg)
}
