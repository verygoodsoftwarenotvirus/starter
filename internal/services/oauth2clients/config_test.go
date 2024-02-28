package oauth2clients

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfig_ValidateWithContext(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		cfg := &Config{
			CreationEnabled:      true,
			DataChangesTopicName: "blah",
		}

		assert.NoError(t, cfg.ValidateWithContext(ctx))
	})
}
