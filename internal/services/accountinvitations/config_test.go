package accountinvitations

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfig_Validate(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()

		cfg := &Config{
			Debug:                false,
			DataChangesTopicName: "data_changes",
		}

		assert.NoError(t, cfg.ValidateWithContext(ctx))
	})
}
