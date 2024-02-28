package accounts

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfig_ValidateWithContext(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		cfg := &Config{
			DataChangesTopicName: t.Name(),
		}

		require.NoError(t, cfg.ValidateWithContext(ctx))
	})

	T.Run("with invalid configuration", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		cfg := &Config{}

		require.Error(t, cfg.ValidateWithContext(ctx))
	})
}
