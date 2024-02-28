package config

import (
	"context"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"

	"github.com/stretchr/testify/assert"
)

func TestConfig_ValidateWithContext(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		cfg := &Config{
			Provider: ProviderMemory,
		}

		assert.NoError(t, cfg.ValidateWithContext(ctx))
	})
}

func TestProvideCache(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		_, err := ProvideCache[types.SessionContextData](&Config{
			Provider: ProviderMemory,
		})

		assert.NoError(t, err)
	})

	T.Run("invalid provider", func(t *testing.T) {
		t.Parallel()

		_, err := ProvideCache[types.SessionContextData](&Config{})

		assert.Error(t, err)
	})
}
