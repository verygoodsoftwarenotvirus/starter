package cloudtrace

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCloudTraceConfig_ValidateWithContext(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		cfg := &Config{
			ProjectID:   t.Name(),
			ServiceName: t.Name(),
		}

		assert.NoError(t, cfg.ValidateWithContext(ctx))
	})
}
