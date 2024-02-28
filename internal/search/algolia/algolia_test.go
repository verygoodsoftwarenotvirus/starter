package algolia

import (
	"context"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"

	"github.com/stretchr/testify/assert"
)

func TestProvideIndexManager(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		logger := logging.NewNoopLogger()
		tracerProvider := tracing.NewNoopTracerProvider()

		im, err := ProvideIndexManager[types.UserSearchSubset](ctx, logger, tracerProvider, &Config{}, "test")
		assert.NoError(t, err)
		assert.NotNil(t, im)
	})
}
