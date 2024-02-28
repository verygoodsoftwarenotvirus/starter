package memory

import (
	"context"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"

	"github.com/stretchr/testify/assert"
)

const (
	exampleKey = "example"
)

func Test_newInMemoryCache(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		actual := NewInMemoryCache[types.SessionContextData]()
		assert.NotNil(t, actual)
	})
}

func Test_inMemoryCacheImpl_Get(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		c := NewInMemoryCache[types.SessionContextData]()

		expected := fakes.BuildFakeSessionContextData()
		assert.NoError(t, c.Set(ctx, exampleKey, expected))

		actual, err := c.Get(ctx, exampleKey)
		assert.Equal(t, expected, actual)
		assert.NoError(t, err)
	})
}

func Test_inMemoryCacheImpl_Set(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		c := NewInMemoryCache[types.SessionContextData]()

		assert.Len(t, c.(*inMemoryCacheImpl[types.SessionContextData]).cache, 0)
		assert.NoError(t, c.Set(ctx, exampleKey, fakes.BuildFakeSessionContextData()))
		assert.Len(t, c.(*inMemoryCacheImpl[types.SessionContextData]).cache, 1)
	})
}

func Test_inMemoryCacheImpl_Delete(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		c := NewInMemoryCache[types.SessionContextData]()

		assert.Len(t, c.(*inMemoryCacheImpl[types.SessionContextData]).cache, 0)
		assert.NoError(t, c.Set(ctx, exampleKey, fakes.BuildFakeSessionContextData()))
		assert.Len(t, c.(*inMemoryCacheImpl[types.SessionContextData]).cache, 1)
		assert.NoError(t, c.Delete(ctx, exampleKey))
		assert.Len(t, c.(*inMemoryCacheImpl[types.SessionContextData]).cache, 0)
	})
}
