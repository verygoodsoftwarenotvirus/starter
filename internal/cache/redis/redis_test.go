package redis

import (
	"context"
	"strings"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	rediscontainers "github.com/testcontainers/testcontainers-go/modules/redis"
)

const (
	exampleKey = "example"
)

func buildContainerBackedRedisConfig(t *testing.T, ctx context.Context) (config *Config, shutdownFunction func(context.Context) error) {
	t.Helper()

	redisContainer, err := rediscontainers.RunContainer(ctx,
		testcontainers.WithImage("docker.io/redis:7-bullseye"),
		rediscontainers.WithLogLevel(rediscontainers.LogLevelNotice),
	)
	if err != nil {
		panic(err)
	}

	redisAddress, err := redisContainer.ConnectionString(ctx)
	require.NoError(t, err)

	cfg := &Config{
		QueueAddresses: []string{
			strings.TrimPrefix(redisAddress, "redis://"),
		},
	}

	return cfg, redisContainer.Terminate
}

func Test_redisCacheImpl_Get(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()

		cfg, containerShutdown := buildContainerBackedRedisConfig(t, ctx)
		defer func() {
			assert.NoError(t, containerShutdown(ctx))
		}()
		c := NewRedisCache[types.SessionContextData](cfg, 0)

		exampleContent := fakes.BuildFakeSessionContextData()
		assert.NoError(t, c.Set(ctx, exampleKey, exampleContent))

		actual, err := c.Get(ctx, exampleKey)
		assert.Equal(t, exampleContent, actual)
		assert.NoError(t, err)
	})
}

func Test_redisCacheImpl_Set(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()

		cfg, containerShutdown := buildContainerBackedRedisConfig(t, ctx)
		defer func() {
			assert.NoError(t, containerShutdown(ctx))
		}()
		c := NewRedisCache[types.SessionContextData](cfg, 0)

		exampleContent := fakes.BuildFakeSessionContextData()
		assert.NoError(t, c.Set(ctx, exampleKey, exampleContent))
	})
}

func Test_redisCacheImpl_Delete(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()

		cfg, containerShutdown := buildContainerBackedRedisConfig(t, ctx)
		defer func() {
			assert.NoError(t, containerShutdown(ctx))
		}()
		c := NewRedisCache[types.SessionContextData](cfg, 0)

		exampleContent := fakes.BuildFakeSessionContextData()
		assert.NoError(t, c.Set(ctx, exampleKey, exampleContent))

		assert.NoError(t, c.Delete(ctx, exampleKey))
	})
}
