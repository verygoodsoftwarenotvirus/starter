package elasticsearch

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	elasticsearchcontainers "github.com/testcontainers/testcontainers-go/modules/elasticsearch"
)

var (
	runningContainerTests = strings.ToLower(os.Getenv("RUN_CONTAINER_TESTS")) == "true"
)

func buildContainerBackedElasticsearchConfig(t *testing.T, ctx context.Context) (config *Config, shutdownFunction func(context.Context) error) {
	t.Helper()

	elasticsearchContainer, err := elasticsearchcontainers.RunContainer(ctx,
		testcontainers.WithImage("elasticsearch:8.10.2"),
		elasticsearchcontainers.WithPassword("arbitraryPassword"),
	)
	require.NoError(t, err)
	require.NotNil(t, elasticsearchContainer)

	cfg := &Config{
		Address:               elasticsearchContainer.Settings.Address,
		IndexOperationTimeout: 0,
		Username:              "elastic",
		Password:              elasticsearchContainer.Settings.Password,
		CACert:                elasticsearchContainer.Settings.CACert,
	}

	return cfg, elasticsearchContainer.Terminate
}

func Test_ProvideIndexManager(T *testing.T) {
	T.Parallel()

	if !runningContainerTests {
		T.SkipNow()
	}

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		cfg, shutdownFunc := buildContainerBackedElasticsearchConfig(t, ctx)
		defer func() {
			require.NoError(t, shutdownFunc(ctx))
		}()

		im, err := ProvideIndexManager[types.UserSearchSubset](ctx, nil, nil, cfg, t.Name())
		assert.NoError(t, err)
		assert.NotNil(t, im)
	})

	T.Run("without available instance", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		cfg := &Config{}

		im, err := ProvideIndexManager[types.UserSearchSubset](ctx, nil, nil, cfg, t.Name())
		assert.Error(t, err)
		assert.Nil(t, im)
	})
}
