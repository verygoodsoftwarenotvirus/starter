package config

import (
	"context"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/internal/search/elasticsearch"

	"github.com/stretchr/testify/assert"
)

func TestConfig_ValidateWithContext(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		cfg := &Config{
			Provider: ElasticsearchProvider,
			Elasticsearch: &elasticsearch.Config{
				Address: t.Name(),
			},
		}

		assert.NoError(t, cfg.ValidateWithContext(ctx))
	})
}
