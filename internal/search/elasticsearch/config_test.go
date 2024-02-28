package elasticsearch

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfig_provideElasticsearchClient(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{}

		esClient, err := cfg.provideElasticsearchClient()
		assert.NoError(t, err)
		assert.NotNil(t, esClient)
	})
}
