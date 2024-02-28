package elasticsearch

import (
	"context"
	"testing"
	"time"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_indexManager_CompleteLifecycle(T *testing.T) {
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

		im, err := ProvideIndexManager[types.UserSearchSubset](ctx, nil, nil, cfg, "index_test")
		assert.NoError(t, err)
		assert.NotNil(t, im)

		user := fakes.BuildFakeUser()
		searchable := &types.UserSearchSubset{
			ID:           user.ID,
			Username:     user.Username,
			FirstName:    user.FirstName,
			LastName:     user.LastName,
			EmailAddress: user.EmailAddress,
		}

		assert.NoError(t, im.Index(ctx, searchable.ID, searchable))

		time.Sleep(5 * time.Second)

		results, err := im.Search(ctx, searchable.FirstName[0:2])
		assert.NoError(t, err)
		assert.Len(t, results, 1)
		assert.Equal(t, searchable, results[0])

		assert.NoError(t, im.Delete(ctx, searchable.ID))
	})
}
