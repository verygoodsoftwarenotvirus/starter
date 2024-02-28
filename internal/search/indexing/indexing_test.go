package indexing

import (
	"context"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/internal/database"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/internal/search"
	"github.com/verygoodsoftwarenotvirus/starter/internal/search/config"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"
	testutils "github.com/verygoodsoftwarenotvirus/starter/tests/utils"

	"github.com/stretchr/testify/assert"
)

func TestHandleIndexRequest(T *testing.T) {
	T.Parallel()

	T.Run("user index type", func(t *testing.T) {
		t.Parallel()

		exampleUser := fakes.BuildFakeUser()

		ctx := context.Background()
		logger := logging.NewNoopLogger()
		tracerProvider := tracing.NewNoopTracerProvider
		searchConfig := &config.Config{}

		dataManager := database.NewMockDatabase()
		dataManager.UserDataManagerMock.On("GetUser", testutils.ContextMatcher, exampleUser.ID).Return(exampleUser, nil)
		dataManager.UserDataManagerMock.On("MarkUserAsIndexed", testutils.ContextMatcher, exampleUser.ID).Return(nil)

		indexReq := &IndexRequest{
			RowID:     exampleUser.ID,
			IndexType: search.IndexTypeUsers,
			Delete:    false,
		}

		assert.NoError(t, HandleIndexRequest(ctx, logger, tracerProvider(), searchConfig, dataManager, indexReq))
	})

	T.Run("deleting user index type", func(t *testing.T) {
		t.Parallel()

		exampleUser := fakes.BuildFakeUser()

		ctx := context.Background()
		logger := logging.NewNoopLogger()
		tracerProvider := tracing.NewNoopTracerProvider
		searchConfig := &config.Config{}

		dataManager := database.NewMockDatabase()
		dataManager.UserDataManagerMock.On("GetUser", testutils.ContextMatcher, exampleUser.ID).Return(exampleUser, nil)
		dataManager.UserDataManagerMock.On("MarkUserAsIndexed", testutils.ContextMatcher, exampleUser.ID).Return(nil)

		indexReq := &IndexRequest{
			RowID:     exampleUser.ID,
			IndexType: search.IndexTypeUsers,
			Delete:    true,
		}

		assert.NoError(t, HandleIndexRequest(ctx, logger, tracerProvider(), searchConfig, dataManager, indexReq))
	})
}
