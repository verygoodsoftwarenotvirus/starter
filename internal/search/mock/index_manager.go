package mocksearch

import (
	"context"

	"github.com/verygoodsoftwarenotvirus/starter/internal/search"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"

	"github.com/stretchr/testify/mock"
)

var (
	_ search.Index[types.UserSearchSubset] = (*IndexManager[types.UserSearchSubset])(nil)
)

// IndexManager is a mock IndexManager.
type IndexManager[T any] struct {
	mock.Mock
}

func (m *IndexManager[T]) Wipe(ctx context.Context) error {
	return m.Called(ctx).Error(0)
}

// Index implements our interface.
func (m *IndexManager[T]) Index(ctx context.Context, id string, value any) error {
	return m.Called(ctx, id, value).Error(0)
}

// Search implements our interface.
func (m *IndexManager[T]) Search(ctx context.Context, query string) (results []*T, err error) {
	args := m.Called(ctx, query)
	return args.Get(0).([]*T), args.Error(1)
}

// Delete implements our interface.
func (m *IndexManager[T]) Delete(ctx context.Context, id string) error {
	return m.Called(ctx, id).Error(0)
}
