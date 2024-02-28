package mocktypes

import (
	"context"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"

	"github.com/stretchr/testify/mock"
)

var _ types.AdminUserDataManager = (*AdminUserDataManagerMock)(nil)

// AdminUserDataManagerMock is a mocked types.AdminUserDataManager for testing.
type AdminUserDataManagerMock struct {
	mock.Mock
}

// UpdateUserAccountStatus is a mock function.
func (m *AdminUserDataManagerMock) UpdateUserAccountStatus(ctx context.Context, userID string, input *types.UserAccountStatusUpdateInput) error {
	return m.Called(ctx, userID, input).Error(0)
}
