package mocktypes

import (
	"context"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"

	"github.com/stretchr/testify/mock"
)

var _ types.UserNotificationDataManager = (*UserNotificationDataManagerMock)(nil)

// UserNotificationDataManagerMock is a mocked types.UserNotificationDataManager for testing.
type UserNotificationDataManagerMock struct {
	mock.Mock
}

// UserNotificationExists is a mock function.
func (m *UserNotificationDataManagerMock) UserNotificationExists(ctx context.Context, userID, userNotificationID string) (bool, error) {
	args := m.Called(ctx, userID, userNotificationID)
	return args.Bool(0), args.Error(1)
}

// GetUserNotification is a mock function.
func (m *UserNotificationDataManagerMock) GetUserNotification(ctx context.Context, userID, userNotificationID string) (*types.UserNotification, error) {
	args := m.Called(ctx, userID, userNotificationID)
	return args.Get(0).(*types.UserNotification), args.Error(1)
}

// GetUserNotifications is a mock function.
func (m *UserNotificationDataManagerMock) GetUserNotifications(ctx context.Context, userID string, filter *types.QueryFilter) (*types.QueryFilteredResult[types.UserNotification], error) {
	args := m.Called(ctx, userID, filter)
	return args.Get(0).(*types.QueryFilteredResult[types.UserNotification]), args.Error(1)
}

// CreateUserNotification is a mock function.
func (m *UserNotificationDataManagerMock) CreateUserNotification(ctx context.Context, input *types.UserNotificationDatabaseCreationInput) (*types.UserNotification, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*types.UserNotification), args.Error(1)
}

// UpdateUserNotification is a mock function.
func (m *UserNotificationDataManagerMock) UpdateUserNotification(ctx context.Context, updated *types.UserNotification) error {
	return m.Called(ctx, updated).Error(0)
}
