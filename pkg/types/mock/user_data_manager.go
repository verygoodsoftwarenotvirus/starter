package mocktypes

import (
	"context"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"

	"github.com/stretchr/testify/mock"
)

var _ types.UserDataManager = (*UserDataManagerMock)(nil)

// UserDataManagerMock is a mocked types.UserDataManager for testing.
type UserDataManagerMock struct {
	mock.Mock
}

// UpdateUserAvatar is a mock function.
func (m *UserDataManagerMock) UpdateUserAvatar(ctx context.Context, userID, newAvatarContent string) error {
	return m.Called(ctx, userID, newAvatarContent).Error(0)
}

// UpdateUserUsername is a mock function.
func (m *UserDataManagerMock) UpdateUserUsername(ctx context.Context, userID, newUsername string) error {
	return m.Called(ctx, userID, newUsername).Error(0)
}

// UpdateUserEmailAddress is a mock function.
func (m *UserDataManagerMock) UpdateUserEmailAddress(ctx context.Context, userID, newEmailAddress string) error {
	return m.Called(ctx, userID, newEmailAddress).Error(0)
}

// UpdateUserDetails is a mock function.
func (m *UserDataManagerMock) UpdateUserDetails(ctx context.Context, userID string, input *types.UserDetailsDatabaseUpdateInput) error {
	return m.Called(ctx, userID, input).Error(0)
}

// GetUserByEmailAddressVerificationToken is a mock function.
func (m *UserDataManagerMock) GetUserByEmailAddressVerificationToken(ctx context.Context, token string) (*types.User, error) {
	args := m.Called(ctx, token)
	return args.Get(0).(*types.User), args.Error(1)
}

// MarkUserEmailAddressAsVerified is a mock function.
func (m *UserDataManagerMock) MarkUserEmailAddressAsVerified(ctx context.Context, userID, token string) error {
	return m.Called(ctx, userID, token).Error(0)
}

// GetUser is a mock function.
func (m *UserDataManagerMock) GetUser(ctx context.Context, userID string) (*types.User, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).(*types.User), args.Error(1)
}

// GetUserWithUnverifiedTwoFactorSecret is a mock function.
func (m *UserDataManagerMock) GetUserWithUnverifiedTwoFactorSecret(ctx context.Context, userID string) (*types.User, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).(*types.User), args.Error(1)
}

// GetUserByEmail is a mock function.
func (m *UserDataManagerMock) GetUserByEmail(ctx context.Context, email string) (*types.User, error) {
	args := m.Called(ctx, email)
	return args.Get(0).(*types.User), args.Error(1)
}

// MarkUserTwoFactorSecretAsVerified is a mock function.
func (m *UserDataManagerMock) MarkUserTwoFactorSecretAsVerified(ctx context.Context, userID string) error {
	return m.Called(ctx, userID).Error(0)
}

// MarkUserEmailAddressAsUnverified is a mock function.
func (m *UserDataManagerMock) MarkUserEmailAddressAsUnverified(ctx context.Context, userID string) error {
	return m.Called(ctx, userID).Error(0)
}

// MarkUserTwoFactorSecretAsUnverified is a mock function.
func (m *UserDataManagerMock) MarkUserTwoFactorSecretAsUnverified(ctx context.Context, userID, newSecret string) error {
	return m.Called(ctx, userID, newSecret).Error(0)
}

// GetUserByUsername is a mock function.
func (m *UserDataManagerMock) GetUserByUsername(ctx context.Context, username string) (*types.User, error) {
	args := m.Called(ctx, username)
	return args.Get(0).(*types.User), args.Error(1)
}

// GetAdminUserByUsername is a mock function.
func (m *UserDataManagerMock) GetAdminUserByUsername(ctx context.Context, username string) (*types.User, error) {
	args := m.Called(ctx, username)
	return args.Get(0).(*types.User), args.Error(1)
}

// SearchForUsersByUsername is a mock function.
func (m *UserDataManagerMock) SearchForUsersByUsername(ctx context.Context, usernameQuery string) ([]*types.User, error) {
	args := m.Called(ctx, usernameQuery)
	return args.Get(0).([]*types.User), args.Error(1)
}

// GetUsers is a mock function.
func (m *UserDataManagerMock) GetUsers(ctx context.Context, filter *types.QueryFilter) (*types.QueryFilteredResult[types.User], error) {
	args := m.Called(ctx, filter)
	return args.Get(0).(*types.QueryFilteredResult[types.User]), args.Error(1)
}

// CreateUser is a mock function.
func (m *UserDataManagerMock) CreateUser(ctx context.Context, input *types.UserDatabaseCreationInput) (*types.User, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*types.User), args.Error(1)
}

// UpdateUserPassword is a mock function.
func (m *UserDataManagerMock) UpdateUserPassword(ctx context.Context, userID, newHash string) error {
	return m.Called(ctx, userID, newHash).Error(0)
}

// ArchiveUser is a mock function.
func (m *UserDataManagerMock) ArchiveUser(ctx context.Context, userID string) error {
	return m.Called(ctx, userID).Error(0)
}

// GetEmailAddressVerificationTokenForUser is a mock function.
func (m *UserDataManagerMock) GetEmailAddressVerificationTokenForUser(ctx context.Context, userID string) (string, error) {
	args := m.Called(ctx, userID)
	return args.String(0), args.Error(1)
}

// GetUserIDsThatNeedSearchIndexing is a mock function.
func (m *UserDataManagerMock) GetUserIDsThatNeedSearchIndexing(ctx context.Context) ([]string, error) {
	args := m.Called(ctx)
	return args.Get(0).([]string), args.Error(1)
}

func (m *UserDataManagerMock) MarkUserAsIndexed(ctx context.Context, userID string) error {
	return m.Called(ctx, userID).Error(0)
}
