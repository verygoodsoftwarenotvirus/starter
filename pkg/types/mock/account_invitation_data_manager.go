package mocktypes

import (
	"context"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"

	"github.com/stretchr/testify/mock"
)

var _ types.AccountInvitationDataManager = (*AccountInvitationDataManagerMock)(nil)

// AccountInvitationDataManagerMock is a mocked types.AccountInvitationDataManager for testing.
type AccountInvitationDataManagerMock struct {
	mock.Mock
}

// AccountInvitationExists is a mock function.
func (m *AccountInvitationDataManagerMock) AccountInvitationExists(ctx context.Context, accountInvitationID string) (bool, error) {
	args := m.Called(ctx, accountInvitationID)
	return args.Bool(0), args.Error(1)
}

// GetAccountInvitationByAccountAndID is a mock function.
func (m *AccountInvitationDataManagerMock) GetAccountInvitationByAccountAndID(ctx context.Context, accountID, accountInvitationID string) (*types.AccountInvitation, error) {
	args := m.Called(ctx, accountID, accountInvitationID)
	return args.Get(0).(*types.AccountInvitation), args.Error(1)
}

// GetAccountInvitationByTokenAndID is a mock function.
func (m *AccountInvitationDataManagerMock) GetAccountInvitationByTokenAndID(ctx context.Context, accountInvitationID, token string) (*types.AccountInvitation, error) {
	args := m.Called(ctx, accountInvitationID, token)
	return args.Get(0).(*types.AccountInvitation), args.Error(1)
}

// GetAccountInvitationByEmailAndToken is a mock function.
func (m *AccountInvitationDataManagerMock) GetAccountInvitationByEmailAndToken(ctx context.Context, emailAddress, token string) (*types.AccountInvitation, error) {
	args := m.Called(ctx, emailAddress, token)
	return args.Get(0).(*types.AccountInvitation), args.Error(1)
}

// GetPendingAccountInvitationsFromUser is a mock function.
func (m *AccountInvitationDataManagerMock) GetPendingAccountInvitationsFromUser(ctx context.Context, userID string, filter *types.QueryFilter) (*types.QueryFilteredResult[types.AccountInvitation], error) {
	args := m.Called(ctx, userID, filter)
	return args.Get(0).(*types.QueryFilteredResult[types.AccountInvitation]), args.Error(1)
}

// GetPendingAccountInvitationsForUser is a mock function.
func (m *AccountInvitationDataManagerMock) GetPendingAccountInvitationsForUser(ctx context.Context, userID string, filter *types.QueryFilter) (*types.QueryFilteredResult[types.AccountInvitation], error) {
	args := m.Called(ctx, userID, filter)
	return args.Get(0).(*types.QueryFilteredResult[types.AccountInvitation]), args.Error(1)
}

// CreateAccountInvitation is a mock function.
func (m *AccountInvitationDataManagerMock) CreateAccountInvitation(ctx context.Context, input *types.AccountInvitationDatabaseCreationInput) (*types.AccountInvitation, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*types.AccountInvitation), args.Error(1)
}

// CancelAccountInvitation is a mock function.
func (m *AccountInvitationDataManagerMock) CancelAccountInvitation(ctx context.Context, accountInvitationID, note string) error {
	return m.Called(ctx, accountInvitationID, note).Error(0)
}

// AcceptAccountInvitation is a mock function.
func (m *AccountInvitationDataManagerMock) AcceptAccountInvitation(ctx context.Context, accountInvitationID, token, note string) error {
	return m.Called(ctx, accountInvitationID, token, note).Error(0)
}

// RejectAccountInvitation is a mock function.
func (m *AccountInvitationDataManagerMock) RejectAccountInvitation(ctx context.Context, accountInvitationID, note string) error {
	return m.Called(ctx, accountInvitationID, note).Error(0)
}

// ArchiveAccountInvitation is a mock function.
func (m *AccountInvitationDataManagerMock) ArchiveAccountInvitation(ctx context.Context, accountID, userID string) error {
	return m.Called(ctx, accountID, userID).Error(0)
}
