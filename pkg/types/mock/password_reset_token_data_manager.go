package mocktypes

import (
	"context"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"

	"github.com/stretchr/testify/mock"
)

var _ types.PasswordResetTokenDataManager = (*PasswordResetTokenDataManagerMock)(nil)

// PasswordResetTokenDataManagerMock is a mocked types.PasswordResetTokenDataManager for testing.
type PasswordResetTokenDataManagerMock struct {
	mock.Mock
}

// GetPasswordResetTokenByToken implements our interface requirements.
func (m *PasswordResetTokenDataManagerMock) GetPasswordResetTokenByToken(ctx context.Context, passwordResetTokenID string) (*types.PasswordResetToken, error) {
	args := m.Called(ctx, passwordResetTokenID)

	return args.Get(0).(*types.PasswordResetToken), args.Error(1)
}

// CreatePasswordResetToken implements our interface requirements.
func (m *PasswordResetTokenDataManagerMock) CreatePasswordResetToken(ctx context.Context, input *types.PasswordResetTokenDatabaseCreationInput) (*types.PasswordResetToken, error) {
	args := m.Called(ctx, input)

	return args.Get(0).(*types.PasswordResetToken), args.Error(1)
}

// RedeemPasswordResetToken implements our interface requirements.
func (m *PasswordResetTokenDataManagerMock) RedeemPasswordResetToken(ctx context.Context, passwordResetTokenID string) error {
	return m.Called(ctx, passwordResetTokenID).Error(0)
}
