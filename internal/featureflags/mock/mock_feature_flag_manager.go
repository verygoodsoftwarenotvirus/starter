package mock

import (
	"context"

	"github.com/verygoodsoftwarenotvirus/starter/internal/featureflags"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"

	"github.com/stretchr/testify/mock"
)

var _ featureflags.FeatureFlagManager = (*FeatureFlagManager)(nil)

type FeatureFlagManager struct {
	mock.Mock
}

// CanUseFeature satisfies the FeatureFlagManager interface.
func (m *FeatureFlagManager) CanUseFeature(ctx context.Context, username, feature string) (bool, error) {
	returnValues := m.Called(ctx, username, feature)
	return returnValues.Bool(0), returnValues.Error(1)
}

// Identify satisfies the FeatureFlagManager interface.
func (m *FeatureFlagManager) Identify(ctx context.Context, user *types.User) error {
	return m.Called(ctx, user).Error(0)
}

// Close satisfies the FeatureFlagManager interface.
func (m *FeatureFlagManager) Close() error {
	return m.Called().Error(0)
}
