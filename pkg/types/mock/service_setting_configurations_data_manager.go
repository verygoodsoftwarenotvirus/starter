package mocktypes

import (
	"context"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"

	"github.com/stretchr/testify/mock"
)

var _ types.ServiceSettingConfigurationDataManager = (*ServiceSettingConfigurationDataManagerMock)(nil)

// ServiceSettingConfigurationDataManagerMock is a mocked types.ServiceSettingConfigurationDataManager for testing.
type ServiceSettingConfigurationDataManagerMock struct {
	mock.Mock
}

// GetServiceSettingConfigurationForUserByName is a mock function.
func (m *ServiceSettingConfigurationDataManagerMock) GetServiceSettingConfigurationForUserByName(ctx context.Context, userID, serviceSettingConfigurationID string) (*types.ServiceSettingConfiguration, error) {
	returnValues := m.Called(ctx, userID, serviceSettingConfigurationID)
	return returnValues.Get(0).(*types.ServiceSettingConfiguration), returnValues.Error(1)
}

// GetServiceSettingConfigurationForAccountByName is a mock function.
func (m *ServiceSettingConfigurationDataManagerMock) GetServiceSettingConfigurationForAccountByName(ctx context.Context, accountID, serviceSettingConfigurationID string) (*types.ServiceSettingConfiguration, error) {
	returnValues := m.Called(ctx, accountID, serviceSettingConfigurationID)
	return returnValues.Get(0).(*types.ServiceSettingConfiguration), returnValues.Error(1)
}

// GetServiceSettingConfigurationsForUser is a mock function.
func (m *ServiceSettingConfigurationDataManagerMock) GetServiceSettingConfigurationsForUser(ctx context.Context, userID string, filter *types.QueryFilter) (*types.QueryFilteredResult[types.ServiceSettingConfiguration], error) {
	returnValues := m.Called(ctx, userID, filter)
	return returnValues.Get(0).(*types.QueryFilteredResult[types.ServiceSettingConfiguration]), returnValues.Error(1)
}

// GetServiceSettingConfigurationsForAccount is a mock function.
func (m *ServiceSettingConfigurationDataManagerMock) GetServiceSettingConfigurationsForAccount(ctx context.Context, accountID string, filter *types.QueryFilter) (*types.QueryFilteredResult[types.ServiceSettingConfiguration], error) {
	returnValues := m.Called(ctx, accountID, filter)
	return returnValues.Get(0).(*types.QueryFilteredResult[types.ServiceSettingConfiguration]), returnValues.Error(1)
}

// ServiceSettingConfigurationExists is a mock function.
func (m *ServiceSettingConfigurationDataManagerMock) ServiceSettingConfigurationExists(ctx context.Context, serviceSettingConfigurationID string) (bool, error) {
	args := m.Called(ctx, serviceSettingConfigurationID)
	return args.Bool(0), args.Error(1)
}

// GetServiceSettingConfiguration is a mock function.
func (m *ServiceSettingConfigurationDataManagerMock) GetServiceSettingConfiguration(ctx context.Context, serviceSettingConfigurationID string) (*types.ServiceSettingConfiguration, error) {
	args := m.Called(ctx, serviceSettingConfigurationID)
	return args.Get(0).(*types.ServiceSettingConfiguration), args.Error(1)
}

// GetRandomServiceSettingConfiguration is a mock function.
func (m *ServiceSettingConfigurationDataManagerMock) GetRandomServiceSettingConfiguration(ctx context.Context) (*types.ServiceSettingConfiguration, error) {
	args := m.Called(ctx)
	return args.Get(0).(*types.ServiceSettingConfiguration), args.Error(1)
}

// CreateServiceSettingConfiguration is a mock function.
func (m *ServiceSettingConfigurationDataManagerMock) CreateServiceSettingConfiguration(ctx context.Context, input *types.ServiceSettingConfigurationDatabaseCreationInput) (*types.ServiceSettingConfiguration, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*types.ServiceSettingConfiguration), args.Error(1)
}

// UpdateServiceSettingConfiguration is a mock function.
func (m *ServiceSettingConfigurationDataManagerMock) UpdateServiceSettingConfiguration(ctx context.Context, updated *types.ServiceSettingConfiguration) error {
	return m.Called(ctx, updated).Error(0)
}

// ArchiveServiceSettingConfiguration is a mock function.
func (m *ServiceSettingConfigurationDataManagerMock) ArchiveServiceSettingConfiguration(ctx context.Context, serviceSettingConfigurationID string) error {
	return m.Called(ctx, serviceSettingConfigurationID).Error(0)
}
