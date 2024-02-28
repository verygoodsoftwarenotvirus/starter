package postgres

import (
	"context"
	"database/sql"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/converters"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createServiceSettingConfigurationForTest(t *testing.T, ctx context.Context, exampleServiceSettingConfiguration *types.ServiceSettingConfiguration, dbc *Querier) *types.ServiceSettingConfiguration {
	t.Helper()

	// create
	if exampleServiceSettingConfiguration == nil {
		user := createUserForTest(t, ctx, nil, dbc)
		accountID, err := dbc.GetDefaultAccountIDForUser(ctx, user.ID)
		require.NoError(t, err)
		serviceSetting := createServiceSettingForTest(t, ctx, nil, dbc)
		exampleServiceSettingConfiguration = fakes.BuildFakeServiceSettingConfiguration()
		exampleServiceSettingConfiguration.ServiceSetting = *serviceSetting
		exampleServiceSettingConfiguration.BelongsToUser = user.ID
		exampleServiceSettingConfiguration.BelongsToAccount = accountID
	}
	dbInput := converters.ConvertServiceSettingConfigurationToServiceSettingConfigurationDatabaseCreationInput(exampleServiceSettingConfiguration)

	created, err := dbc.CreateServiceSettingConfiguration(ctx, dbInput)
	require.NoError(t, err)
	require.NotNil(t, created)
	exampleServiceSettingConfiguration.CreatedAt = created.CreatedAt
	exampleServiceSettingConfiguration.ServiceSetting = created.ServiceSetting
	assert.Equal(t, exampleServiceSettingConfiguration, created)

	serviceSettingConfiguration, err := dbc.GetServiceSettingConfiguration(ctx, created.ID)
	exampleServiceSettingConfiguration.CreatedAt = serviceSettingConfiguration.CreatedAt
	exampleServiceSettingConfiguration.ServiceSetting = serviceSettingConfiguration.ServiceSetting

	assert.NoError(t, err)
	assert.Equal(t, serviceSettingConfiguration, exampleServiceSettingConfiguration)

	return created
}

func TestQuerier_Integration_ServiceSettingConfigurations(t *testing.T) {
	if !runningContainerTests {
		t.SkipNow()
	}

	ctx := context.Background()
	dbc, container := buildDatabaseClientForTest(t, ctx)

	databaseURI, err := container.ConnectionString(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, databaseURI)

	defer func(t *testing.T) {
		t.Helper()
		assert.NoError(t, container.Terminate(ctx))
	}(t)

	user := createUserForTest(t, ctx, nil, dbc)
	accountID, err := dbc.GetDefaultAccountIDForUser(ctx, user.ID)
	require.NoError(t, err)
	serviceSetting := createServiceSettingForTest(t, ctx, nil, dbc)
	exampleServiceSettingConfiguration := fakes.BuildFakeServiceSettingConfiguration()
	exampleServiceSettingConfiguration.ServiceSetting = *serviceSetting
	exampleServiceSettingConfiguration.BelongsToUser = user.ID
	exampleServiceSettingConfiguration.BelongsToAccount = accountID
	createdServiceSettingConfigurations := []*types.ServiceSettingConfiguration{}

	// create
	createdServiceSettingConfigurations = append(createdServiceSettingConfigurations, createServiceSettingConfigurationForTest(t, ctx, exampleServiceSettingConfiguration, dbc))

	// update
	createdServiceSettingConfigurations[0].Value = "new value"
	require.NoError(t, dbc.UpdateServiceSettingConfiguration(ctx, createdServiceSettingConfigurations[0]))

	// delete
	for _, serviceSettingConfiguration := range createdServiceSettingConfigurations {
		assert.NoError(t, dbc.ArchiveServiceSettingConfiguration(ctx, serviceSettingConfiguration.ID))

		var exists bool
		exists, err = dbc.ServiceSettingConfigurationExists(ctx, serviceSettingConfiguration.ID)
		assert.NoError(t, err)
		assert.False(t, exists)

		var y *types.ServiceSettingConfiguration
		y, err = dbc.GetServiceSettingConfiguration(ctx, serviceSettingConfiguration.ID)
		assert.Nil(t, y)
		assert.Error(t, err)
		assert.ErrorIs(t, err, sql.ErrNoRows)
	}
}

func TestQuerier_ServiceSettingConfigurationExists(T *testing.T) {
	T.Parallel()

	T.Run("with invalid service setting ID", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()

		c, _ := buildTestClient(t)

		actual, err := c.ServiceSettingConfigurationExists(ctx, "")
		assert.Error(t, err)
		assert.False(t, actual)
	})
}

func TestQuerier_GetServiceSettingConfiguration(T *testing.T) {
	T.Parallel()

	T.Run("with invalid service setting ID", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		exampleServiceSettingConfiguration := fakes.BuildFakeServiceSettingConfiguration()
		c, _ := buildTestClient(t)

		actual, err := c.GetServiceSettingConfiguration(ctx, exampleServiceSettingConfiguration.ID)
		assert.Error(t, err)
		assert.Nil(t, actual)
	})
}

func TestQuerier_GetServiceSettingConfigurationForUserByName(T *testing.T) {
	T.Parallel()

	T.Run("with invalid service setting ID", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		exampleUserID := fakes.BuildFakeID()
		c, _ := buildTestClient(t)

		actual, err := c.GetServiceSettingConfigurationForUserByName(ctx, exampleUserID, "")
		assert.Error(t, err)
		assert.Nil(t, actual)
	})
}

func TestQuerier_GetServiceSettingConfigurationForAccountByName(T *testing.T) {
	T.Parallel()

	T.Run("with invalid service setting name", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		exampleAccountID := fakes.BuildFakeID()
		c, _ := buildTestClient(t)

		actual, err := c.GetServiceSettingConfigurationForAccountByName(ctx, exampleAccountID, "")
		assert.Error(t, err)
		assert.Nil(t, actual)
	})
}

func TestQuerier_GetServiceSettingConfigurationsForUser(T *testing.T) {
	T.Parallel()

	T.Run("with invalid service setting ID", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		exampleUserID := fakes.BuildFakeID()
		c, _ := buildTestClient(t)

		actual, err := c.GetServiceSettingConfigurationsForUser(ctx, exampleUserID, nil)
		assert.Error(t, err)
		assert.Nil(t, actual)
	})
}

func TestQuerier_CreateServiceSettingConfiguration(T *testing.T) {
	T.Parallel()

	T.Run("with invalid input", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		c, _ := buildTestClient(t)

		actual, err := c.CreateServiceSettingConfiguration(ctx, nil)
		assert.Error(t, err)
		assert.Nil(t, actual)
	})
}

func TestQuerier_UpdateServiceSettingConfiguration(T *testing.T) {
	T.Parallel()

	T.Run("with nil input", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		c, _ := buildTestClient(t)

		assert.Error(t, c.UpdateServiceSettingConfiguration(ctx, nil))
	})
}

func TestQuerier_ArchiveServiceSettingConfiguration(T *testing.T) {
	T.Parallel()

	T.Run("with invalid service setting ID", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		c, _ := buildTestClient(t)

		assert.Error(t, c.ArchiveServiceSettingConfiguration(ctx, ""))
	})
}
