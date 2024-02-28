package requests

import (
	"net/http"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"

	"github.com/stretchr/testify/assert"
)

func TestBuilder_BuildGetServiceSettingConfigurationForUserByNameRequest(T *testing.T) {
	T.Parallel()

	const expectedPathFormat = "/api/v1/settings/configurations/user/%s"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		exampleSettingName := fakes.BuildFakeServiceSetting().Name
		filter := (*types.QueryFilter)(nil)
		spec := newRequestSpec(true, http.MethodGet, "limit=50&page=1&sortBy=asc", expectedPathFormat, exampleSettingName)

		actual, err := helper.builder.BuildGetServiceSettingConfigurationForUserByNameRequest(helper.ctx, exampleSettingName, filter)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()

		exampleSettingName := fakes.BuildFakeServiceSetting().Name
		filter := (*types.QueryFilter)(nil)

		actual, err := helper.builder.BuildGetServiceSettingConfigurationForUserByNameRequest(helper.ctx, exampleSettingName, filter)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func TestBuilder_BuildGetServiceSettingConfigurationsForUserRequest(T *testing.T) {
	T.Parallel()

	const expectedPathFormat = "/api/v1/settings/configurations/user"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		filter := (*types.QueryFilter)(nil)
		spec := newRequestSpec(true, http.MethodGet, "limit=50&page=1&sortBy=asc", expectedPathFormat)

		actual, err := helper.builder.BuildGetServiceSettingConfigurationsForUserRequest(helper.ctx, filter)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()

		filter := (*types.QueryFilter)(nil)

		actual, err := helper.builder.BuildGetServiceSettingConfigurationsForUserRequest(helper.ctx, filter)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func TestBuilder_BuildGetServiceSettingConfigurationsForAccountRequest(T *testing.T) {
	T.Parallel()

	const expectedPathFormat = "/api/v1/settings/configurations/account"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		filter := (*types.QueryFilter)(nil)
		spec := newRequestSpec(true, http.MethodGet, "limit=50&page=1&sortBy=asc", expectedPathFormat)

		actual, err := helper.builder.BuildGetServiceSettingConfigurationsForAccountRequest(helper.ctx, filter)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()

		filter := (*types.QueryFilter)(nil)

		actual, err := helper.builder.BuildGetServiceSettingConfigurationsForAccountRequest(helper.ctx, filter)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func TestBuilder_BuildCreateServiceSettingConfigurationRequest(T *testing.T) {
	T.Parallel()

	const expectedPath = "/api/v1/settings/configurations"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		exampleInput := fakes.BuildFakeServiceSettingConfigurationCreationRequestInput()

		spec := newRequestSpec(false, http.MethodPost, "", expectedPath)

		actual, err := helper.builder.BuildCreateServiceSettingConfigurationRequest(helper.ctx, exampleInput)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with nil input", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		actual, err := helper.builder.BuildCreateServiceSettingConfigurationRequest(helper.ctx, nil)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	T.Run("with invalid input", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		actual, err := helper.builder.BuildCreateServiceSettingConfigurationRequest(helper.ctx, &types.ServiceSettingConfigurationCreationRequestInput{})
		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()

		exampleInput := fakes.BuildFakeServiceSettingConfigurationCreationRequestInput()

		actual, err := helper.builder.BuildCreateServiceSettingConfigurationRequest(helper.ctx, exampleInput)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func TestBuilder_BuildUpdateServiceSettingConfigurationRequest(T *testing.T) {
	T.Parallel()

	const expectedPathFormat = "/api/v1/settings/configurations/%s"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		exampleServiceSettingConfiguration := fakes.BuildFakeServiceSettingConfiguration()

		spec := newRequestSpec(false, http.MethodPut, "", expectedPathFormat, exampleServiceSettingConfiguration.ID)

		actual, err := helper.builder.BuildUpdateServiceSettingConfigurationRequest(helper.ctx, exampleServiceSettingConfiguration)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with nil input", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		actual, err := helper.builder.BuildUpdateServiceSettingConfigurationRequest(helper.ctx, nil)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()

		exampleServiceSettingConfiguration := fakes.BuildFakeServiceSettingConfiguration()

		actual, err := helper.builder.BuildUpdateServiceSettingConfigurationRequest(helper.ctx, exampleServiceSettingConfiguration)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func TestBuilder_BuildArchiveServiceSettingConfigurationRequest(T *testing.T) {
	T.Parallel()

	const expectedPathFormat = "/api/v1/settings/configurations/%s"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		exampleServiceSettingConfiguration := fakes.BuildFakeServiceSettingConfiguration()

		spec := newRequestSpec(true, http.MethodDelete, "", expectedPathFormat, exampleServiceSettingConfiguration.ID)

		actual, err := helper.builder.BuildArchiveServiceSettingConfigurationRequest(helper.ctx, exampleServiceSettingConfiguration.ID)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with invalid service setting ID", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		actual, err := helper.builder.BuildArchiveServiceSettingConfigurationRequest(helper.ctx, "")
		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()

		exampleServiceSettingConfiguration := fakes.BuildFakeServiceSettingConfiguration()

		actual, err := helper.builder.BuildArchiveServiceSettingConfigurationRequest(helper.ctx, exampleServiceSettingConfiguration.ID)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}
