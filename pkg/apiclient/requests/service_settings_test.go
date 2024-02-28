package requests

import (
	"net/http"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"

	"github.com/stretchr/testify/assert"
)

func TestBuilder_BuildGetServiceSettingRequest(T *testing.T) {
	T.Parallel()

	const expectedPathFormat = "/api/v1/settings/%s"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		exampleServiceSetting := fakes.BuildFakeServiceSetting()

		spec := newRequestSpec(true, http.MethodGet, "", expectedPathFormat, exampleServiceSetting.ID)

		actual, err := helper.builder.BuildGetServiceSettingRequest(helper.ctx, exampleServiceSetting.ID)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with invalid service setting ID", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		actual, err := helper.builder.BuildGetServiceSettingRequest(helper.ctx, "")
		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()

		exampleServiceSetting := fakes.BuildFakeServiceSetting()

		actual, err := helper.builder.BuildGetServiceSettingRequest(helper.ctx, exampleServiceSetting.ID)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func TestBuilder_BuildGetServiceSettingsRequest(T *testing.T) {
	T.Parallel()

	const expectedPathFormat = "/api/v1/settings"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		filter := (*types.QueryFilter)(nil)
		spec := newRequestSpec(true, http.MethodGet, "limit=50&page=1&sortBy=asc", expectedPathFormat)

		actual, err := helper.builder.BuildGetServiceSettingsRequest(helper.ctx, filter)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()

		filter := (*types.QueryFilter)(nil)

		actual, err := helper.builder.BuildGetServiceSettingsRequest(helper.ctx, filter)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func TestBuilder_BuildSearchServiceSettingsRequest(T *testing.T) {
	T.Parallel()

	const expectedPath = "/api/v1/settings/search"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		limit := types.DefaultQueryFilter().Limit
		exampleQuery := "whatever"
		spec := newRequestSpec(true, http.MethodGet, "limit=50&q=whatever", expectedPath)

		actual, err := helper.builder.BuildSearchServiceSettingsRequest(helper.ctx, exampleQuery, *limit)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()

		limit := types.DefaultQueryFilter().Limit
		exampleQuery := "whatever"

		actual, err := helper.builder.BuildSearchServiceSettingsRequest(helper.ctx, exampleQuery, *limit)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}
