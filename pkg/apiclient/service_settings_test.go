package apiclient

import (
	"context"
	"net/http"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func TestServiceSettings(t *testing.T) {
	t.Parallel()

	suite.Run(t, new(serviceSettingsTestSuite))
}

type serviceSettingsBaseSuite struct {
	suite.Suite
	ctx                               context.Context
	exampleServiceSetting             *types.ServiceSetting
	exampleServiceSettingResponse     *types.APIResponse[*types.ServiceSetting]
	exampleServiceSettingListResponse *types.APIResponse[[]*types.ServiceSetting]
	exampleServiceSettingList         []*types.ServiceSetting
}

var _ suite.SetupTestSuite = (*serviceSettingsBaseSuite)(nil)

func (s *serviceSettingsBaseSuite) SetupTest() {
	s.ctx = context.Background()
	s.exampleServiceSetting = fakes.BuildFakeServiceSetting()
	s.exampleServiceSettingResponse = &types.APIResponse[*types.ServiceSetting]{
		Data: s.exampleServiceSetting,
	}

	exampleList := fakes.BuildFakeServiceSettingList()
	s.exampleServiceSettingList = exampleList.Data
	s.exampleServiceSettingListResponse = &types.APIResponse[[]*types.ServiceSetting]{
		Data:       s.exampleServiceSettingList,
		Pagination: &exampleList.Pagination,
	}
}

type serviceSettingsTestSuite struct {
	suite.Suite
	serviceSettingsBaseSuite
}

func (s *serviceSettingsTestSuite) TestClient_GetServiceSetting() {
	const expectedPathFormat = "/api/v1/settings/%s"

	s.Run("standard", func() {
		t := s.T()

		spec := newRequestSpec(true, http.MethodGet, "", expectedPathFormat, s.exampleServiceSetting.ID)
		c, _ := buildTestClientWithJSONResponse(t, spec, s.exampleServiceSettingResponse)
		actual, err := c.GetServiceSetting(s.ctx, s.exampleServiceSetting.ID)

		require.NotNil(t, actual)
		assert.NoError(t, err)
		assert.Equal(t, s.exampleServiceSetting, actual)
	})

	s.Run("with invalid service setting ID", func() {
		t := s.T()

		c, _ := buildSimpleTestClient(t)
		actual, err := c.GetServiceSetting(s.ctx, "")

		require.Nil(t, actual)
		assert.Error(t, err)
	})

	s.Run("with error building request", func() {
		t := s.T()

		c := buildTestClientWithInvalidURL(t)
		actual, err := c.GetServiceSetting(s.ctx, s.exampleServiceSetting.ID)

		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	s.Run("with error executing request", func() {
		t := s.T()

		spec := newRequestSpec(true, http.MethodGet, "", expectedPathFormat, s.exampleServiceSetting.ID)
		c := buildTestClientWithInvalidResponse(t, spec)
		actual, err := c.GetServiceSetting(s.ctx, s.exampleServiceSetting.ID)

		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func (s *serviceSettingsTestSuite) TestClient_GetServiceSettings() {
	const expectedPath = "/api/v1/settings"

	filter := (*types.QueryFilter)(nil)

	s.Run("standard", func() {
		t := s.T()

		spec := newRequestSpec(true, http.MethodGet, "limit=50&page=1&sortBy=asc", expectedPath)
		c, _ := buildTestClientWithJSONResponse(t, spec, s.exampleServiceSettingListResponse)
		actual, err := c.GetServiceSettings(s.ctx, filter)

		require.NotNil(t, actual)
		assert.NoError(t, err)
		assert.Equal(t, s.exampleServiceSettingList, actual.Data)
	})

	s.Run("with error building request", func() {
		t := s.T()

		c := buildTestClientWithInvalidURL(t)
		actual, err := c.GetServiceSettings(s.ctx, filter)

		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	s.Run("with error executing request", func() {
		t := s.T()

		spec := newRequestSpec(true, http.MethodGet, "limit=50&page=1&sortBy=asc", expectedPath)
		c := buildTestClientWithInvalidResponse(t, spec)
		actual, err := c.GetServiceSettings(s.ctx, filter)

		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func (s *serviceSettingsTestSuite) TestClient_SearchServiceSettings() {
	const expectedPath = "/api/v1/settings/search"

	exampleQuery := "whatever"

	s.Run("standard", func() {
		t := s.T()

		spec := newRequestSpec(true, http.MethodGet, "limit=50&q=whatever", expectedPath)
		c, _ := buildTestClientWithJSONResponse(t, spec, s.exampleServiceSettingListResponse)
		actual, err := c.SearchServiceSettings(s.ctx, exampleQuery, 0)

		require.NotNil(t, actual)
		assert.NoError(t, err)
		assert.Equal(t, s.exampleServiceSettingList, actual)
	})

	s.Run("with empty query", func() {
		t := s.T()

		c, _ := buildSimpleTestClient(t)
		actual, err := c.SearchServiceSettings(s.ctx, "", 0)

		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	s.Run("with error building request", func() {
		t := s.T()

		c := buildTestClientWithInvalidURL(t)

		actual, err := c.SearchServiceSettings(s.ctx, exampleQuery, 0)

		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	s.Run("with bad response from server", func() {
		t := s.T()

		spec := newRequestSpec(true, http.MethodGet, "limit=50&q=whatever", expectedPath)
		c := buildTestClientWithInvalidResponse(t, spec)
		actual, err := c.SearchServiceSettings(s.ctx, exampleQuery, 0)

		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}
