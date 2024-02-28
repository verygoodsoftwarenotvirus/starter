package apiclient

import (
	"context"
	"net/http"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/converters"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func TestOAuth2Clients(t *testing.T) {
	t.Parallel()

	suite.Run(t, new(oauth2ClientsTestSuite))
}

type oauth2ClientsTestSuite struct {
	suite.Suite
	ctx                             context.Context
	exampleOAuth2Client             *types.OAuth2Client
	exampleOAuth2ClientResponse     *types.APIResponse[*types.OAuth2Client]
	exampleOAuth2ClientListResponse *types.APIResponse[[]*types.OAuth2Client]
	exampleOAuth2ClientList         []*types.OAuth2Client
}

var _ suite.SetupTestSuite = (*oauth2ClientsTestSuite)(nil)

func (s *oauth2ClientsTestSuite) SetupTest() {
	s.ctx = context.Background()
	s.exampleOAuth2Client = fakes.BuildFakeOAuth2Client()
	s.exampleOAuth2Client.ClientSecret = ""
	exampleOAuth2ClientList := fakes.BuildFakeOAuth2ClientList()
	for i := 0; i < len(exampleOAuth2ClientList.Data); i++ {
		exampleOAuth2ClientList.Data[i].ClientSecret = ""
	}

	s.exampleOAuth2ClientList = exampleOAuth2ClientList.Data
	s.exampleOAuth2ClientResponse = &types.APIResponse[*types.OAuth2Client]{
		Data: s.exampleOAuth2Client,
	}
	s.exampleOAuth2ClientListResponse = &types.APIResponse[[]*types.OAuth2Client]{
		Data:       exampleOAuth2ClientList.Data,
		Pagination: &exampleOAuth2ClientList.Pagination,
	}
}

func (s *oauth2ClientsTestSuite) TestClient_GetOAuth2Client() {
	const expectedPathFormat = "/api/v1/oauth2_clients/%s"

	s.Run("standard", func() {
		t := s.T()

		spec := newRequestSpec(true, http.MethodGet, "", expectedPathFormat, s.exampleOAuth2Client.ID)
		c, _ := buildTestClientWithJSONResponse(t, spec, s.exampleOAuth2ClientResponse)

		actual, err := c.GetOAuth2Client(s.ctx, s.exampleOAuth2Client.ID)
		require.NotNil(t, actual)
		assert.NoError(t, err)
		assert.Equal(t, s.exampleOAuth2Client, actual)
	})

	s.Run("with invalid API client ID", func() {
		t := s.T()

		spec := newRequestSpec(true, http.MethodGet, "", expectedPathFormat, s.exampleOAuth2Client.ID)
		c, _ := buildTestClientWithJSONResponse(t, spec, s.exampleOAuth2Client)

		actual, err := c.GetOAuth2Client(s.ctx, "")
		assert.Error(t, err)
		assert.Nil(t, actual)
	})

	s.Run("with error building request", func() {
		t := s.T()

		c := buildTestClientWithInvalidURL(t)

		actual, err := c.GetOAuth2Client(s.ctx, s.exampleOAuth2Client.ID)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	s.Run("with error executing request", func() {
		t := s.T()

		c, _ := buildTestClientThatWaitsTooLong(t)

		actual, err := c.GetOAuth2Client(s.ctx, s.exampleOAuth2Client.ID)
		assert.Error(t, err)
		assert.Nil(t, actual)
	})
}

func (s *oauth2ClientsTestSuite) TestClient_GetOAuth2Clients() {
	const expectedPath = "/api/v1/oauth2_clients"

	s.Run("standard", func() {
		t := s.T()

		spec := newRequestSpec(true, http.MethodGet, "limit=50&page=1&sortBy=asc", expectedPath)
		c, _ := buildTestClientWithJSONResponse(t, spec, s.exampleOAuth2ClientListResponse)

		actual, err := c.GetOAuth2Clients(s.ctx, nil)
		require.NotNil(t, actual)
		assert.NoError(t, err)
		assert.Equal(t, s.exampleOAuth2ClientList, actual.Data)
	})

	s.Run("with error building request", func() {
		t := s.T()

		c := buildTestClientWithInvalidURL(t)
		actual, err := c.GetOAuth2Clients(s.ctx, nil)

		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	s.Run("with error executing request", func() {
		t := s.T()

		c, _ := buildTestClientThatWaitsTooLong(t)

		actual, err := c.GetOAuth2Clients(s.ctx, nil)
		assert.Error(t, err)
		assert.Nil(t, actual)
	})
}

func (s *oauth2ClientsTestSuite) TestClient_CreateOAuth2Client() {
	const expectedPath = "/api/v1/oauth2_clients"

	s.Run("standard", func() {
		t := s.T()

		exampleInput := converters.ConvertOAuth2ClientToOAuth2ClientCreationInput(s.exampleOAuth2Client)
		exampleResponse := converters.ConvertOAuth2ClientToOAuth2ClientCreationResponse(s.exampleOAuth2Client)

		spec := newRequestSpec(false, http.MethodPost, "", expectedPath)
		c, _ := buildTestClientWithJSONResponse(t, spec, &types.APIResponse[*types.OAuth2ClientCreationResponse]{
			Data: exampleResponse,
		})
		c.authMethod = cookieAuthMethod

		actual, err := c.CreateOAuth2Client(s.ctx, exampleInput)
		assert.NoError(t, err)
		assert.Equal(t, exampleResponse, actual)
	})

	s.Run("with nil input", func() {
		t := s.T()

		c, _ := buildTestClientWithJSONResponse(t, nil, s.exampleOAuth2Client)

		_, err := c.CreateOAuth2Client(s.ctx, nil)
		assert.Error(t, err)
	})

	s.Run("with error building request", func() {
		t := s.T()

		exampleInput := converters.ConvertOAuth2ClientToOAuth2ClientCreationInput(s.exampleOAuth2Client)
		c := buildTestClientWithInvalidURL(t)
		c.authMethod = cookieAuthMethod

		actual, err := c.CreateOAuth2Client(s.ctx, exampleInput)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	s.Run("with invalid response from server", func() {
		t := s.T()

		exampleInput := converters.ConvertOAuth2ClientToOAuth2ClientCreationInput(s.exampleOAuth2Client)
		spec := newRequestSpec(false, http.MethodPost, "", expectedPath)
		c := buildTestClientWithInvalidResponse(t, spec)
		c.authMethod = cookieAuthMethod

		actual, err := c.CreateOAuth2Client(s.ctx, exampleInput)
		assert.Error(t, err)
		assert.Nil(t, actual)
	})
}

func (s *oauth2ClientsTestSuite) TestClient_ArchiveOAuth2Client() {
	const expectedPathFormat = "/api/v1/oauth2_clients/%s"

	s.Run("standard", func() {
		t := s.T()

		spec := newRequestSpec(true, http.MethodDelete, "", expectedPathFormat, s.exampleOAuth2Client.ID)
		c, _ := buildTestClientWithJSONResponse(t, spec, s.exampleOAuth2ClientResponse)

		assert.NoError(t, c.ArchiveOAuth2Client(s.ctx, s.exampleOAuth2Client.ID), "no error should be returned")
	})

	s.Run("with invalid API client ID", func() {
		t := s.T()

		spec := newRequestSpec(true, http.MethodDelete, "", expectedPathFormat, s.exampleOAuth2Client.ID)
		c, _ := buildTestClientWithStatusCodeResponse(t, spec, http.StatusOK)

		assert.Error(t, c.ArchiveOAuth2Client(s.ctx, ""), "no error should be returned")
	})

	s.Run("with error building request", func() {
		t := s.T()

		c := buildTestClientWithInvalidURL(t)
		assert.Error(t, c.ArchiveOAuth2Client(s.ctx, s.exampleOAuth2Client.ID), "error should be returned")
	})

	s.Run("with error executing request", func() {
		t := s.T()

		c, _ := buildTestClientThatWaitsTooLong(t)

		assert.Error(t, c.ArchiveOAuth2Client(s.ctx, s.exampleOAuth2Client.ID), "no error should be returned")
	})
}
