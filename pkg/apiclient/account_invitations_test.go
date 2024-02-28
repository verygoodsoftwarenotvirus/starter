package apiclient

import (
	"context"
	"net/http"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

func TestAccountInvitations(t *testing.T) {
	t.Parallel()

	suite.Run(t, new(accountInvitationsTestSuite))
}

type accountInvitationsTestSuite struct {
	suite.Suite
	ctx                                  context.Context
	exampleAccount                       *types.Account
	exampleAccountInvitation             *types.AccountInvitation
	exampleAccountInvitationResponse     *types.APIResponse[*types.AccountInvitation]
	exampleUser                          *types.User
	exampleAccountInvitationListResponse *types.APIResponse[[]*types.AccountInvitation]
	exampleAccountInvitationList         []*types.AccountInvitation
}

var _ suite.SetupTestSuite = (*accountInvitationsTestSuite)(nil)

func (s *accountInvitationsTestSuite) SetupTest() {
	s.ctx = context.Background()
	s.exampleUser = fakes.BuildFakeUser()
	s.exampleAccount = fakes.BuildFakeAccount()
	s.exampleAccount.BelongsToUser = s.exampleUser.ID
	s.exampleAccountInvitation = fakes.BuildFakeAccountInvitation()
	s.exampleAccountInvitation.FromUser = *s.exampleUser
	s.exampleAccountInvitation.ToUser = func(s string) *string { return &s }(fakes.BuildFakeUser().ID)
	s.exampleAccountInvitationResponse = &types.APIResponse[*types.AccountInvitation]{
		Data: s.exampleAccountInvitation,
	}
	exampleList := fakes.BuildFakeAccountInvitationList()
	s.exampleAccountInvitationList = exampleList.Data
	s.exampleAccountInvitationListResponse = &types.APIResponse[[]*types.AccountInvitation]{
		Data:       s.exampleAccountInvitationList,
		Pagination: &exampleList.Pagination,
	}
}

func (s *accountInvitationsTestSuite) TestClient_GetAccountInvitation() {
	const expectedPath = "/api/v1/accounts/%s/invitations/%s"

	s.Run("standard", func() {
		t := s.T()

		s.exampleAccount.BelongsToUser = ""

		spec := newRequestSpec(true, http.MethodGet, "", expectedPath, s.exampleAccount.ID, s.exampleAccountInvitation.ID)
		c, _ := buildTestClientWithJSONResponse(t, spec, s.exampleAccountInvitationResponse)

		actual, err := c.GetAccountInvitation(s.ctx, s.exampleAccount.ID, s.exampleAccountInvitation.ID)
		assert.NoError(t, err)
		assert.NotNil(t, actual)
	})

	s.Run("with invalid account ID", func() {
		t := s.T()

		s.exampleAccount.BelongsToUser = ""

		spec := newRequestSpec(true, http.MethodGet, "", expectedPath, s.exampleAccount.ID, s.exampleAccountInvitation.ID)
		c, _ := buildTestClientWithJSONResponse(t, spec, s.exampleAccountInvitation)

		actual, err := c.GetAccountInvitation(s.ctx, "", s.exampleAccountInvitation.ID)
		assert.Error(t, err)
		assert.Nil(t, actual)
	})

	s.Run("with invalid invitation ID", func() {
		t := s.T()

		s.exampleAccount.BelongsToUser = ""

		spec := newRequestSpec(true, http.MethodGet, "", expectedPath, s.exampleAccount.ID, s.exampleAccountInvitation.ID)
		c, _ := buildTestClientWithJSONResponse(t, spec, s.exampleAccountInvitation)

		actual, err := c.GetAccountInvitation(s.ctx, s.exampleAccount.ID, "")
		assert.Error(t, err)
		assert.Nil(t, actual)
	})

	s.Run("with error building request", func() {
		t := s.T()

		s.exampleAccount.BelongsToUser = ""

		c := buildTestClientWithInvalidURL(t)

		actual, err := c.GetAccountInvitation(s.ctx, s.exampleAccount.ID, s.exampleAccountInvitation.ID)
		assert.Error(t, err)
		assert.Nil(t, actual)
	})

	s.Run("with error executing request", func() {
		t := s.T()

		s.exampleAccount.BelongsToUser = ""

		c, _ := buildTestClientThatWaitsTooLong(t)

		actual, err := c.GetAccountInvitation(s.ctx, s.exampleAccount.ID, s.exampleAccountInvitation.ID)
		assert.Error(t, err)
		assert.Nil(t, actual)
	})
}

func (s *accountInvitationsTestSuite) TestClient_GetPendingAccountInvitationsForUser() {
	const expectedPath = "/api/v1/account_invitations/received"

	s.Run("standard", func() {
		t := s.T()

		filter := types.DefaultQueryFilter()
		s.exampleAccount.BelongsToUser = ""

		spec := newRequestSpec(true, http.MethodGet, "limit=50&page=1&sortBy=asc", expectedPath)
		c, _ := buildTestClientWithJSONResponse(t, spec, s.exampleAccountInvitationListResponse)

		actual, err := c.GetPendingAccountInvitationsForUser(s.ctx, filter)
		assert.NoError(t, err)
		assert.NotNil(t, actual)
	})

	s.Run("with error building request", func() {
		t := s.T()

		filter := types.DefaultQueryFilter()

		c := buildTestClientWithInvalidURL(t)

		actual, err := c.GetPendingAccountInvitationsForUser(s.ctx, filter)
		assert.Error(t, err)
		assert.Nil(t, actual)
	})

	s.Run("with error executing request", func() {
		t := s.T()

		filter := types.DefaultQueryFilter()

		c, _ := buildTestClientThatWaitsTooLong(t)

		actual, err := c.GetPendingAccountInvitationsForUser(s.ctx, filter)
		assert.Error(t, err)
		assert.Nil(t, actual)
	})
}

func (s *accountInvitationsTestSuite) TestClient_GetPendingAccountInvitationsFromUser() {
	const expectedPath = "/api/v1/account_invitations/sent"

	s.Run("standard", func() {
		t := s.T()

		filter := types.DefaultQueryFilter()
		s.exampleAccount.BelongsToUser = ""

		spec := newRequestSpec(true, http.MethodGet, "limit=50&page=1&sortBy=asc", expectedPath)
		c, _ := buildTestClientWithJSONResponse(t, spec, s.exampleAccountInvitationListResponse)

		actual, err := c.GetPendingAccountInvitationsFromUser(s.ctx, filter)
		assert.NoError(t, err)
		assert.NotNil(t, actual)
	})

	s.Run("with error building request", func() {
		t := s.T()

		filter := types.DefaultQueryFilter()

		c := buildTestClientWithInvalidURL(t)

		actual, err := c.GetPendingAccountInvitationsFromUser(s.ctx, filter)
		assert.Error(t, err)
		assert.Nil(t, actual)
	})

	s.Run("with error executing request", func() {
		t := s.T()

		filter := types.DefaultQueryFilter()

		c, _ := buildTestClientThatWaitsTooLong(t)

		actual, err := c.GetPendingAccountInvitationsFromUser(s.ctx, filter)
		assert.Error(t, err)
		assert.Nil(t, actual)
	})
}

func (s *accountInvitationsTestSuite) TestClient_AcceptAccountInvitation() {
	const expectedPath = "/api/v1/account_invitations/%s/accept"

	s.Run("standard", func() {
		t := s.T()

		s.exampleAccount.BelongsToUser = ""

		spec := newRequestSpec(false, http.MethodPut, "", expectedPath, s.exampleAccountInvitation.ID)
		c, _ := buildTestClientWithJSONResponse(t, spec, s.exampleAccountInvitationResponse)

		assert.NoError(t, c.AcceptAccountInvitation(s.ctx, s.exampleAccountInvitation.ID, s.exampleAccountInvitation.Token, t.Name()))
	})

	s.Run("with invalid token", func() {
		t := s.T()

		s.exampleAccount.BelongsToUser = ""

		spec := newRequestSpec(false, http.MethodPut, "", expectedPath, s.exampleAccountInvitation.ID)
		c, _ := buildTestClientWithJSONResponse(t, spec, s.exampleAccountInvitationResponse)

		assert.Error(t, c.AcceptAccountInvitation(s.ctx, s.exampleAccountInvitation.ID, "", t.Name()))
	})

	s.Run("with invalid account invitation ID", func() {
		t := s.T()

		s.exampleAccount.BelongsToUser = ""

		spec := newRequestSpec(false, http.MethodPut, "", expectedPath, s.exampleAccountInvitation.ID)
		c, _ := buildTestClientWithJSONResponse(t, spec, s.exampleAccountInvitationResponse)

		assert.Error(t, c.AcceptAccountInvitation(s.ctx, "", s.exampleAccountInvitation.Token, t.Name()))
	})

	s.Run("with error building request", func() {
		t := s.T()

		c := buildTestClientWithInvalidURL(t)

		assert.Error(t, c.AcceptAccountInvitation(s.ctx, s.exampleAccountInvitation.ID, s.exampleAccountInvitation.Token, t.Name()))
	})

	s.Run("with error executing request", func() {
		t := s.T()

		c, _ := buildTestClientThatWaitsTooLong(t)

		assert.Error(t, c.AcceptAccountInvitation(s.ctx, s.exampleAccountInvitation.ID, s.exampleAccountInvitation.Token, t.Name()))
	})
}

func (s *accountInvitationsTestSuite) TestClient_CancelAccountInvitation() {
	const expectedPath = "/api/v1/account_invitations/%s/cancel"

	s.Run("standard", func() {
		t := s.T()

		s.exampleAccount.BelongsToUser = ""

		spec := newRequestSpec(false, http.MethodPut, "", expectedPath, s.exampleAccountInvitation.ID)
		c, _ := buildTestClientWithJSONResponse(t, spec, s.exampleAccountInvitationResponse)

		assert.NoError(t, c.CancelAccountInvitation(s.ctx, s.exampleAccountInvitation.ID, s.exampleAccountInvitation.Token, t.Name()))
	})

	s.Run("with invalid account ID", func() {
		t := s.T()

		s.exampleAccount.BelongsToUser = ""

		spec := newRequestSpec(false, http.MethodPut, "", expectedPath, s.exampleAccountInvitation.ID)
		c, _ := buildTestClientWithJSONResponse(t, spec, s.exampleAccountInvitationResponse)

		assert.Error(t, c.CancelAccountInvitation(s.ctx, "", s.exampleAccountInvitation.ID, t.Name()))
	})

	s.Run("with invalid account invitation ID", func() {
		t := s.T()

		s.exampleAccount.BelongsToUser = ""

		spec := newRequestSpec(false, http.MethodPut, "", expectedPath, s.exampleAccountInvitation.ID)
		c, _ := buildTestClientWithJSONResponse(t, spec, s.exampleAccountInvitationResponse)

		assert.Error(t, c.CancelAccountInvitation(s.ctx, s.exampleAccountInvitation.ID, "", t.Name()))
	})

	s.Run("with error building request", func() {
		t := s.T()

		c := buildTestClientWithInvalidURL(t)

		assert.Error(t, c.CancelAccountInvitation(s.ctx, s.exampleAccountInvitation.ID, s.exampleAccountInvitation.Token, t.Name()))
	})

	s.Run("with error executing request", func() {
		t := s.T()

		s.exampleAccount.BelongsToUser = ""

		c, _ := buildTestClientThatWaitsTooLong(t)

		assert.Error(t, c.CancelAccountInvitation(s.ctx, s.exampleAccountInvitation.ID, s.exampleAccountInvitation.Token, t.Name()))
	})
}

func (s *accountInvitationsTestSuite) TestClient_RejectAccountInvitation() {
	const expectedPath = "/api/v1/account_invitations/%s/reject"

	s.Run("standard", func() {
		t := s.T()

		s.exampleAccount.BelongsToUser = ""

		spec := newRequestSpec(false, http.MethodPut, "", expectedPath, s.exampleAccountInvitation.ID)
		c, _ := buildTestClientWithJSONResponse(t, spec, s.exampleAccountInvitationResponse)

		assert.NoError(t, c.RejectAccountInvitation(s.ctx, s.exampleAccountInvitation.ID, s.exampleAccountInvitation.Token, t.Name()))
	})

	s.Run("with invalid account ID", func() {
		t := s.T()

		s.exampleAccount.BelongsToUser = ""

		spec := newRequestSpec(false, http.MethodPut, "", expectedPath, s.exampleAccountInvitation.ID)
		c, _ := buildTestClientWithJSONResponse(t, spec, s.exampleAccountInvitationResponse)

		assert.Error(t, c.RejectAccountInvitation(s.ctx, "", s.exampleAccountInvitation.ID, t.Name()))
	})

	s.Run("with invalid account invitation ID", func() {
		t := s.T()

		s.exampleAccount.BelongsToUser = ""

		spec := newRequestSpec(false, http.MethodPut, "", expectedPath, s.exampleAccountInvitation.ID)
		c, _ := buildTestClientWithJSONResponse(t, spec, s.exampleAccountInvitationResponse)

		assert.Error(t, c.RejectAccountInvitation(s.ctx, s.exampleAccountInvitation.ID, "", t.Name()))
	})

	s.Run("with error building request", func() {
		t := s.T()

		c := buildTestClientWithInvalidURL(t)

		assert.Error(t, c.RejectAccountInvitation(s.ctx, s.exampleAccountInvitation.ID, s.exampleAccountInvitation.Token, t.Name()))
	})

	s.Run("with error executing request", func() {
		t := s.T()

		c, _ := buildTestClientThatWaitsTooLong(t)

		assert.Error(t, c.RejectAccountInvitation(s.ctx, s.exampleAccountInvitation.ID, s.exampleAccountInvitation.Token, t.Name()))
	})
}
