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

func TestAccounts(t *testing.T) {
	t.Parallel()

	suite.Run(t, new(accountsTestSuite))
}

type accountsTestSuite struct {
	suite.Suite
	ctx                        context.Context
	exampleUser                *types.User
	exampleAccount             *types.Account
	exampleAccountResponse     *types.APIResponse[*types.Account]
	exampleAccountListResponse *types.APIResponse[[]*types.Account]
	exampleAccountList         []*types.Account
}

var _ suite.SetupTestSuite = (*accountsTestSuite)(nil)

func (s *accountsTestSuite) SetupTest() {
	s.ctx = context.Background()
	s.exampleUser = fakes.BuildFakeUser()
	s.exampleAccount = fakes.BuildFakeAccount()
	s.exampleAccount.WebhookEncryptionKey = ""
	s.exampleAccount.BelongsToUser = s.exampleUser.ID
	exampleAccountList := fakes.BuildFakeAccountList()
	for i := range exampleAccountList.Data {
		exampleAccountList.Data[i].WebhookEncryptionKey = ""
	}

	s.exampleAccountList = exampleAccountList.Data
	s.exampleAccountListResponse = &types.APIResponse[[]*types.Account]{
		Data:       exampleAccountList.Data,
		Pagination: &exampleAccountList.Pagination,
	}
	s.exampleAccountResponse = &types.APIResponse[*types.Account]{
		Data: s.exampleAccount,
	}
}

func (s *accountsTestSuite) TestClient_SwitchActiveAccount() {
	const expectedPath = "/api/v1/users/account/select"

	s.Run("standard", func() {
		t := s.T()

		s.exampleAccount.BelongsToUser = ""

		spec := newRequestSpec(false, http.MethodPost, "", expectedPath)
		c, _ := buildTestClientWithJSONResponse(t, spec, s.exampleAccountResponse)
		c.authMethod = cookieAuthMethod

		assert.NoError(t, c.SwitchActiveAccount(s.ctx, s.exampleAccount.ID))
	})

	s.Run("with invalid account ID", func() {
		t := s.T()

		c, _ := buildSimpleTestClient(t)
		c.authMethod = cookieAuthMethod

		assert.Error(t, c.SwitchActiveAccount(s.ctx, ""))
	})

	s.Run("with error building request", func() {
		t := s.T()

		c := buildTestClientWithInvalidURL(t)
		c.authMethod = cookieAuthMethod

		assert.Error(t, c.SwitchActiveAccount(s.ctx, s.exampleAccount.ID))
	})

	s.Run("with error executing request", func() {
		t := s.T()

		c, _ := buildTestClientThatWaitsTooLong(t)
		c.authMethod = cookieAuthMethod

		assert.Error(t, c.SwitchActiveAccount(s.ctx, s.exampleAccount.ID))
	})
}

func (s *accountsTestSuite) TestClient_GetCurrentAccount() {
	const expectedPathFormat = "/api/v1/accounts/current"

	s.Run("standard", func() {
		t := s.T()

		spec := newRequestSpec(true, http.MethodGet, "", expectedPathFormat)
		c, _ := buildTestClientWithJSONResponse(t, spec, s.exampleAccountResponse)

		actual, err := c.GetCurrentAccount(s.ctx)

		for i := range actual.Members {
			actual.Members[i].BelongsToUser.TwoFactorSecretVerifiedAt = s.exampleAccount.Members[i].BelongsToUser.TwoFactorSecretVerifiedAt
		}

		require.NotNil(t, actual)
		assert.NoError(t, err)
		assert.Equal(t, s.exampleAccount, actual)
	})

	s.Run("with error building request", func() {
		t := s.T()

		c := buildTestClientWithInvalidURL(t)
		actual, err := c.GetCurrentAccount(s.ctx)

		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	s.Run("with error executing request", func() {
		t := s.T()

		spec := newRequestSpec(true, http.MethodGet, "", expectedPathFormat)

		c := buildTestClientWithInvalidResponse(t, spec)
		actual, err := c.GetCurrentAccount(s.ctx)

		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func (s *accountsTestSuite) TestClient_GetAccount() {
	const expectedPathFormat = "/api/v1/accounts/%s"

	s.Run("standard", func() {
		t := s.T()

		spec := newRequestSpec(true, http.MethodGet, "", expectedPathFormat, s.exampleAccount.ID)
		c, _ := buildTestClientWithJSONResponse(t, spec, s.exampleAccountResponse)

		actual, err := c.GetAccount(s.ctx, s.exampleAccount.ID)

		for i := range actual.Members {
			actual.Members[i].BelongsToUser.TwoFactorSecretVerifiedAt = s.exampleAccount.Members[i].BelongsToUser.TwoFactorSecretVerifiedAt
		}

		require.NotNil(t, actual)
		assert.NoError(t, err)
		assert.Equal(t, s.exampleAccount, actual)
	})

	s.Run("with invalid account ID", func() {
		t := s.T()

		c, _ := buildSimpleTestClient(t)

		actual, err := c.GetAccount(s.ctx, "")
		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	s.Run("with error building request", func() {
		t := s.T()

		c := buildTestClientWithInvalidURL(t)
		actual, err := c.GetAccount(s.ctx, s.exampleAccount.ID)

		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	s.Run("with error executing request", func() {
		t := s.T()

		spec := newRequestSpec(true, http.MethodGet, "", expectedPathFormat, s.exampleAccount.ID)

		c := buildTestClientWithInvalidResponse(t, spec)
		actual, err := c.GetAccount(s.ctx, s.exampleAccount.ID)

		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func (s *accountsTestSuite) TestClient_GetAccounts() {
	const expectedPath = "/api/v1/accounts"

	spec := newRequestSpec(true, http.MethodGet, "limit=50&page=1&sortBy=asc", expectedPath)
	filter := (*types.QueryFilter)(nil)

	s.Run("standard", func() {
		t := s.T()

		c, _ := buildTestClientWithJSONResponse(t, spec, s.exampleAccountListResponse)
		actual, err := c.GetAccounts(s.ctx, filter)

		for i, account := range actual.Data {
			for j := range account.Members {
				actual.Data[i].Members[j].BelongsToUser.TwoFactorSecretVerifiedAt = s.exampleAccountList[i].Members[j].BelongsToUser.TwoFactorSecretVerifiedAt
			}
		}

		require.NotNil(t, actual)
		assert.NoError(t, err)
		assert.Equal(t, s.exampleAccountList, actual.Data)
	})

	s.Run("with error building request", func() {
		t := s.T()

		c := buildTestClientWithInvalidURL(t)
		actual, err := c.GetAccounts(s.ctx, filter)

		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	s.Run("with error executing request", func() {
		t := s.T()

		c := buildTestClientWithInvalidResponse(t, spec)
		actual, err := c.GetAccounts(s.ctx, filter)

		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func (s *accountsTestSuite) TestClient_CreateAccount() {
	const expectedPath = "/api/v1/accounts"

	spec := newRequestSpec(false, http.MethodPost, "", expectedPath)

	s.Run("standard", func() {
		t := s.T()

		s.exampleAccount.BelongsToUser = ""
		exampleInput := converters.ConvertAccountToAccountCreationRequestInput(s.exampleAccount)

		c := buildTestClientWithRequestBodyValidation(t, spec, exampleInput, exampleInput, s.exampleAccountResponse)
		actual, err := c.CreateAccount(s.ctx, exampleInput)

		for i := range actual.Members {
			actual.Members[i].BelongsToUser.TwoFactorSecretVerifiedAt = s.exampleAccount.Members[i].BelongsToUser.TwoFactorSecretVerifiedAt
		}

		require.NotNil(t, actual)
		assert.NoError(t, err)
		assert.Equal(t, s.exampleAccount, actual)
	})

	s.Run("with nil input", func() {
		t := s.T()

		c, _ := buildSimpleTestClient(t)

		actual, err := c.CreateAccount(s.ctx, nil)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	s.Run("with invalid input", func() {
		t := s.T()

		exampleInput := &types.AccountCreationRequestInput{}
		c, _ := buildSimpleTestClient(t)

		actual, err := c.CreateAccount(s.ctx, exampleInput)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	s.Run("with error building request", func() {
		t := s.T()

		exampleInput := converters.ConvertAccountToAccountCreationRequestInput(s.exampleAccount)
		c := buildTestClientWithInvalidURL(t)

		actual, err := c.CreateAccount(s.ctx, exampleInput)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	s.Run("with error executing request", func() {
		t := s.T()

		s.exampleAccount.BelongsToUser = ""
		exampleInput := converters.ConvertAccountToAccountCreationRequestInput(s.exampleAccount)

		c, _ := buildTestClientThatWaitsTooLong(t)

		actual, err := c.CreateAccount(s.ctx, exampleInput)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func (s *accountsTestSuite) TestClient_UpdateAccount() {
	const expectedPathFormat = "/api/v1/accounts/%s"

	s.Run("standard", func() {
		t := s.T()

		spec := newRequestSpec(false, http.MethodPut, "", expectedPathFormat, s.exampleAccount.ID)
		c, _ := buildTestClientWithJSONResponse(t, spec, s.exampleAccountResponse)

		assert.NoError(t, c.UpdateAccount(s.ctx, s.exampleAccount), "no error should be returned")
	})

	s.Run("with nil input", func() {
		t := s.T()

		c, _ := buildSimpleTestClient(t)

		assert.Error(t, c.UpdateAccount(s.ctx, nil), "error should be returned")
	})

	s.Run("with error building request", func() {
		t := s.T()

		c := buildTestClientWithInvalidURL(t)

		err := c.UpdateAccount(s.ctx, s.exampleAccount)
		assert.Error(t, err)
	})

	s.Run("with error executing request", func() {
		t := s.T()

		c, _ := buildTestClientThatWaitsTooLong(t)

		assert.Error(t, c.UpdateAccount(s.ctx, s.exampleAccount), "error should be returned")
	})
}

func (s *accountsTestSuite) TestClient_ArchiveAccount() {
	const expectedPathFormat = "/api/v1/accounts/%s"

	s.Run("standard", func() {
		t := s.T()

		spec := newRequestSpec(true, http.MethodDelete, "", expectedPathFormat, s.exampleAccount.ID)
		c, _ := buildTestClientWithJSONResponse(t, spec, s.exampleAccountResponse)

		assert.NoError(t, c.ArchiveAccount(s.ctx, s.exampleAccount.ID), "no error should be returned")
	})

	s.Run("with invalid account ID", func() {
		t := s.T()

		c, _ := buildSimpleTestClient(t)

		assert.Error(t, c.ArchiveAccount(s.ctx, ""), "no error should be returned")
	})

	s.Run("with error building request", func() {
		t := s.T()

		c := buildTestClientWithInvalidURL(t)
		assert.Error(t, c.ArchiveAccount(s.ctx, s.exampleAccount.ID), "error should be returned")
	})

	s.Run("with error executing request", func() {
		t := s.T()

		c, _ := buildTestClientThatWaitsTooLong(t)

		assert.Error(t, c.ArchiveAccount(s.ctx, s.exampleAccount.ID), "no error should be returned")
	})
}

func (s *accountsTestSuite) TestClient_InviteUserToAccount() {
	const expectedPathFormat = "/api/v1/accounts/%s/invite"

	s.Run("standard", func() {
		t := s.T()

		invitation := fakes.BuildFakeAccountInvitation()
		exampleAccountID := fakes.BuildFakeID()
		invitation.FromUser.TwoFactorSecret = ""
		invitation.DestinationAccount.WebhookEncryptionKey = ""
		invitationResponse := &types.APIResponse[*types.AccountInvitation]{
			Data: invitation,
		}

		exampleInput := converters.ConvertAccountInvitationToAccountInvitationCreationInput(invitation)
		spec := newRequestSpec(false, http.MethodPost, "", expectedPathFormat, exampleAccountID)
		c, _ := buildTestClientWithJSONResponse(t, spec, invitationResponse)

		accountInvite, err := c.InviteUserToAccount(s.ctx, exampleAccountID, exampleInput)
		assert.Equal(t, invitation, accountInvite)
		assert.NoError(t, err)
	})

	s.Run("with nil input", func() {
		t := s.T()

		c, _ := buildSimpleTestClient(t)

		exampleAccountID := fakes.BuildFakeID()

		accountInvite, err := c.InviteUserToAccount(s.ctx, exampleAccountID, nil)
		assert.Nil(t, accountInvite)
		assert.Error(t, err)
	})

	s.Run("with invalid input", func() {
		t := s.T()

		c, _ := buildSimpleTestClient(t)

		exampleAccountID := fakes.BuildFakeID()

		accountInvite, err := c.InviteUserToAccount(s.ctx, exampleAccountID, &types.AccountInvitationCreationRequestInput{})
		assert.Nil(t, accountInvite)
		assert.Error(t, err)
	})

	s.Run("with error building request", func() {
		t := s.T()

		c := buildTestClientWithInvalidURL(t)

		exampleAccountID := fakes.BuildFakeID()
		exampleInput := fakes.BuildFakeAccountInvitationCreationRequestInput()

		accountInvite, err := c.InviteUserToAccount(s.ctx, exampleAccountID, exampleInput)
		assert.Nil(t, accountInvite)
		assert.Error(t, err)
	})

	s.Run("with error executing request", func() {
		t := s.T()

		c, _ := buildTestClientThatWaitsTooLong(t)

		exampleAccountID := fakes.BuildFakeID()
		exampleInput := fakes.BuildFakeAccountInvitationCreationRequestInput()

		accountInvite, err := c.InviteUserToAccount(s.ctx, exampleAccountID, exampleInput)
		assert.Nil(t, accountInvite)
		assert.Error(t, err)
	})
}

func (s *accountsTestSuite) TestClient_MarkAsDefault() {
	const expectedPathFormat = "/api/v1/accounts/%s/default"

	s.Run("standard", func() {
		t := s.T()

		spec := newRequestSpec(true, http.MethodPost, "", expectedPathFormat, s.exampleAccount.ID)
		c, _ := buildTestClientWithJSONResponse(t, spec, s.exampleAccountResponse)

		assert.NoError(t, c.MarkAsDefault(s.ctx, s.exampleAccount.ID))
	})

	s.Run("with invalid account ID", func() {
		t := s.T()

		c, _ := buildSimpleTestClient(t)

		assert.Error(t, c.MarkAsDefault(s.ctx, ""))
	})

	s.Run("with error building request", func() {
		t := s.T()

		c := buildTestClientWithInvalidURL(t)

		assert.Error(t, c.MarkAsDefault(s.ctx, s.exampleAccount.ID))
	})

	s.Run("with error executing request", func() {
		t := s.T()

		c, _ := buildTestClientThatWaitsTooLong(t)

		assert.Error(t, c.MarkAsDefault(s.ctx, s.exampleAccount.ID))
	})
}

func (s *accountsTestSuite) TestClient_RemoveUserFromAccount() {
	const expectedPathFormat = "/api/v1/accounts/%s/members/%s"

	s.Run("standard", func() {
		t := s.T()

		spec := newRequestSpec(true, http.MethodDelete, "", expectedPathFormat, s.exampleAccount.ID, s.exampleUser.ID)
		c, _ := buildTestClientWithJSONResponse(t, spec, s.exampleAccountResponse)

		assert.NoError(t, c.RemoveUserFromAccount(s.ctx, s.exampleAccount.ID, s.exampleUser.ID))
	})

	s.Run("with invalid account ID", func() {
		t := s.T()

		c, _ := buildSimpleTestClient(t)

		assert.Error(t, c.RemoveUserFromAccount(s.ctx, "", s.exampleUser.ID))
	})

	s.Run("with invalid user ID", func() {
		t := s.T()

		c, _ := buildSimpleTestClient(t)

		assert.Error(t, c.RemoveUserFromAccount(s.ctx, s.exampleAccount.ID, ""))
	})

	s.Run("with error building request", func() {
		t := s.T()

		c := buildTestClientWithInvalidURL(t)

		assert.Error(t, c.RemoveUserFromAccount(s.ctx, s.exampleAccount.ID, s.exampleUser.ID))
	})

	s.Run("with error executing request", func() {
		t := s.T()

		c, _ := buildTestClientThatWaitsTooLong(t)

		assert.Error(t, c.RemoveUserFromAccount(s.ctx, s.exampleAccount.ID, s.exampleUser.ID))
	})
}

func (s *accountsTestSuite) TestClient_ModifyMemberPermissions() {
	const expectedPathFormat = "/api/v1/accounts/%s/members/%s/permissions"

	s.Run("standard", func() {
		t := s.T()

		spec := newRequestSpec(false, http.MethodPatch, "", expectedPathFormat, s.exampleAccount.ID, s.exampleUser.ID)
		c, _ := buildTestClientWithJSONResponse(t, spec, s.exampleAccountResponse)
		exampleInput := fakes.BuildFakeUserPermissionModificationInput()

		assert.NoError(t, c.ModifyMemberPermissions(s.ctx, s.exampleAccount.ID, s.exampleUser.ID, exampleInput))
	})

	s.Run("with invalid account ID", func() {
		t := s.T()

		c, _ := buildSimpleTestClient(t)
		exampleInput := fakes.BuildFakeUserPermissionModificationInput()

		assert.Error(t, c.ModifyMemberPermissions(s.ctx, "", s.exampleUser.ID, exampleInput))
	})

	s.Run("with invalid user ID", func() {
		t := s.T()

		c, _ := buildSimpleTestClient(t)
		exampleInput := fakes.BuildFakeUserPermissionModificationInput()

		assert.Error(t, c.ModifyMemberPermissions(s.ctx, s.exampleAccount.ID, "", exampleInput))
	})

	s.Run("with nil input", func() {
		t := s.T()

		c, _ := buildSimpleTestClient(t)

		assert.Error(t, c.ModifyMemberPermissions(s.ctx, s.exampleAccount.ID, s.exampleUser.ID, nil))
	})

	s.Run("with invalid input", func() {
		t := s.T()

		c, _ := buildSimpleTestClient(t)
		exampleInput := &types.ModifyUserPermissionsInput{}

		assert.Error(t, c.ModifyMemberPermissions(s.ctx, s.exampleAccount.ID, s.exampleUser.ID, exampleInput))
	})

	s.Run("with error building request", func() {
		t := s.T()

		c := buildTestClientWithInvalidURL(t)
		exampleInput := fakes.BuildFakeUserPermissionModificationInput()

		assert.Error(t, c.ModifyMemberPermissions(s.ctx, s.exampleAccount.ID, s.exampleUser.ID, exampleInput))
	})

	s.Run("with error executing request", func() {
		t := s.T()

		c, _ := buildTestClientThatWaitsTooLong(t)
		exampleInput := fakes.BuildFakeUserPermissionModificationInput()

		assert.Error(t, c.ModifyMemberPermissions(s.ctx, s.exampleAccount.ID, s.exampleUser.ID, exampleInput))
	})
}

func (s *accountsTestSuite) TestClient_TransferAccountOwnership() {
	const expectedPathFormat = "/api/v1/accounts/%s/transfer"

	s.Run("standard", func() {
		t := s.T()

		spec := newRequestSpec(false, http.MethodPost, "", expectedPathFormat, s.exampleAccount.ID)
		c, _ := buildTestClientWithJSONResponse(t, spec, s.exampleAccountResponse)
		exampleInput := fakes.BuildFakeTransferAccountOwnershipInput()

		assert.NoError(t, c.TransferAccountOwnership(s.ctx, s.exampleAccount.ID, exampleInput))
	})

	s.Run("with invalid account ID", func() {
		t := s.T()

		c, _ := buildSimpleTestClient(t)
		exampleInput := fakes.BuildFakeTransferAccountOwnershipInput()

		assert.Error(t, c.TransferAccountOwnership(s.ctx, "", exampleInput))
	})

	s.Run("with nil input", func() {
		t := s.T()

		c, _ := buildSimpleTestClient(t)

		assert.Error(t, c.TransferAccountOwnership(s.ctx, s.exampleAccount.ID, nil))
	})

	s.Run("with invalid input", func() {
		t := s.T()

		c, _ := buildSimpleTestClient(t)
		exampleInput := &types.AccountOwnershipTransferInput{}

		assert.Error(t, c.TransferAccountOwnership(s.ctx, s.exampleAccount.ID, exampleInput))
	})

	s.Run("with error building request", func() {
		t := s.T()

		c := buildTestClientWithInvalidURL(t)
		exampleInput := fakes.BuildFakeTransferAccountOwnershipInput()

		assert.Error(t, c.TransferAccountOwnership(s.ctx, s.exampleAccount.ID, exampleInput))
	})

	s.Run("with error executing request", func() {
		t := s.T()

		c, _ := buildTestClientThatWaitsTooLong(t)
		exampleInput := fakes.BuildFakeTransferAccountOwnershipInput()

		assert.Error(t, c.TransferAccountOwnership(s.ctx, s.exampleAccount.ID, exampleInput))
	})
}
