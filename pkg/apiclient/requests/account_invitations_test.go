package requests

import (
	"net/http"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"

	"github.com/stretchr/testify/assert"
)

func TestBuilder_BuildGetAccountInvitationRequest(T *testing.T) {
	T.Parallel()

	expectedPathFormat := "/api/v1/accounts/%s/invitations/%s"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		exampleAccountInvitation := fakes.BuildFakeAccountInvitation()

		spec := newRequestSpec(false, http.MethodGet, "", expectedPathFormat, exampleAccountInvitation.DestinationAccount.ID, exampleAccountInvitation.ID)

		actual, err := helper.builder.BuildGetAccountInvitationRequest(helper.ctx, exampleAccountInvitation.DestinationAccount.ID, exampleAccountInvitation.ID)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with invalid account ID", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		exampleAccountInvitation := fakes.BuildFakeAccountInvitation()

		actual, err := helper.builder.BuildGetAccountInvitationRequest(helper.ctx, "", exampleAccountInvitation.ID)
		assert.Error(t, err)
		assert.Nil(t, actual)
	})

	T.Run("with invalid invitation ID", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		exampleAccountInvitation := fakes.BuildFakeAccountInvitation()

		actual, err := helper.builder.BuildGetAccountInvitationRequest(helper.ctx, exampleAccountInvitation.DestinationAccount.ID, "")
		assert.Error(t, err)
		assert.Nil(t, actual)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()
		exampleAccountInvitation := fakes.BuildFakeAccountInvitation()

		actual, err := helper.builder.BuildGetAccountInvitationRequest(helper.ctx, exampleAccountInvitation.DestinationAccount.ID, exampleAccountInvitation.ID)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func TestBuilder_BuildGetPendingAccountInvitationsFromUserRequest(T *testing.T) {
	T.Parallel()

	expectedPathFormat := "/api/v1/account_invitations/sent"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		filter := types.DefaultQueryFilter()

		spec := newRequestSpec(false, http.MethodGet, "limit=50&page=1&sortBy=asc", expectedPathFormat)

		actual, err := helper.builder.BuildGetPendingAccountInvitationsFromUserRequest(helper.ctx, filter)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()
		filter := types.DefaultQueryFilter()

		actual, err := helper.builder.BuildGetPendingAccountInvitationsFromUserRequest(helper.ctx, filter)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func TestBuilder_BuildGetPendingAccountInvitationsForUserRequest(T *testing.T) {
	T.Parallel()

	expectedPathFormat := "/api/v1/account_invitations/received"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		filter := types.DefaultQueryFilter()

		spec := newRequestSpec(false, http.MethodGet, "limit=50&page=1&sortBy=asc", expectedPathFormat)

		actual, err := helper.builder.BuildGetPendingAccountInvitationsForUserRequest(helper.ctx, filter)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()
		filter := types.DefaultQueryFilter()

		actual, err := helper.builder.BuildGetPendingAccountInvitationsForUserRequest(helper.ctx, filter)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func TestBuilder_BuildAcceptAccountInvitationRequest(T *testing.T) {
	T.Parallel()

	expectedPathFormat := "/api/v1/account_invitations/%s/accept"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		exampleAccountInvitation := fakes.BuildFakeAccountInvitation()

		spec := newRequestSpec(false, http.MethodPut, "", expectedPathFormat, exampleAccountInvitation.ID)

		actual, err := helper.builder.BuildAcceptAccountInvitationRequest(helper.ctx, exampleAccountInvitation.ID, exampleAccountInvitation.Token, t.Name())
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()
		exampleAccountInvitation := fakes.BuildFakeAccountInvitation()

		actual, err := helper.builder.BuildAcceptAccountInvitationRequest(helper.ctx, exampleAccountInvitation.ID, exampleAccountInvitation.Token, t.Name())
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func TestBuilder_BuildCancelAccountInvitationRequest(T *testing.T) {
	T.Parallel()

	expectedPathFormat := "/api/v1/account_invitations/%s/cancel"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		exampleAccountInvitation := fakes.BuildFakeAccountInvitation()

		spec := newRequestSpec(false, http.MethodPut, "", expectedPathFormat, exampleAccountInvitation.ID)

		actual, err := helper.builder.BuildCancelAccountInvitationRequest(helper.ctx, exampleAccountInvitation.ID, exampleAccountInvitation.Token, t.Name())
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()
		exampleAccountInvitation := fakes.BuildFakeAccountInvitation()

		actual, err := helper.builder.BuildCancelAccountInvitationRequest(helper.ctx, exampleAccountInvitation.ID, exampleAccountInvitation.Token, t.Name())
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func TestBuilder_BuildRejectAccountInvitationRequest(T *testing.T) {
	T.Parallel()

	expectedPathFormat := "/api/v1/account_invitations/%s/reject"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		exampleAccountInvitation := fakes.BuildFakeAccountInvitation()

		spec := newRequestSpec(false, http.MethodPut, "", expectedPathFormat, exampleAccountInvitation.ID)

		actual, err := helper.builder.BuildRejectAccountInvitationRequest(helper.ctx, exampleAccountInvitation.ID, exampleAccountInvitation.Token, t.Name())
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()
		exampleAccountInvitation := fakes.BuildFakeAccountInvitation()

		actual, err := helper.builder.BuildRejectAccountInvitationRequest(helper.ctx, exampleAccountInvitation.ID, exampleAccountInvitation.Token, t.Name())
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}
