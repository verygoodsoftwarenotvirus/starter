package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/internal/identifiers"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestQuerier_Integration_AccountUserMemberships(t *testing.T) {
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

	exampleUser := createUserForTest(t, ctx, nil, dbc)
	accounts, err := dbc.GetAccounts(ctx, exampleUser.ID, nil)
	assert.NoError(t, err)
	assert.Len(t, accounts.Data, 1)

	account := fakes.BuildFakeAccount()
	account.BelongsToUser = exampleUser.ID
	exampleAccount := createAccountForTest(t, ctx, account, dbc)

	memberUserIDs := []string{exampleUser.ID}

	for i := 0; i < exampleQuantity; i++ {
		newMember := createUserForTest(t, ctx, nil, dbc)
		assert.NoError(t, dbc.addUserToAccount(ctx, dbc.db, &types.AccountUserMembershipDatabaseCreationInput{
			ID:          identifiers.New(),
			Reason:      "testing",
			UserID:      newMember.ID,
			AccountID:   exampleAccount.ID,
			AccountRole: "account_member",
		}))
		memberUserIDs = append(memberUserIDs, newMember.ID)
	}

	account, err = dbc.GetAccount(ctx, exampleAccount.ID)
	assert.NoError(t, err)

	accountMemberUserIDs := []string{}
	for _, member := range account.Members {
		accountMemberUserIDs = append(accountMemberUserIDs, member.BelongsToUser.ID)
	}

	assert.Subset(t, memberUserIDs, accountMemberUserIDs)

	isMember, err := dbc.UserIsMemberOfAccount(ctx, memberUserIDs[0], exampleAccount.ID)
	assert.NoError(t, err)
	assert.True(t, isMember)

	assert.NoError(t, dbc.MarkAccountAsUserDefault(ctx, memberUserIDs[1], exampleAccount.ID))
	defaultAccountID, err := dbc.GetDefaultAccountIDForUser(ctx, memberUserIDs[1])
	assert.NoError(t, err)
	assert.Equal(t, exampleAccount.ID, defaultAccountID)

	sessionCtxData, err := dbc.BuildSessionContextDataForUser(ctx, memberUserIDs[1])
	assert.NoError(t, err)
	assert.NotNil(t, sessionCtxData)
	assert.Equal(t, exampleAccount.ID, sessionCtxData.ActiveAccountID)

	assert.NoError(t, dbc.RemoveUserFromAccount(ctx, memberUserIDs[len(memberUserIDs)-1], exampleAccount.ID))

	assert.NoError(t, dbc.TransferAccountOwnership(ctx, exampleAccount.ID, &types.AccountOwnershipTransferInput{
		Reason:       "testing",
		CurrentOwner: exampleUser.ID,
		NewOwner:     memberUserIDs[1],
	}))

	assert.NoError(t, dbc.ModifyUserPermissions(ctx, exampleAccount.ID, memberUserIDs[0], &types.ModifyUserPermissionsInput{
		Reason:  "testing",
		NewRole: "account_admin",
	}))
}

func TestQuerier_BuildSessionContextDataForUser(T *testing.T) {
	T.Parallel()

	T.Run("with invalid user ID", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		c, _ := buildTestClient(t)

		actual, err := c.BuildSessionContextDataForUser(ctx, "")
		assert.Error(t, err)
		assert.Nil(t, actual)
	})
}

func TestQuerier_GetDefaultAccountIDForUser(T *testing.T) {
	T.Parallel()

	T.Run("with invalid user ID", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		c, _ := buildTestClient(t)

		actual, err := c.GetDefaultAccountIDForUser(ctx, "")
		assert.Error(t, err)
		assert.Zero(t, actual)
	})
}

func TestQuerier_MarkAccountAsUserDefault(T *testing.T) {
	T.Parallel()

	T.Run("with invalid user ID", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		exampleAccount := fakes.BuildFakeAccount()

		c, _ := buildTestClient(t)

		assert.Error(t, c.MarkAccountAsUserDefault(ctx, "", exampleAccount.ID))
	})

	T.Run("with invalid account ID", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		exampleUser := fakes.BuildFakeUser()

		c, _ := buildTestClient(t)

		assert.Error(t, c.MarkAccountAsUserDefault(ctx, exampleUser.ID, ""))
	})
}

func TestQuerier_UserIsMemberOfAccount(T *testing.T) {
	T.Parallel()

	T.Run("with invalid user ID", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		exampleAccountID := fakes.BuildFakeID()

		c, _ := buildTestClient(t)

		actual, err := c.UserIsMemberOfAccount(ctx, "", exampleAccountID)
		assert.False(t, actual)
		assert.Error(t, err)
	})

	T.Run("with invalid account ID", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		exampleUserID := fakes.BuildFakeID()

		c, _ := buildTestClient(t)

		actual, err := c.UserIsMemberOfAccount(ctx, exampleUserID, "")
		assert.False(t, actual)
		assert.Error(t, err)
	})
}

func TestQuerier_ModifyUserPermissions(T *testing.T) {
	T.Parallel()

	T.Run("with invalid account id", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		exampleUserID := fakes.BuildFakeID()
		exampleInput := fakes.BuildFakeUserPermissionModificationInput()

		c, _ := buildTestClient(t)

		assert.Error(t, c.ModifyUserPermissions(ctx, "", exampleUserID, exampleInput))
	})

	T.Run("with nil input", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		exampleUserID := fakes.BuildFakeID()
		exampleAccountID := fakes.BuildFakeID()

		c, _ := buildTestClient(t)

		assert.Error(t, c.ModifyUserPermissions(ctx, exampleAccountID, exampleUserID, nil))
	})
}

func TestSQLQuerier_addUserToAccount(T *testing.T) {
	T.Parallel()

	T.Run("with invalid input", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()

		c, db := buildTestClient(t)

		err := c.addUserToAccount(ctx, c.db, nil)
		assert.Error(t, err)

		mock.AssertExpectationsForObjects(t, db)
	})
}

func TestQuerier_RemoveUserFromAccount(T *testing.T) {
	T.Parallel()

	T.Run("with invalid user ID", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		exampleAccount := fakes.BuildFakeAccount()

		c, _ := buildTestClient(t)

		assert.Error(t, c.RemoveUserFromAccount(ctx, "", exampleAccount.ID))
	})

	T.Run("with invalid account ID", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		exampleUser := fakes.BuildFakeUser()

		c, _ := buildTestClient(t)

		assert.Error(t, c.RemoveUserFromAccount(ctx, exampleUser.ID, ""))
	})

	T.Run("with error creating transaction", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		exampleUserID := fakes.BuildFakeID()
		exampleAccountID := fakes.BuildFakeID()

		c, db := buildTestClient(t)

		db.ExpectBegin().WillReturnError(errors.New("blah"))

		assert.Error(t, c.RemoveUserFromAccount(ctx, exampleUserID, exampleAccountID))
	})
}
