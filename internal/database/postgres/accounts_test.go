package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/converters"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createAccountForTest(t *testing.T, ctx context.Context, exampleAccount *types.Account, dbc *Querier) *types.Account {
	t.Helper()

	// create
	if exampleAccount == nil {
		exampleUser := createUserForTest(t, ctx, nil, dbc)
		exampleAccount = fakes.BuildFakeAccount()
		exampleAccount.BelongsToUser = exampleUser.ID
	}
	exampleAccount.PaymentProcessorCustomerID = ""
	exampleAccount.Members = nil
	dbInput := converters.ConvertAccountToAccountDatabaseCreationInput(exampleAccount)

	created, err := dbc.CreateAccount(ctx, dbInput)
	assert.NoError(t, err)
	require.NotNil(t, created)
	exampleAccount.CreatedAt = created.CreatedAt
	exampleAccount.WebhookEncryptionKey = created.WebhookEncryptionKey
	assert.Equal(t, exampleAccount, created)

	account, err := dbc.GetAccount(ctx, created.ID)
	require.NoError(t, err)
	require.NotNil(t, account)

	exampleAccount.CreatedAt = account.CreatedAt
	exampleAccount.Members = account.Members
	exampleAccount.WebhookEncryptionKey = account.WebhookEncryptionKey

	assert.Equal(t, exampleAccount, account)

	return created
}

func TestQuerier_Integration_Accounts(t *testing.T) {
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

	exampleAccount := fakes.BuildFakeAccount()
	exampleAccount.Members = nil
	exampleAccount.BelongsToUser = exampleUser.ID
	exampleAccount.PaymentProcessorCustomerID = ""
	createdAccounts := []*types.Account{}

	// create
	createdAccounts = append(createdAccounts, createAccountForTest(t, ctx, exampleAccount, dbc))

	// update
	updatedAccount := fakes.BuildFakeAccount()
	updatedAccount.ID = createdAccounts[0].ID
	updatedAccount.BelongsToUser = createdAccounts[0].BelongsToUser
	assert.NoError(t, dbc.UpdateAccount(ctx, updatedAccount))

	// create more
	for i := 0; i < exampleQuantity; i++ {
		input := fakes.BuildFakeAccount()
		input.BelongsToUser = exampleUser.ID
		input.Name = fmt.Sprintf("%s %d", updatedAccount.Name, i)
		createdAccounts = append(createdAccounts, createAccountForTest(t, ctx, input, dbc))
	}

	// fetch as list
	accounts, err := dbc.GetAccounts(ctx, exampleUser.ID, nil)
	assert.NoError(t, err)
	assert.NotEmpty(t, accounts.Data)
	assert.GreaterOrEqual(t, len(accounts.Data), len(createdAccounts))

	// delete
	for _, account := range createdAccounts {
		assert.NoError(t, dbc.ArchiveAccount(ctx, account.ID, exampleUser.ID))

		var y *types.Account
		y, err = dbc.GetAccount(ctx, account.ID)
		assert.Nil(t, y)
		assert.Error(t, err)
		assert.ErrorIs(t, err, sql.ErrNoRows)
	}

	assert.NoError(t, dbc.ArchiveUser(ctx, exampleUser.ID))
}

func TestQuerier_GetAccount(T *testing.T) {
	T.Parallel()

	T.Run("with invalid account ID", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()

		exampleUserID := fakes.BuildFakeID()
		exampleAccount := fakes.BuildFakeAccount()
		exampleAccount.BelongsToUser = exampleUserID

		c, _ := buildTestClient(t)

		actual, err := c.GetAccount(ctx, "")
		assert.Error(t, err)
		assert.Nil(t, actual)
	})

	T.Run("with invalid user ID", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()

		exampleUserID := fakes.BuildFakeID()
		exampleAccount := fakes.BuildFakeAccount()
		exampleAccount.BelongsToUser = exampleUserID

		c, _ := buildTestClient(t)

		actual, err := c.GetAccount(ctx, exampleAccount.ID)
		assert.Error(t, err)
		assert.Nil(t, actual)
	})
}

func TestQuerier_GetAccounts(T *testing.T) {
	T.Parallel()

	T.Run("with invalid user ID", func(t *testing.T) {
		t.Parallel()

		filter := types.DefaultQueryFilter()

		ctx := context.Background()
		c, _ := buildTestClient(t)

		actual, err := c.GetAccounts(ctx, "", filter)
		assert.Error(t, err)
		assert.Nil(t, actual)
	})
}

func TestQuerier_CreateAccount(T *testing.T) {
	T.Parallel()

	T.Run("with invalid input", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		c, _ := buildTestClient(t)

		actual, err := c.CreateAccount(ctx, nil)
		assert.Error(t, err)
		assert.Nil(t, actual)
	})
}

func TestQuerier_UpdateAccount(T *testing.T) {
	T.Parallel()

	T.Run("with invalid input", func(t *testing.T) {
		t.Parallel()

		exampleUserID := fakes.BuildFakeID()
		exampleAccount := fakes.BuildFakeAccount()
		exampleAccount.BelongsToUser = exampleUserID

		ctx := context.Background()
		c, _ := buildTestClient(t)

		assert.Error(t, c.UpdateAccount(ctx, nil))
	})
}

func TestQuerier_ArchiveAccount(T *testing.T) {
	T.Parallel()

	T.Run("with invalid account ID", func(t *testing.T) {
		t.Parallel()

		exampleUserID := fakes.BuildFakeID()

		ctx := context.Background()
		c, _ := buildTestClient(t)

		assert.Error(t, c.ArchiveAccount(ctx, "", exampleUserID))
	})

	T.Run("with invalid user ID", func(t *testing.T) {
		t.Parallel()

		exampleAccountID := fakes.BuildFakeID()

		ctx := context.Background()
		c, _ := buildTestClient(t)

		assert.Error(t, c.ArchiveAccount(ctx, exampleAccountID, ""))
	})
}
