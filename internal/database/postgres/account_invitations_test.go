package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/converters"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func createAccountInvitationForTest(t *testing.T, ctx context.Context, exampleAccountInvitation *types.AccountInvitation, dbc *Querier) *types.AccountInvitation {
	t.Helper()

	// create
	if exampleAccountInvitation == nil {
		fromUser := createUserForTest(t, ctx, nil, dbc)
		toUser := createUserForTest(t, ctx, nil, dbc)
		account := createAccountForTest(t, ctx, nil, dbc)
		exampleAccountInvitation = fakes.BuildFakeAccountInvitation()
		exampleAccountInvitation.ExpiresAt = time.Now().Add(time.Hour * 24 * 7)
		exampleAccountInvitation.DestinationAccount = *account
		exampleAccountInvitation.FromUser = *fromUser
		exampleAccountInvitation.ToUser = &toUser.ID
	}
	dbInput := converters.ConvertAccountInvitationToAccountInvitationDatabaseCreationInput(exampleAccountInvitation)

	created, err := dbc.CreateAccountInvitation(ctx, dbInput)
	assert.NoError(t, err)
	require.NotNil(t, created)
	exampleAccountInvitation.CreatedAt = created.CreatedAt
	exampleAccountInvitation.StatusNote = created.StatusNote
	exampleAccountInvitation.FromUser = created.FromUser
	assert.Equal(t, exampleAccountInvitation.DestinationAccount.ID, created.DestinationAccount.ID)
	exampleAccountInvitation.DestinationAccount = created.DestinationAccount
	assert.Equal(t, exampleAccountInvitation, created)

	accountInvitation, err := dbc.GetAccountInvitationByAccountAndID(ctx, created.DestinationAccount.ID, created.ID)
	assert.NoError(t, err)
	require.NotNil(t, accountInvitation)
	exampleAccountInvitation.CreatedAt = accountInvitation.CreatedAt
	exampleAccountInvitation.ExpiresAt = accountInvitation.ExpiresAt
	assert.Equal(t, exampleAccountInvitation.FromUser.ID, accountInvitation.FromUser.ID)
	exampleAccountInvitation.FromUser = accountInvitation.FromUser
	assert.Equal(t, exampleAccountInvitation.DestinationAccount.ID, accountInvitation.DestinationAccount.ID)
	exampleAccountInvitation.DestinationAccount = accountInvitation.DestinationAccount

	assert.Equal(t, accountInvitation, exampleAccountInvitation)

	return created
}

func TestQuerier_Integration_AccountInvitations(t *testing.T) {
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

	account := createAccountForTest(t, ctx, nil, dbc)

	fromUser := createUserForTest(t, ctx, nil, dbc)
	toUserA := createUserForTest(t, ctx, nil, dbc)
	toUserB := createUserForTest(t, ctx, nil, dbc)
	toUserC := createUserForTest(t, ctx, nil, dbc)

	toBeCancelledInput := fakes.BuildFakeAccountInvitation()
	toBeCancelledInput.DestinationAccount = *account
	toBeCancelledInput.ExpiresAt = time.Now().Add(time.Hour * 24 * 7)
	toBeCancelledInput.FromUser = *fromUser
	toBeCancelledInput.ToUser = &toUserA.ID
	toBeCancelled := createAccountInvitationForTest(t, ctx, toBeCancelledInput, dbc)

	toBeRejectedInput := fakes.BuildFakeAccountInvitation()
	toBeRejectedInput.DestinationAccount = *account
	toBeRejectedInput.ExpiresAt = time.Now().Add(time.Hour * 24 * 7)
	toBeRejectedInput.FromUser = *fromUser
	toBeRejectedInput.ToUser = &toUserB.ID
	toBeRejected := createAccountInvitationForTest(t, ctx, toBeRejectedInput, dbc)

	toBeAcceptedInput := fakes.BuildFakeAccountInvitation()
	toBeAcceptedInput.DestinationAccount = *account
	toBeAcceptedInput.ExpiresAt = time.Now().Add(time.Hour * 24 * 7)
	toBeAcceptedInput.FromUser = *fromUser
	toBeAcceptedInput.ToUser = &toUserC.ID
	toBeAcceptedInput.ToEmail = toUserC.EmailAddress
	toBeAccepted := createAccountInvitationForTest(t, ctx, toBeAcceptedInput, dbc)

	outboundInvites, err := dbc.GetPendingAccountInvitationsFromUser(ctx, fromUser.ID, nil)
	assert.NoError(t, err)
	assert.Len(t, outboundInvites.Data, 3)

	inboundInvites, err := dbc.GetPendingAccountInvitationsForUser(ctx, toUserC.ID, nil)
	assert.NoError(t, err)
	assert.Len(t, inboundInvites.Data, 1)

	exists, err := dbc.AccountInvitationExists(ctx, toBeCancelled.ID)
	assert.NoError(t, err)
	assert.True(t, exists)

	invite, err := dbc.GetAccountInvitationByEmailAndToken(ctx, toUserC.EmailAddress, toBeAccepted.Token)
	assert.NoError(t, err)
	assert.NotNil(t, invite)

	// create invite for nonexistent user
	forNewUserInput := fakes.BuildFakeAccountInvitation()
	forNewUserInput.DestinationAccount = *account
	forNewUserInput.ExpiresAt = time.Now().Add(time.Hour * 24 * 7)
	forNewUserInput.FromUser = *fromUser
	forNewUserInput.ToUser = nil
	forNewUserInput.ToEmail = fakes.BuildFakeUser().EmailAddress
	forNewUser := createAccountInvitationForTest(t, ctx, forNewUserInput, dbc)

	fakeUser := fakes.BuildFakeUser()
	fakeUser.EmailAddress = forNewUserInput.ToEmail
	dbInput := converters.ConvertUserToUserDatabaseCreationInput(fakeUser)
	dbInput.InvitationToken = forNewUser.Token
	dbInput.DestinationAccountID = account.ID

	createdUser, err := dbc.CreateUser(ctx, dbInput)
	assert.NoError(t, err)
	assert.NotNil(t, createdUser)

	assert.NoError(t, dbc.CancelAccountInvitation(ctx, toBeCancelled.ID, "testing"))
	assert.NoError(t, dbc.RejectAccountInvitation(ctx, toBeRejected.ID, "testing"))
	assert.NoError(t, dbc.AcceptAccountInvitation(ctx, toBeAccepted.ID, toBeAccepted.Token, "testing"))
}

func TestQuerier_AccountInvitationExists(T *testing.T) {
	T.Parallel()

	T.Run("with invalid account invitation ID", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		c, db := buildTestClient(t)

		actual, err := c.AccountInvitationExists(ctx, "")
		assert.Error(t, err)
		assert.False(t, actual)

		mock.AssertExpectationsForObjects(t, db)
	})
}

func TestQuerier_GetAccountInvitationByTokenAndID(T *testing.T) {
	T.Parallel()

	T.Run("with invalid account ID", func(t *testing.T) {
		t.Parallel()

		exampleAccountID := fakes.BuildFakeID()

		ctx := context.Background()
		c, _ := buildTestClient(t)

		actual, err := c.GetAccountInvitationByTokenAndID(ctx, "", exampleAccountID)
		assert.Error(t, err)
		assert.Nil(t, actual)
	})

	T.Run("with invalid account invitation ID", func(t *testing.T) {
		t.Parallel()

		exampleAccountID := fakes.BuildFakeID()

		ctx := context.Background()
		c, _ := buildTestClient(t)

		actual, err := c.GetAccountInvitationByTokenAndID(ctx, exampleAccountID, "")
		assert.Error(t, err)
		assert.Nil(t, actual)
	})
}

func TestQuerier_GetAccountInvitationByAccountAndID(T *testing.T) {
	T.Parallel()

	T.Run("with invalid account ID", func(t *testing.T) {
		t.Parallel()

		exampleAccountID := fakes.BuildFakeID()

		ctx := context.Background()
		c, _ := buildTestClient(t)

		actual, err := c.GetAccountInvitationByAccountAndID(ctx, "", exampleAccountID)
		assert.Error(t, err)
		assert.Nil(t, actual)
	})

	T.Run("with invalid account invitation ID", func(t *testing.T) {
		t.Parallel()

		exampleAccountID := fakes.BuildFakeID()

		ctx := context.Background()
		c, _ := buildTestClient(t)

		actual, err := c.GetAccountInvitationByAccountAndID(ctx, exampleAccountID, "")
		assert.Error(t, err)
		assert.Nil(t, actual)
	})
}

func TestQuerier_GetAccountInvitationByEmailAndToken(T *testing.T) {
	T.Parallel()

	T.Run("with invalid account ID", func(t *testing.T) {
		t.Parallel()

		exampleAccountID := fakes.BuildFakeID()

		ctx := context.Background()
		c, _ := buildTestClient(t)

		actual, err := c.GetAccountInvitationByEmailAndToken(ctx, "", exampleAccountID)
		assert.Error(t, err)
		assert.Nil(t, actual)
	})

	T.Run("with invalid account invitation ID", func(t *testing.T) {
		t.Parallel()

		exampleAccountID := fakes.BuildFakeID()

		ctx := context.Background()
		c, _ := buildTestClient(t)

		actual, err := c.GetAccountInvitationByEmailAndToken(ctx, exampleAccountID, "")
		assert.Error(t, err)
		assert.Nil(t, actual)
	})
}

func TestQuerier_CreateAccountInvitation(T *testing.T) {
	T.Parallel()

	T.Run("with invalid input", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		c, _ := buildTestClient(t)

		actual, err := c.CreateAccountInvitation(ctx, nil)
		assert.Error(t, err)
		assert.Nil(t, actual)
	})
}

func TestSQLQuerier_setInvitationStatus(T *testing.T) {
	T.Parallel()

	T.Run("with invalid account invitation ID", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		exampleAccountInvitation := fakes.BuildFakeAccountInvitation()

		c, _ := buildTestClient(t)

		err := c.setInvitationStatus(ctx, c.db, "", exampleAccountInvitation.Note, exampleAccountInvitation.Status)
		assert.Error(t, err)
	})
}

func TestSQLQuerier_AcceptAccountInvitation(T *testing.T) {
	T.Parallel()

	T.Run("with invalid invitation ID", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		exampleToken := fakes.BuildFakeID()

		c, db := buildTestClient(t)

		err := c.AcceptAccountInvitation(ctx, "", exampleToken, t.Name())
		assert.Error(t, err)

		mock.AssertExpectationsForObjects(t, db)
	})

	T.Run("with invalid token", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		exampleAccountInvitation := fakes.BuildFakeAccountInvitation()

		c, db := buildTestClient(t)

		err := c.AcceptAccountInvitation(ctx, exampleAccountInvitation.ID, "", exampleAccountInvitation.Note)
		assert.Error(t, err)

		mock.AssertExpectationsForObjects(t, db)
	})
}

func TestSQLQuerier_attachInvitationsToUser(T *testing.T) {
	T.Parallel()

	T.Run("with invalid email address", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		exampleUser := fakes.BuildFakeUser()

		c, db := buildTestClient(t)

		err := c.attachInvitationsToUser(ctx, c.db, "", exampleUser.ID)
		assert.Error(t, err)

		mock.AssertExpectationsForObjects(t, db)
	})

	T.Run("with invalid user ID", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		exampleUser := fakes.BuildFakeUser()

		c, db := buildTestClient(t)

		err := c.attachInvitationsToUser(ctx, c.db, exampleUser.EmailAddress, "")
		assert.Error(t, err)

		mock.AssertExpectationsForObjects(t, db)
	})
}
