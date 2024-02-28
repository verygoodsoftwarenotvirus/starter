package postgres

import (
	"context"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/converters"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func createOAuth2ClientTokenForTest(t *testing.T, ctx context.Context, exampleOAuth2ClientToken *types.OAuth2ClientToken, dbc *Querier) *types.OAuth2ClientToken {
	t.Helper()

	// create
	if exampleOAuth2ClientToken == nil {
		user := createUserForTest(t, ctx, nil, dbc)
		oauth2Client := createOAuth2ClientForTest(t, ctx, nil, dbc)
		exampleOAuth2ClientToken = fakes.BuildFakeOAuth2ClientToken()
		exampleOAuth2ClientToken.BelongsToUser = user.ID
		exampleOAuth2ClientToken.ClientID = oauth2Client.ID
	}
	dbInput := converters.ConvertOAuth2ClientTokenToOAuth2ClientTokenDatabaseCreationInput(exampleOAuth2ClientToken)

	created, err := dbc.CreateOAuth2ClientToken(ctx, dbInput)
	assert.NoError(t, err)
	require.NotNil(t, created)

	exampleOAuth2ClientToken.CodeCreatedAt = created.CodeCreatedAt
	exampleOAuth2ClientToken.AccessCreatedAt = created.AccessCreatedAt
	exampleOAuth2ClientToken.RefreshCreatedAt = created.RefreshCreatedAt
	assert.Equal(t, exampleOAuth2ClientToken, created)

	oauth2ClientToken, err := dbc.GetOAuth2ClientTokenByAccess(ctx, created.Access)
	assert.NoError(t, err)
	exampleOAuth2ClientToken.CodeCreatedAt = oauth2ClientToken.CodeCreatedAt
	exampleOAuth2ClientToken.AccessCreatedAt = oauth2ClientToken.AccessCreatedAt
	exampleOAuth2ClientToken.RefreshCreatedAt = oauth2ClientToken.RefreshCreatedAt
	assert.Equal(t, oauth2ClientToken, exampleOAuth2ClientToken)

	return created
}

func TestQuerier_Integration_OAuth2ClientTokens(t *testing.T) {
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

	user := createUserForTest(t, ctx, nil, dbc)
	oauth2Client := createOAuth2ClientForTest(t, ctx, nil, dbc)
	exampleOAuth2ClientToken := fakes.BuildFakeOAuth2ClientToken()
	exampleOAuth2ClientToken.BelongsToUser = user.ID
	exampleOAuth2ClientToken.ClientID = oauth2Client.ClientID
	exampleOAuth2ClientToken.Scope = "account_member"

	// create
	createdOAuth2ClientToken := createOAuth2ClientTokenForTest(t, ctx, exampleOAuth2ClientToken, dbc)

	// get
	byCode, err := dbc.GetOAuth2ClientTokenByCode(ctx, exampleOAuth2ClientToken.Code)
	assert.NoError(t, err)
	assert.NotNil(t, byCode)

	// delete
	assert.NoError(t, dbc.ArchiveOAuth2ClientTokenByCode(ctx, createdOAuth2ClientToken.Code))

	// create
	createdOAuth2ClientToken = createOAuth2ClientTokenForTest(t, ctx, exampleOAuth2ClientToken, dbc)

	// get
	byAccess, err := dbc.GetOAuth2ClientTokenByAccess(ctx, exampleOAuth2ClientToken.Access)
	assert.NoError(t, err)
	assert.NotNil(t, byAccess)

	// delete
	assert.NoError(t, dbc.ArchiveOAuth2ClientTokenByAccess(ctx, createdOAuth2ClientToken.Access))

	// create
	createdOAuth2ClientToken = createOAuth2ClientTokenForTest(t, ctx, exampleOAuth2ClientToken, dbc)

	// get
	byRefresh, err := dbc.GetOAuth2ClientTokenByRefresh(ctx, exampleOAuth2ClientToken.Refresh)
	assert.NoError(t, err)
	assert.NotNil(t, byRefresh)

	// delete
	assert.NoError(t, dbc.ArchiveOAuth2ClientTokenByRefresh(ctx, createdOAuth2ClientToken.Refresh))
}

func TestQuerier_ArchiveOAuth2ClientTokenByAccess(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		c, db := buildTestClient(t)

		assert.Error(t, c.ArchiveOAuth2ClientTokenByAccess(ctx, ""))

		mock.AssertExpectationsForObjects(t, db)
	})
}

func TestQuerier_ArchiveOAuth2ClientTokenByCode(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		c, db := buildTestClient(t)

		assert.Error(t, c.ArchiveOAuth2ClientTokenByCode(ctx, ""))

		mock.AssertExpectationsForObjects(t, db)
	})
}

func TestQuerier_ArchiveOAuth2ClientTokenByRefresh(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		c, db := buildTestClient(t)

		assert.Error(t, c.ArchiveOAuth2ClientTokenByRefresh(ctx, ""))

		mock.AssertExpectationsForObjects(t, db)
	})
}
