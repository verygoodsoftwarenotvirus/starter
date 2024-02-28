package postgres

import (
	"context"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQuerier_Integration_Admin(t *testing.T) {
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

	createdUser := createUserForTest(t, ctx, nil, dbc)

	input := fakes.BuildFakeUserAccountStatusUpdateInput()
	input.TargetUserID = createdUser.ID

	assert.NoError(t, dbc.UpdateUserAccountStatus(ctx, createdUser.ID, input))

	assert.NoError(t, dbc.ArchiveUser(ctx, createdUser.ID))
}
