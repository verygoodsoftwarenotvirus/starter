package postgres

import (
	"context"
	"fmt"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/converters"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createUserNotificationForTest(t *testing.T, ctx context.Context, userID string, exampleUserNotification *types.UserNotification, dbc *Querier) *types.UserNotification {
	t.Helper()

	if userID == "" {
		user := createUserForTest(t, ctx, nil, dbc)
		userID = user.ID
	}

	// create
	if exampleUserNotification == nil {
		exampleUserNotification = fakes.BuildFakeUserNotification()
	}
	exampleUserNotification.BelongsToUser = userID
	dbInput := converters.ConvertUserNotificationToUserNotificationDatabaseCreationInput(exampleUserNotification)

	created, err := dbc.CreateUserNotification(ctx, dbInput)
	require.NoError(t, err)
	exampleUserNotification.CreatedAt = created.CreatedAt
	assert.Equal(t, exampleUserNotification, created)

	userNotification, err := dbc.GetUserNotification(ctx, created.BelongsToUser, created.ID)
	exampleUserNotification.CreatedAt = userNotification.CreatedAt

	assert.NoError(t, err)
	assert.Equal(t, userNotification, exampleUserNotification)

	return created
}

func TestQuerier_Integration_UserNotifications(t *testing.T) {
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

	exampleUserNotification := fakes.BuildFakeUserNotification()
	createdUserNotifications := []*types.UserNotification{}

	// create
	createdUserNotifications = append(createdUserNotifications, createUserNotificationForTest(t, ctx, user.ID, exampleUserNotification, dbc))

	// update
	updatedUserNotification := fakes.BuildFakeUserNotification()
	updatedUserNotification.ID = createdUserNotifications[0].ID
	updatedUserNotification.BelongsToUser = user.ID
	assert.NoError(t, dbc.UpdateUserNotification(ctx, updatedUserNotification))
	createdUserNotifications[0] = updatedUserNotification

	// create more
	for i := 0; i < exampleQuantity; i++ {
		input := fakes.BuildFakeUserNotification()
		input.Content = fmt.Sprintf("%s %d", updatedUserNotification.Content, i)
		createdUserNotifications = append(createdUserNotifications, createUserNotificationForTest(t, ctx, user.ID, input, dbc))
	}

	// fetch as list
	userNotifications, err := dbc.GetUserNotifications(ctx, user.ID, nil)
	assert.NoError(t, err)
	assert.NotEmpty(t, userNotifications.Data)
	assert.Equal(t, len(createdUserNotifications), len(userNotifications.Data))

	// delete
	for _, userNotification := range createdUserNotifications {
		var exists bool
		exists, err = dbc.UserNotificationExists(ctx, user.ID, userNotification.ID)
		assert.NoError(t, err)
		assert.True(t, exists)
	}
}

func TestQuerier_UserNotificationExists(T *testing.T) {
	T.Parallel()

	T.Run("with invalid user ID", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()

		c, _ := buildTestClient(t)

		actual, err := c.UserNotificationExists(ctx, fakes.BuildFakeID(), "")
		assert.Error(t, err)
		assert.False(t, actual)
	})

	T.Run("with invalid user notification ID", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()

		c, _ := buildTestClient(t)

		actual, err := c.UserNotificationExists(ctx, "", fakes.BuildFakeID())
		assert.Error(t, err)
		assert.False(t, actual)
	})
}

func TestQuerier_GetUserNotification(T *testing.T) {
	T.Parallel()

	T.Run("with invalid user ID", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		c, _ := buildTestClient(t)

		actual, err := c.GetUserNotification(ctx, "", fakes.BuildFakeID())
		assert.Error(t, err)
		assert.Nil(t, actual)
	})

	T.Run("with invalid user notification ID", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		c, _ := buildTestClient(t)

		actual, err := c.GetUserNotification(ctx, fakes.BuildFakeID(), "")
		assert.Error(t, err)
		assert.Nil(t, actual)
	})
}

func TestQuerier_CreateUserNotification(T *testing.T) {
	T.Parallel()

	T.Run("with invalid input", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		c, _ := buildTestClient(t)

		actual, err := c.CreateUserNotification(ctx, nil)
		assert.Error(t, err)
		assert.Nil(t, actual)
	})
}

func TestQuerier_UpdateUserNotification(T *testing.T) {
	T.Parallel()

	T.Run("with nil input", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		c, _ := buildTestClient(t)

		assert.Error(t, c.UpdateUserNotification(ctx, nil))
	})
}
