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
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func createWebhookForTest(t *testing.T, ctx context.Context, exampleWebhook *types.Webhook, dbc *Querier) *types.Webhook {
	t.Helper()

	// create
	if exampleWebhook == nil {
		exampleWebhook = fakes.BuildFakeWebhook()
	}
	dbInput := converters.ConvertWebhookToWebhookDatabaseCreationInput(exampleWebhook)

	created, err := dbc.CreateWebhook(ctx, dbInput)
	assert.NoError(t, err)
	require.NotNil(t, created)

	exampleWebhook.CreatedAt = created.CreatedAt
	for i := range created.Events {
		exampleWebhook.Events[i].CreatedAt = created.Events[i].CreatedAt
	}
	assert.Equal(t, exampleWebhook, created)

	webhook, err := dbc.GetWebhook(ctx, created.ID, created.BelongsToAccount)
	exampleWebhook.CreatedAt = webhook.CreatedAt
	for i := range created.Events {
		exampleWebhook.Events[i].CreatedAt = webhook.Events[i].CreatedAt
	}

	assert.NoError(t, err)
	assert.Equal(t, webhook, exampleWebhook)

	return created
}

func TestQuerier_Integration_Webhooks(t *testing.T) {
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
	accountID, err := dbc.GetDefaultAccountIDForUser(ctx, user.ID)
	require.NoError(t, err)
	require.NotEmpty(t, accountID)

	exampleWebhook := fakes.BuildFakeWebhook()
	exampleWebhook.BelongsToAccount = accountID
	createdWebhooks := []*types.Webhook{}

	// create
	createdWebhooks = append(createdWebhooks, createWebhookForTest(t, ctx, exampleWebhook, dbc))

	// create more
	for i := 0; i < exampleQuantity; i++ {
		input := fakes.BuildFakeWebhook()
		input.Name = fmt.Sprintf("%s %d", exampleWebhook.Name, i)
		input.BelongsToAccount = accountID
		createdWebhooks = append(createdWebhooks, createWebhookForTest(t, ctx, input, dbc))
	}

	// fetch as list
	webhooks, err := dbc.GetWebhooks(ctx, accountID, nil)
	assert.NoError(t, err)
	assert.NotEmpty(t, webhooks.Data)
	assert.Equal(t, len(createdWebhooks), len(webhooks.Data))

	// fetch as list
	webhooksByAccountAndEvent, err := dbc.GetWebhooksForAccountAndEvent(ctx, accountID, types.ServiceEventType(createdWebhooks[0].Events[0].TriggerEvent))
	assert.NoError(t, err)
	assert.NotEmpty(t, webhooksByAccountAndEvent)

	// delete
	for _, webhook := range createdWebhooks {
		assert.NoError(t, dbc.ArchiveWebhook(ctx, webhook.ID, accountID))

		var exists bool
		exists, err = dbc.WebhookExists(ctx, webhook.ID, accountID)
		assert.NoError(t, err)
		assert.False(t, exists)

		var y *types.Webhook
		y, err = dbc.GetWebhook(ctx, webhook.ID, accountID)
		assert.Nil(t, y)
		assert.Error(t, err)
		assert.ErrorIs(t, err, sql.ErrNoRows)
	}
}

func TestQuerier_WebhookExists(T *testing.T) {
	T.Parallel()

	T.Run("with invalid webhook ID", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()

		exampleAccountID := fakes.BuildFakeID()

		c, _ := buildTestClient(t)

		actual, err := c.WebhookExists(ctx, "", exampleAccountID)
		assert.Error(t, err)
		assert.False(t, actual)
	})

	T.Run("with invalid account ID", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()

		exampleWebhookID := fakes.BuildFakeID()

		c, db := buildTestClient(t)

		actual, err := c.WebhookExists(ctx, exampleWebhookID, "")
		assert.Error(t, err)
		assert.False(t, actual)

		mock.AssertExpectationsForObjects(t, db)
	})
}

func TestQuerier_GetWebhook(T *testing.T) {
	T.Parallel()

	T.Run("with invalid webhook ID", func(t *testing.T) {
		t.Parallel()

		exampleAccountID := fakes.BuildFakeID()

		ctx := context.Background()
		c, _ := buildTestClient(t)

		actual, err := c.GetWebhook(ctx, "", exampleAccountID)
		assert.Error(t, err)
		assert.Nil(t, actual)
	})

	T.Run("with invalid account ID", func(t *testing.T) {
		t.Parallel()

		exampleWebhook := fakes.BuildFakeWebhook()

		ctx := context.Background()
		c, _ := buildTestClient(t)

		actual, err := c.GetWebhook(ctx, exampleWebhook.ID, "")
		assert.Error(t, err)
		assert.Nil(t, actual)
	})
}

func TestQuerier_GetWebhooks(T *testing.T) {
	T.Parallel()

	T.Run("with invalid account ID", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		filter := types.DefaultQueryFilter()
		c, _ := buildTestClient(t)

		actual, err := c.GetWebhooks(ctx, "", filter)
		assert.Error(t, err)
		assert.Nil(t, actual)
	})
}

func TestQuerier_CreateWebhook(T *testing.T) {
	T.Parallel()

	T.Run("with invalid input", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		c, _ := buildTestClient(t)

		actual, err := c.CreateWebhook(ctx, nil)
		assert.Error(t, err)
		assert.Nil(t, actual)
	})

	T.Run("with msising user ID", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		c, _ := buildTestClient(t)

		input := converters.ConvertWebhookToWebhookDatabaseCreationInput(fakes.BuildFakeWebhook())

		actual, err := c.CreateWebhook(ctx, input)
		assert.Error(t, err)
		assert.Nil(t, actual)
	})
}

func TestQuerier_createWebhookTriggerEvent(T *testing.T) {
	T.Parallel()

	T.Run("with invalid input", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		c, _ := buildTestClient(t)

		created, err := c.createWebhookTriggerEvent(ctx, c.db, fakes.BuildFakeID(), nil)
		assert.Error(t, err)
		assert.Nil(t, created)
	})

	T.Run("with missing account ID", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		c, _ := buildTestClient(t)
		fakes.BuildFakeWebhookTriggerEvent()

		input := converters.ConvertWebhookTriggerEventToWebhookTriggerEventDatabaseCreationInput(fakes.BuildFakeWebhookTriggerEvent())

		created, err := c.createWebhookTriggerEvent(ctx, c.db, "", input)
		assert.Error(t, err)
		assert.Nil(t, created)
	})
}

func TestQuerier_ArchiveWebhook(T *testing.T) {
	T.Parallel()

	T.Run("with invalid webhook ID", func(t *testing.T) {
		t.Parallel()

		exampleAccountID := fakes.BuildFakeID()

		ctx := context.Background()
		c, _ := buildTestClient(t)

		assert.Error(t, c.ArchiveWebhook(ctx, "", exampleAccountID))
	})

	T.Run("with invalid account ID", func(t *testing.T) {
		t.Parallel()

		exampleWebhookID := fakes.BuildFakeID()

		ctx := context.Background()
		c, _ := buildTestClient(t)

		assert.Error(t, c.ArchiveWebhook(ctx, exampleWebhookID, ""))
	})
}
