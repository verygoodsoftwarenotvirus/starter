package requests

import (
	"net/http"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"

	"github.com/stretchr/testify/assert"
)

func TestBuilder_BuildGetWebhookRequest(T *testing.T) {
	T.Parallel()

	const expectedPathFormat = "/api/v1/webhooks/%s"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		exampleWebhook := fakes.BuildFakeWebhook()

		spec := newRequestSpec(false, http.MethodGet, "", expectedPathFormat, exampleWebhook.ID)

		actual, err := helper.builder.BuildGetWebhookRequest(helper.ctx, exampleWebhook.ID)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with invalid webhook ID", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		actual, err := helper.builder.BuildGetWebhookRequest(helper.ctx, "")
		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()
		exampleWebhook := fakes.BuildFakeWebhook()

		actual, err := helper.builder.BuildGetWebhookRequest(helper.ctx, exampleWebhook.ID)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func TestBuilder_BuildGetWebhooksRequest(T *testing.T) {
	T.Parallel()

	const expectedPath = "/api/v1/webhooks"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		spec := newRequestSpec(false, http.MethodGet, "limit=50&page=1&sortBy=asc", expectedPath)

		actual, err := helper.builder.BuildGetWebhooksRequest(helper.ctx, nil)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()

		actual, err := helper.builder.BuildGetWebhooksRequest(helper.ctx, nil)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func TestBuilder_BuildCreateWebhookRequest(T *testing.T) {
	T.Parallel()

	const expectedPath = "/api/v1/webhooks"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		exampleInput := fakes.BuildFakeWebhookCreationRequestInput()

		spec := newRequestSpec(false, http.MethodPost, "", expectedPath)

		actual, err := helper.builder.BuildCreateWebhookRequest(helper.ctx, exampleInput)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with nil input", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		actual, err := helper.builder.BuildCreateWebhookRequest(helper.ctx, nil)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	T.Run("with invalid input", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()
		exampleInput := &types.WebhookCreationRequestInput{}

		actual, err := helper.builder.BuildCreateWebhookRequest(helper.ctx, exampleInput)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()
		exampleInput := fakes.BuildFakeWebhookCreationRequestInput()

		actual, err := helper.builder.BuildCreateWebhookRequest(helper.ctx, exampleInput)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func TestBuilder_BuildArchiveWebhookRequest(T *testing.T) {
	T.Parallel()

	const expectedPathFormat = "/api/v1/webhooks/%s"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		exampleWebhook := fakes.BuildFakeWebhook()

		spec := newRequestSpec(false, http.MethodDelete, "", expectedPathFormat, exampleWebhook.ID)

		actual, err := helper.builder.BuildArchiveWebhookRequest(helper.ctx, exampleWebhook.ID)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with invalid webhook ID", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		actual, err := helper.builder.BuildArchiveWebhookRequest(helper.ctx, "")
		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()
		exampleWebhook := fakes.BuildFakeWebhook()

		actual, err := helper.builder.BuildArchiveWebhookRequest(helper.ctx, exampleWebhook.ID)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func TestBuilder_BuildArchiveWebhookTriggerEventRequest(T *testing.T) {
	T.Parallel()

	const expectedPathFormat = "/api/v1/webhooks/%s/trigger_events/%s"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		exampleWebhook := fakes.BuildFakeWebhook()
		exampleWebhookTriggerEvent := fakes.BuildFakeWebhookTriggerEvent()

		spec := newRequestSpec(false, http.MethodDelete, "", expectedPathFormat, exampleWebhook.ID, exampleWebhookTriggerEvent.ID)

		actual, err := helper.builder.BuildArchiveWebhookTriggerEventRequest(helper.ctx, exampleWebhook.ID, exampleWebhookTriggerEvent.ID)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with invalid webhook ID", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		exampleWebhookTriggerEvent := fakes.BuildFakeWebhookTriggerEvent()

		actual, err := helper.builder.BuildArchiveWebhookTriggerEventRequest(helper.ctx, "", exampleWebhookTriggerEvent.ID)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	T.Run("with invalid webhook trigger event ID", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		exampleWebhook := fakes.BuildFakeWebhook()

		actual, err := helper.builder.BuildArchiveWebhookTriggerEventRequest(helper.ctx, exampleWebhook.ID, "")
		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()
		exampleWebhook := fakes.BuildFakeWebhook()
		exampleWebhookTriggerEvent := fakes.BuildFakeWebhookTriggerEvent()

		actual, err := helper.builder.BuildArchiveWebhookTriggerEventRequest(helper.ctx, exampleWebhook.ID, exampleWebhookTriggerEvent.ID)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}
