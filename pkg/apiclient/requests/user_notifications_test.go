package requests

import (
	"net/http"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"

	"github.com/stretchr/testify/assert"
)

func TestBuilder_BuildGetUserNotificationRequest(T *testing.T) {
	T.Parallel()

	const expectedPathFormat = "/api/v1/user_notifications/%s"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		exampleUserNotification := fakes.BuildFakeUserNotification()

		spec := newRequestSpec(true, http.MethodGet, "", expectedPathFormat, exampleUserNotification.ID)

		actual, err := helper.builder.BuildGetUserNotificationRequest(helper.ctx, exampleUserNotification.ID)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with invalid user notification ID", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		actual, err := helper.builder.BuildGetUserNotificationRequest(helper.ctx, "")
		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()

		exampleUserNotification := fakes.BuildFakeUserNotification()

		actual, err := helper.builder.BuildGetUserNotificationRequest(helper.ctx, exampleUserNotification.ID)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func TestBuilder_BuildGetUserNotificationsRequest(T *testing.T) {
	T.Parallel()

	const expectedPathFormat = "/api/v1/user_notifications"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		filter := (*types.QueryFilter)(nil)
		spec := newRequestSpec(true, http.MethodGet, "limit=50&page=1&sortBy=asc", expectedPathFormat)

		actual, err := helper.builder.BuildGetUserNotificationsRequest(helper.ctx, filter)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()

		filter := (*types.QueryFilter)(nil)

		actual, err := helper.builder.BuildGetUserNotificationsRequest(helper.ctx, filter)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func TestBuilder_BuildCreateUserNotificationRequest(T *testing.T) {
	T.Parallel()

	const expectedPath = "/api/v1/user_notifications"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		exampleInput := fakes.BuildFakeUserNotificationCreationRequestInput()

		spec := newRequestSpec(false, http.MethodPost, "", expectedPath)

		actual, err := helper.builder.BuildCreateUserNotificationRequest(helper.ctx, exampleInput)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with nil input", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		actual, err := helper.builder.BuildCreateUserNotificationRequest(helper.ctx, nil)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	T.Run("with invalid input", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		actual, err := helper.builder.BuildCreateUserNotificationRequest(helper.ctx, &types.UserNotificationCreationRequestInput{})
		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()

		exampleInput := fakes.BuildFakeUserNotificationCreationRequestInput()

		actual, err := helper.builder.BuildCreateUserNotificationRequest(helper.ctx, exampleInput)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func TestBuilder_BuildUpdateUserNotificationRequest(T *testing.T) {
	T.Parallel()

	const expectedPathFormat = "/api/v1/user_notifications/%s"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		exampleUserNotification := fakes.BuildFakeUserNotification()

		spec := newRequestSpec(false, http.MethodPatch, "", expectedPathFormat, exampleUserNotification.ID)

		actual, err := helper.builder.BuildUpdateUserNotificationRequest(helper.ctx, exampleUserNotification)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with nil input", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		actual, err := helper.builder.BuildUpdateUserNotificationRequest(helper.ctx, nil)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()

		exampleUserNotification := fakes.BuildFakeUserNotification()

		actual, err := helper.builder.BuildUpdateUserNotificationRequest(helper.ctx, exampleUserNotification)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}
