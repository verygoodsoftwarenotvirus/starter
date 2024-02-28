package requests

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"

	"github.com/stretchr/testify/assert"
)

func TestBuilder_BuildGetSelfRequest(T *testing.T) {
	T.Parallel()

	const expectedPathFormat = "/api/v1/users/self"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		spec := newRequestSpec(true, http.MethodGet, "", expectedPathFormat)

		actual, err := helper.builder.BuildGetSelfRequest(helper.ctx)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()

		actual, err := helper.builder.BuildGetSelfRequest(helper.ctx)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func TestBuilder_BuildGetUserRequest(T *testing.T) {
	T.Parallel()

	const expectedPathFormat = "/api/v1/users/%s"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		spec := newRequestSpec(true, http.MethodGet, "", expectedPathFormat, helper.exampleUser.ID)

		actual, err := helper.builder.BuildGetUserRequest(helper.ctx, helper.exampleUser.ID)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with invalid user ID", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		actual, err := helper.builder.BuildGetUserRequest(helper.ctx, "")
		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()

		actual, err := helper.builder.BuildGetUserRequest(helper.ctx, helper.exampleUser.ID)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func TestBuilder_BuildGetUsersRequest(T *testing.T) {
	T.Parallel()

	const expectedPath = "/api/v1/users"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		spec := newRequestSpec(true, http.MethodGet, "limit=50&page=1&sortBy=asc", expectedPath)

		actual, err := helper.builder.BuildGetUsersRequest(helper.ctx, nil)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()

		actual, err := helper.builder.BuildGetUsersRequest(helper.ctx, nil)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func TestBuilder_BuildSearchForUsersByUsernameRequest(T *testing.T) {
	T.Parallel()

	const expectedPath = "/api/v1/users/search"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		exampleUsername := fakes.BuildFakeUser().Username
		spec := newRequestSpec(false, http.MethodGet, fmt.Sprintf("q=%s", exampleUsername), expectedPath)

		actual, err := helper.builder.BuildSearchForUsersByUsernameRequest(helper.ctx, exampleUsername)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with empty username", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		actual, err := helper.builder.BuildSearchForUsersByUsernameRequest(helper.ctx, "")
		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()

		exampleUsername := fakes.BuildFakeUser().Username

		actual, err := helper.builder.BuildSearchForUsersByUsernameRequest(helper.ctx, exampleUsername)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func TestBuilder_BuildCreateUserRequest(T *testing.T) {
	T.Parallel()

	const expectedPath = "/users"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		exampleInput := fakes.BuildFakeUserCreationInput()

		spec := newRequestSpec(false, http.MethodPost, "", expectedPath)

		actual, err := helper.builder.BuildCreateUserRequest(helper.ctx, exampleInput)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with nil input", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		actual, err := helper.builder.BuildCreateUserRequest(helper.ctx, nil)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()
		exampleInput := fakes.BuildFakeUserCreationInput()

		actual, err := helper.builder.BuildCreateUserRequest(helper.ctx, exampleInput)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func TestBuilder_BuildArchiveUserRequest(T *testing.T) {
	T.Parallel()

	const expectedPathFormat = "/api/v1/users/%s"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		spec := newRequestSpec(true, http.MethodDelete, "", expectedPathFormat, helper.exampleUser.ID)

		actual, err := helper.builder.BuildArchiveUserRequest(helper.ctx, helper.exampleUser.ID)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with invalid user ID", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		actual, err := helper.builder.BuildArchiveUserRequest(helper.ctx, "")
		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()

		actual, err := helper.builder.BuildArchiveUserRequest(helper.ctx, helper.exampleUser.ID)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func TestBuilder_BuildAvatarUploadRequest(T *testing.T) {
	T.Parallel()

	const expectedPath = "/api/v1/users/avatar/upload"
	exampleInput := fakes.BuildFakeAvatarUpdateInput()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		spec := newRequestSpec(false, http.MethodPost, "", expectedPath)

		actual, err := helper.builder.BuildAvatarUploadRequest(helper.ctx, exampleInput)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with nil input", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		actual, err := helper.builder.BuildAvatarUploadRequest(helper.ctx, nil)
		assert.Error(t, err)
		assert.Nil(t, actual)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()

		actual, err := helper.builder.BuildAvatarUploadRequest(helper.ctx, exampleInput)
		assert.Error(t, err)
		assert.Nil(t, actual)
	})
}

func TestBuilder_BuildCheckUserPermissionsRequests(T *testing.T) {
	T.Parallel()

	const expectedPath = "/api/v1/users/permissions/check"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		spec := newRequestSpec(false, http.MethodPost, "", expectedPath)

		actual, err := helper.builder.BuildCheckUserPermissionsRequests(helper.ctx, t.Name())
		assert.NoError(t, err)
		assert.NotNil(t, actual)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with invalid permissions", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		actual, err := helper.builder.BuildCheckUserPermissionsRequests(helper.ctx)
		assert.Error(t, err)
		assert.Nil(t, actual)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()

		actual, err := helper.builder.BuildCheckUserPermissionsRequests(helper.ctx, t.Name())
		assert.Error(t, err)
		assert.Nil(t, actual)
	})
}

func TestBuilder_BuildUpdateUserEmailAddressRequest(T *testing.T) {
	T.Parallel()

	const expectedPathFormat = "/api/v1/users/email_address"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		exampleInput := fakes.BuildFakeUserEmailAddressUpdateInput()

		spec := newRequestSpec(true, http.MethodPut, "", expectedPathFormat)

		actual, err := helper.builder.BuildUpdateUserEmailAddressRequest(helper.ctx, exampleInput)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with invalid user ID", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		actual, err := helper.builder.BuildUpdateUserEmailAddressRequest(helper.ctx, nil)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		exampleInput := fakes.BuildFakeUserEmailAddressUpdateInput()
		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()

		actual, err := helper.builder.BuildUpdateUserEmailAddressRequest(helper.ctx, exampleInput)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func TestBuilder_BuildUpdateUserUsernameRequest(T *testing.T) {
	T.Parallel()

	const expectedPathFormat = "/api/v1/users/username"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		exampleInput := fakes.BuildFakeUsernameUpdateInput()

		spec := newRequestSpec(true, http.MethodPut, "", expectedPathFormat)

		actual, err := helper.builder.BuildUpdateUserUsernameRequest(helper.ctx, exampleInput)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with invalid user ID", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		actual, err := helper.builder.BuildUpdateUserUsernameRequest(helper.ctx, nil)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		exampleInput := fakes.BuildFakeUsernameUpdateInput()
		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()

		actual, err := helper.builder.BuildUpdateUserUsernameRequest(helper.ctx, exampleInput)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func TestBuilder_BuildUpdateUserDetailsRequest(T *testing.T) {
	T.Parallel()

	const expectedPathFormat = "/api/v1/users/details"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		exampleInput := fakes.BuildFakeUserDetailsUpdateInput()

		spec := newRequestSpec(true, http.MethodPut, "", expectedPathFormat)

		actual, err := helper.builder.BuildUpdateUserDetailsRequest(helper.ctx, exampleInput)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with invalid user ID", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		actual, err := helper.builder.BuildUpdateUserDetailsRequest(helper.ctx, nil)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		exampleInput := fakes.BuildFakeUserDetailsUpdateInput()
		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()

		actual, err := helper.builder.BuildUpdateUserDetailsRequest(helper.ctx, exampleInput)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}
