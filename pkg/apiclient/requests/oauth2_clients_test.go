package requests

import (
	"net/http"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"

	"github.com/stretchr/testify/assert"
)

func TestBuilder_BuildGetOAuth2ClientRequest(T *testing.T) {
	T.Parallel()

	const expectedPathFormat = "/api/v1/oauth2_clients/%s"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		exampleOAuth2Client := fakes.BuildFakeOAuth2Client()

		spec := newRequestSpec(true, http.MethodGet, "", expectedPathFormat, exampleOAuth2Client.ID)

		actual, err := helper.builder.BuildGetOAuth2ClientRequest(helper.ctx, exampleOAuth2Client.ID)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with invalid client ID", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		actual, err := helper.builder.BuildGetOAuth2ClientRequest(helper.ctx, "")
		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()
		exampleOAuth2Client := fakes.BuildFakeOAuth2Client()

		actual, err := helper.builder.BuildGetOAuth2ClientRequest(helper.ctx, exampleOAuth2Client.ID)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func TestBuilder_BuildGetOAuth2ClientsRequest(T *testing.T) {
	T.Parallel()

	const expectedPath = "/api/v1/oauth2_clients"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		spec := newRequestSpec(true, http.MethodGet, "limit=50&page=1&sortBy=asc", expectedPath)

		actual, err := helper.builder.BuildGetOAuth2ClientsRequest(helper.ctx, nil)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()

		actual, err := helper.builder.BuildGetOAuth2ClientsRequest(helper.ctx, nil)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func TestBuilder_BuildCreateOAuth2ClientRequest(T *testing.T) {
	T.Parallel()

	const expectedPath = "/api/v1/oauth2_clients"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		exampleInput := fakes.BuildFakeOAuth2ClientCreationInput()

		spec := newRequestSpec(false, http.MethodPost, "", expectedPath)

		actual, err := helper.builder.BuildCreateOAuth2ClientRequest(helper.ctx, exampleInput)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with nil input", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		actual, err := helper.builder.BuildCreateOAuth2ClientRequest(helper.ctx, nil)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()

		exampleInput := fakes.BuildFakeOAuth2ClientCreationInput()

		actual, err := helper.builder.BuildCreateOAuth2ClientRequest(helper.ctx, exampleInput)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func TestBuilder_BuildArchiveOAuth2ClientRequest(T *testing.T) {
	T.Parallel()

	const expectedPathFormat = "/api/v1/oauth2_clients/%s"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		exampleOAuth2Client := fakes.BuildFakeOAuth2Client()

		spec := newRequestSpec(true, http.MethodDelete, "", expectedPathFormat, exampleOAuth2Client.ID)

		actual, err := helper.builder.BuildArchiveOAuth2ClientRequest(helper.ctx, exampleOAuth2Client.ID)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with invalid client ID", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		actual, err := helper.builder.BuildArchiveOAuth2ClientRequest(helper.ctx, "")
		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()
		exampleOAuth2Client := fakes.BuildFakeOAuth2Client()

		actual, err := helper.builder.BuildArchiveOAuth2ClientRequest(helper.ctx, exampleOAuth2Client.ID)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}
