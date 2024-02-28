package requests

import (
	"net/http"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"

	"github.com/stretchr/testify/assert"
)

func TestBuilder_BuildGetAuditLogEntryRequest(T *testing.T) {
	T.Parallel()

	const expectedPath = "/api/v1/audit_log_entries/%s"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		exampleAuditLogEntry := fakes.BuildFakeAuditLogEntry()
		spec := newRequestSpec(true, http.MethodGet, "", expectedPath, exampleAuditLogEntry.ID)

		actual, err := helper.builder.BuildGetAuditLogEntryRequest(helper.ctx, exampleAuditLogEntry.ID)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		exampleAuditLogEntry := fakes.BuildFakeAuditLogEntry()
		helper.builder = buildTestRequestBuilderWithInvalidURL()

		actual, err := helper.builder.BuildGetAuditLogEntryRequest(helper.ctx, exampleAuditLogEntry.ID)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func TestBuilder_BuildGetAuditLogEntriesForUserRequest(T *testing.T) {
	T.Parallel()

	const expectedPath = "/api/v1/audit_log_entries/for_user"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		spec := newRequestSpec(false, http.MethodGet, "", expectedPath)

		actual, err := helper.builder.BuildGetAuditLogEntriesForUserRequest(helper.ctx)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with specified resource", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		spec := newRequestSpec(false, http.MethodGet, "resources=example", expectedPath)

		actual, err := helper.builder.BuildGetAuditLogEntriesForUserRequest(helper.ctx, "example")
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()

		actual, err := helper.builder.BuildGetAuditLogEntriesForUserRequest(helper.ctx)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func TestBuilder_BuildGetAuditLogEntriesForAccountRequest(T *testing.T) {
	T.Parallel()

	const expectedPath = "/api/v1/audit_log_entries/for_account"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		spec := newRequestSpec(true, http.MethodGet, "", expectedPath)

		actual, err := helper.builder.BuildGetAuditLogEntriesForAccountRequest(helper.ctx)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with specified resource type", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		spec := newRequestSpec(true, http.MethodGet, "resources=example", expectedPath)

		actual, err := helper.builder.BuildGetAuditLogEntriesForAccountRequest(helper.ctx, "example")
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with invalid request builder", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()
		helper.builder = buildTestRequestBuilderWithInvalidURL()

		actual, err := helper.builder.BuildGetAuditLogEntriesForAccountRequest(helper.ctx)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}
