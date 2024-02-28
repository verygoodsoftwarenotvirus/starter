package apiclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func TestAuditLogEntries(t *testing.T) {
	t.Parallel()

	suite.Run(t, new(auditLogEntriesTestSuite))
}

type auditLogEntriesTestSuite struct {
	suite.Suite

	ctx                              context.Context
	exampleUser                      *types.User
	exampleAccount                   *types.Account
	exampleAuditLogEntry             *types.AuditLogEntry
	exampleAuditLogEntryList         *types.QueryFilteredResult[types.AuditLogEntry]
	exampleAuditLogEntryResponse     *types.APIResponse[*types.AuditLogEntry]
	exampleAuditLogEntryListResponse *types.APIResponse[[]*types.AuditLogEntry]
}

var _ suite.SetupTestSuite = (*auditLogEntriesTestSuite)(nil)

func (s *auditLogEntriesTestSuite) SetupTest() {
	s.ctx = context.Background()

	s.exampleUser = fakes.BuildFakeUser()
	s.exampleAccount = fakes.BuildFakeAccount()
	s.exampleAccount.BelongsToUser = s.exampleUser.ID
	s.exampleAuditLogEntry = fakes.BuildFakeAuditLogEntry()
	s.exampleAuditLogEntry.BelongsToUser = s.exampleUser.ID
	s.exampleAuditLogEntry.BelongsToAccount = &s.exampleAccount.ID
	s.exampleAuditLogEntryList = fakes.BuildFakeAuditLogEntryList()
	s.exampleAuditLogEntryResponse = &types.APIResponse[*types.AuditLogEntry]{
		Data: s.exampleAuditLogEntry,
	}
	s.exampleAuditLogEntryListResponse = &types.APIResponse[[]*types.AuditLogEntry]{
		Data:       s.exampleAuditLogEntryList.Data,
		Pagination: &s.exampleAuditLogEntryList.Pagination,
	}
}

func (s *auditLogEntriesTestSuite) TestClient_GetAuditLogEntry() {
	const expectedPath = "/api/v1/audit_log_entries/%s"

	s.Run("standard", func() {
		t := s.T()

		spec := newRequestSpec(false, http.MethodGet, "", expectedPath, s.exampleAuditLogEntry.ID)
		c, _ := buildTestClientWithJSONResponse(t, spec, s.exampleAuditLogEntryResponse)

		actual, err := c.GetAuditLogEntry(s.ctx, s.exampleAuditLogEntry.ID)
		assert.NoError(t, err)
		assert.Equal(t, s.exampleAuditLogEntry, actual)
	})

	s.Run("with error building request", func() {
		t := s.T()

		c := buildTestClientWithInvalidURL(t)

		actual, err := c.GetAuditLogEntry(s.ctx, s.exampleAuditLogEntry.ID)
		assert.Error(t, err)
		assert.Nil(t, actual)
	})

	s.Run("with error executing request", func() {
		t := s.T()

		c, _ := buildTestClientThatWaitsTooLong(t)

		actual, err := c.GetAuditLogEntry(s.ctx, s.exampleAuditLogEntry.ID)
		assert.Error(t, err)
		assert.Nil(t, actual)
	})
}

func (s *auditLogEntriesTestSuite) TestClient_GetAuditLogEntriesForUser() {
	const expectedPath = "/api/v1/audit_log_entries/for_user"

	s.Run("standard", func() {
		t := s.T()

		spec := newRequestSpec(true, http.MethodGet, "", expectedPath)
		ts := httptest.NewTLSServer(http.HandlerFunc(
			func(res http.ResponseWriter, req *http.Request) {
				assertRequestQuality(t, req, spec)

				require.NoError(t, json.NewEncoder(res).Encode(s.exampleAuditLogEntryListResponse))
			},
		))
		c := buildTestClient(t, ts)

		auditLogEntriesList, err := c.GetAuditLogEntriesForUser(s.ctx)
		assert.Equal(t, auditLogEntriesList, s.exampleAuditLogEntryList)
		assert.NoError(t, err)
	})

	s.Run("with nil input", func() {
		t := s.T()

		c, _ := buildSimpleTestClient(t)

		auditLogEntryList, err := c.GetAuditLogEntriesForUser(s.ctx)
		assert.Empty(t, auditLogEntryList)
		assert.Error(t, err)
	})

	s.Run("with error building request", func() {
		t := s.T()

		c := buildTestClientWithInvalidURL(t)

		auditLogEntryList, err := c.GetAuditLogEntriesForUser(s.ctx)
		assert.Empty(t, auditLogEntryList)
		assert.Error(t, err)
	})

	s.Run("with timeout", func() {
		t := s.T()

		c, _ := buildTestClientThatWaitsTooLong(t)

		auditLogEntryList, err := c.GetAuditLogEntriesForUser(s.ctx)
		require.Empty(t, auditLogEntryList)
		assert.Error(t, err)
	})
}

func (s *auditLogEntriesTestSuite) TestClient_GetAuditLogEntriesForAccount() {
	const expectedPath = "/api/v1/audit_log_entries/for_account"

	s.Run("standard", func() {
		t := s.T()

		spec := newRequestSpec(true, http.MethodGet, "", expectedPath)
		ts := httptest.NewTLSServer(http.HandlerFunc(
			func(res http.ResponseWriter, req *http.Request) {
				assertRequestQuality(t, req, spec)

				require.NoError(t, json.NewEncoder(res).Encode(s.exampleAuditLogEntryListResponse))
			},
		))
		c := buildTestClient(t, ts)

		auditLogEntriesList, err := c.GetAuditLogEntriesForAccount(s.ctx)
		assert.Equal(t, auditLogEntriesList, s.exampleAuditLogEntryList)
		assert.NoError(t, err)
	})

	s.Run("with error building request", func() {
		t := s.T()

		c := buildTestClientWithInvalidURL(t)

		auditLogEntriesList, err := c.GetAuditLogEntriesForAccount(s.ctx)
		assert.Nil(t, auditLogEntriesList)
		assert.Error(t, err)
	})

	s.Run("with error executing request", func() {
		t := s.T()

		c, _ := buildTestClientThatWaitsTooLong(t)

		auditLogEntriesList, err := c.GetAuditLogEntriesForAccount(s.ctx)
		assert.Nil(t, auditLogEntriesList)
		assert.Error(t, err)
	})
}
