package auditlogentries

import (
	"database/sql"
	"errors"
	"net/http"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"
	mocktypes "github.com/verygoodsoftwarenotvirus/starter/pkg/types/mock"
	testutils "github.com/verygoodsoftwarenotvirus/starter/tests/utils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestAuditLogEntriesService_ReadAuditLogEntryHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		auditLogEntryDataManager := &mocktypes.AuditLogEntryDataManagerMock{}
		auditLogEntryDataManager.On(
			"GetAuditLogEntry",
			testutils.ContextMatcher,
			helper.exampleAuditLogEntry.ID,
		).Return(helper.exampleAuditLogEntry, nil)
		helper.service.auditLogEntryDataManager = auditLogEntryDataManager

		helper.service.ReadAuditLogEntryHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusOK, helper.res.Code)
		var actual *types.APIResponse[*types.AuditLogEntry]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Equal(t, actual.Data, helper.exampleAuditLogEntry)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, auditLogEntryDataManager)
	})

	T.Run("with error retrieving session context data", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.sessionContextDataFetcher = testutils.BrokenSessionContextDataFetcher

		helper.service.ReadAuditLogEntryHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)
		var actual *types.APIResponse[*types.AuditLogEntry]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with no such audit log entry in the database", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		auditLogEntryDataManager := &mocktypes.AuditLogEntryDataManagerMock{}
		auditLogEntryDataManager.On(
			"GetAuditLogEntry",
			testutils.ContextMatcher,
			helper.exampleAuditLogEntry.ID,
		).Return((*types.AuditLogEntry)(nil), sql.ErrNoRows)
		helper.service.auditLogEntryDataManager = auditLogEntryDataManager

		helper.service.ReadAuditLogEntryHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusNotFound, helper.res.Code)
		var actual *types.APIResponse[*types.AuditLogEntry]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, auditLogEntryDataManager)
	})

	T.Run("with error fetching from database", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		auditLogEntryDataManager := &mocktypes.AuditLogEntryDataManagerMock{}
		auditLogEntryDataManager.On(
			"GetAuditLogEntry",
			testutils.ContextMatcher,
			helper.exampleAuditLogEntry.ID,
		).Return((*types.AuditLogEntry)(nil), errors.New("blah"))
		helper.service.auditLogEntryDataManager = auditLogEntryDataManager

		helper.service.ReadAuditLogEntryHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.AuditLogEntry]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, auditLogEntryDataManager)
	})
}

func TestAuditLogEntriesService_ListUserAuditLogEntriesHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		exampleAuditLogEntryList := fakes.BuildFakeAuditLogEntryList()

		auditLogEntryDataManager := &mocktypes.AuditLogEntryDataManagerMock{}
		auditLogEntryDataManager.On(
			"GetAuditLogEntriesForUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			mock.IsType(&types.QueryFilter{}),
		).Return(exampleAuditLogEntryList, nil)
		helper.service.auditLogEntryDataManager = auditLogEntryDataManager

		helper.service.ListUserAuditLogEntriesHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusOK, helper.res.Code)
		var actual *types.APIResponse[[]*types.AuditLogEntry]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Equal(t, actual.Data, exampleAuditLogEntryList.Data)
		assert.Equal(t, *actual.Pagination, exampleAuditLogEntryList.Pagination)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, auditLogEntryDataManager)
	})

	T.Run("with specified resource type", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		exampleAuditLogEntryList := fakes.BuildFakeAuditLogEntryList()

		auditLogEntryDataManager := &mocktypes.AuditLogEntryDataManagerMock{}
		auditLogEntryDataManager.On(
			"GetAuditLogEntriesForUserAndResourceType",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			[]string{helper.exampleAuditLogEntry.ResourceType},
			mock.IsType(&types.QueryFilter{}),
		).Return(exampleAuditLogEntryList, nil)
		helper.service.auditLogEntryDataManager = auditLogEntryDataManager

		q := helper.req.URL.Query()
		q.Set(types.AuditLogResourceTypesQueryParamKey, helper.exampleAuditLogEntry.ResourceType)
		helper.req.URL.RawQuery = q.Encode()

		helper.service.ListUserAuditLogEntriesHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusOK, helper.res.Code)
		var actual *types.APIResponse[[]*types.AuditLogEntry]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Equal(t, actual.Data, exampleAuditLogEntryList.Data)
		assert.Equal(t, *actual.Pagination, exampleAuditLogEntryList.Pagination)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, auditLogEntryDataManager)
	})

	T.Run("with error retrieving session context data", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.sessionContextDataFetcher = testutils.BrokenSessionContextDataFetcher

		helper.service.ListUserAuditLogEntriesHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)
		var actual *types.APIResponse[*types.AuditLogEntry]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with no rows returned", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		auditLogEntryDataManager := &mocktypes.AuditLogEntryDataManagerMock{}
		auditLogEntryDataManager.On(
			"GetAuditLogEntriesForUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			mock.IsType(&types.QueryFilter{}),
		).Return((*types.QueryFilteredResult[types.AuditLogEntry])(nil), sql.ErrNoRows)
		helper.service.auditLogEntryDataManager = auditLogEntryDataManager

		helper.service.ListUserAuditLogEntriesHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusOK, helper.res.Code)
		var actual *types.APIResponse[[]*types.AuditLogEntry]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, auditLogEntryDataManager)
	})

	T.Run("with error retrieving audit log entries from database", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		auditLogEntryDataManager := &mocktypes.AuditLogEntryDataManagerMock{}
		auditLogEntryDataManager.On(
			"GetAuditLogEntriesForUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			mock.IsType(&types.QueryFilter{}),
		).Return((*types.QueryFilteredResult[types.AuditLogEntry])(nil), errors.New("blah"))
		helper.service.auditLogEntryDataManager = auditLogEntryDataManager

		helper.service.ListUserAuditLogEntriesHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.AuditLogEntry]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, auditLogEntryDataManager)
	})
}

func TestAuditLogEntriesService_ListAccountAuditLogEntriesHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		exampleAuditLogEntryList := fakes.BuildFakeAuditLogEntryList()

		auditLogEntryDataManager := &mocktypes.AuditLogEntryDataManagerMock{}
		auditLogEntryDataManager.On(
			"GetAuditLogEntriesForAccount",
			testutils.ContextMatcher,
			helper.exampleAccount.ID,
			mock.IsType(&types.QueryFilter{}),
		).Return(exampleAuditLogEntryList, nil)
		helper.service.auditLogEntryDataManager = auditLogEntryDataManager

		helper.service.ListAccountAuditLogEntriesHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusOK, helper.res.Code)
		var actual *types.APIResponse[[]*types.AuditLogEntry]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Equal(t, actual.Data, exampleAuditLogEntryList.Data)
		assert.Equal(t, *actual.Pagination, exampleAuditLogEntryList.Pagination)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, auditLogEntryDataManager)
	})

	T.Run("with specified resource type", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		exampleAuditLogEntryList := fakes.BuildFakeAuditLogEntryList()

		auditLogEntryDataManager := &mocktypes.AuditLogEntryDataManagerMock{}
		auditLogEntryDataManager.On(
			"GetAuditLogEntriesForAccountAndResourceType",
			testutils.ContextMatcher,
			helper.exampleAccount.ID,
			[]string{helper.exampleAuditLogEntry.ResourceType},
			mock.IsType(&types.QueryFilter{}),
		).Return(exampleAuditLogEntryList, nil)
		helper.service.auditLogEntryDataManager = auditLogEntryDataManager

		q := helper.req.URL.Query()
		q.Set(types.AuditLogResourceTypesQueryParamKey, helper.exampleAuditLogEntry.ResourceType)
		helper.req.URL.RawQuery = q.Encode()

		helper.service.ListAccountAuditLogEntriesHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusOK, helper.res.Code)
		var actual *types.APIResponse[[]*types.AuditLogEntry]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Equal(t, actual.Data, exampleAuditLogEntryList.Data)
		assert.Equal(t, *actual.Pagination, exampleAuditLogEntryList.Pagination)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, auditLogEntryDataManager)
	})

	T.Run("with error retrieving session context data", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.sessionContextDataFetcher = testutils.BrokenSessionContextDataFetcher

		helper.service.ListAccountAuditLogEntriesHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)
		var actual *types.APIResponse[*types.AuditLogEntry]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with no rows returned", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		auditLogEntryDataManager := &mocktypes.AuditLogEntryDataManagerMock{}
		auditLogEntryDataManager.On(
			"GetAuditLogEntriesForAccount",
			testutils.ContextMatcher,
			helper.exampleAccount.ID,
			mock.IsType(&types.QueryFilter{}),
		).Return((*types.QueryFilteredResult[types.AuditLogEntry])(nil), sql.ErrNoRows)
		helper.service.auditLogEntryDataManager = auditLogEntryDataManager

		helper.service.ListAccountAuditLogEntriesHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusOK, helper.res.Code)
		var actual *types.APIResponse[[]*types.AuditLogEntry]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, auditLogEntryDataManager)
	})

	T.Run("with error retrieving audit log entries from database", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		auditLogEntryDataManager := &mocktypes.AuditLogEntryDataManagerMock{}
		auditLogEntryDataManager.On(
			"GetAuditLogEntriesForAccount",
			testutils.ContextMatcher,
			helper.exampleAccount.ID,
			mock.IsType(&types.QueryFilter{}),
		).Return((*types.QueryFilteredResult[types.AuditLogEntry])(nil), errors.New("blah"))
		helper.service.auditLogEntryDataManager = auditLogEntryDataManager

		helper.service.ListAccountAuditLogEntriesHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.AuditLogEntry]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, auditLogEntryDataManager)
	})
}
