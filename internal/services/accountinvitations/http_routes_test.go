package accountinvitations

import (
	"bytes"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/internal/database"
	"github.com/verygoodsoftwarenotvirus/starter/internal/encoding"
	mockpublishers "github.com/verygoodsoftwarenotvirus/starter/internal/messagequeue/mock"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	randommock "github.com/verygoodsoftwarenotvirus/starter/internal/pkg/random/mock"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/converters"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"
	mocktypes "github.com/verygoodsoftwarenotvirus/starter/pkg/types/mock"
	testutils "github.com/verygoodsoftwarenotvirus/starter/tests/utils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func Test_service_InviteMemberHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeAccountInvitationCreationRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		udm := &mocktypes.UserDataManagerMock{}
		udm.On(
			"GetUserByEmail",
			testutils.ContextMatcher,
			strings.TrimSpace(strings.ToLower(exampleInput.ToEmail)),
		).Return(helper.exampleUser, nil)
		helper.service.userDataManager = udm

		sg := &randommock.Generator{}
		sg.On(
			"GenerateBase64EncodedString",
			testutils.ContextMatcher,
			64,
		).Return(t.Name(), nil)
		helper.service.secretGenerator = sg

		dbManager := database.NewMockDatabase()
		dbManager.AccountInvitationDataManagerMock.On(
			"CreateAccountInvitation",
			testutils.ContextMatcher,
			mock.MatchedBy(func(*types.AccountInvitationDatabaseCreationInput) bool { return true }),
		).Return(helper.exampleAccountInvitation, nil)
		helper.service.accountInvitationDataManager = dbManager

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(nil)
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.InviteMemberHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusCreated, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		helper.exampleAccountInvitation.FromUser.TwoFactorSecret = ""
		helper.exampleAccountInvitation.DestinationAccount.WebhookEncryptionKey = ""
		assert.Equal(t, actual.Data, helper.exampleAccountInvitation)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, udm, sg, dbManager, dataChangesPublisher)
	})

	T.Run("with error fetching session context data", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)

		helper.service.sessionContextDataFetcher = func(*http.Request) (*types.SessionContextData, error) {
			return nil, errors.New("blah")
		}

		helper.service.InviteMemberHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with invalid input", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := &types.AccountInvitationCreationRequestInput{}
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.service.InviteMemberHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with error generating invitation token", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeAccountInvitationCreationRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		sg := &randommock.Generator{}
		sg.On(
			"GenerateBase64EncodedString",
			testutils.ContextMatcher,
			64,
		).Return("", errors.New("blah"))
		helper.service.secretGenerator = sg

		helper.service.InviteMemberHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, sg)
	})

	T.Run("with error fetching user ID", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeAccountInvitationCreationRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		sg := &randommock.Generator{}
		sg.On(
			"GenerateBase64EncodedString",
			testutils.ContextMatcher,
			64,
		).Return(t.Name(), nil)
		helper.service.secretGenerator = sg

		udm := &mocktypes.UserDataManagerMock{}
		udm.On(
			"GetUserByEmail",
			testutils.ContextMatcher,
			strings.TrimSpace(strings.ToLower(exampleInput.ToEmail)),
		).Return((*types.User)(nil), errors.New("blah"))
		helper.service.userDataManager = udm

		helper.service.InviteMemberHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, udm, sg)
	})

	T.Run("with error writing to database", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeAccountInvitationCreationRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		udm := &mocktypes.UserDataManagerMock{}
		udm.On(
			"GetUserByEmail",
			testutils.ContextMatcher,
			strings.TrimSpace(strings.ToLower(exampleInput.ToEmail)),
		).Return(helper.exampleUser, nil)
		helper.service.userDataManager = udm

		sg := &randommock.Generator{}
		sg.On(
			"GenerateBase64EncodedString",
			testutils.ContextMatcher,
			64,
		).Return(t.Name(), nil)
		helper.service.secretGenerator = sg

		dbManager := database.NewMockDatabase()
		dbManager.AccountInvitationDataManagerMock.On(
			"CreateAccountInvitation",
			testutils.ContextMatcher,
			mock.MatchedBy(func(*types.AccountInvitationDatabaseCreationInput) bool { return true }),
		).Return((*types.AccountInvitation)(nil), errors.New("blah"))
		helper.service.accountInvitationDataManager = dbManager

		helper.service.InviteMemberHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, udm, sg, dbManager)
	})

	T.Run("with error publishing message", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeAccountInvitationCreationRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		udm := &mocktypes.UserDataManagerMock{}
		udm.On(
			"GetUserByEmail",
			testutils.ContextMatcher,
			strings.TrimSpace(strings.ToLower(exampleInput.ToEmail)),
		).Return(helper.exampleUser, nil)
		helper.service.userDataManager = udm

		sg := &randommock.Generator{}
		sg.On(
			"GenerateBase64EncodedString",
			testutils.ContextMatcher,
			64,
		).Return(t.Name(), nil)
		helper.service.secretGenerator = sg

		dbManager := database.NewMockDatabase()
		dbManager.AccountInvitationDataManagerMock.On(
			"CreateAccountInvitation",
			testutils.ContextMatcher,
			mock.MatchedBy(func(*types.AccountInvitationDatabaseCreationInput) bool { return true }),
		).Return(helper.exampleAccountInvitation, nil)
		helper.service.accountInvitationDataManager = dbManager

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(errors.New("blah"))
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.InviteMemberHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusCreated, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		helper.exampleAccountInvitation.FromUser.TwoFactorSecret = ""
		helper.exampleAccountInvitation.DestinationAccount.WebhookEncryptionKey = ""
		assert.Equal(t, actual.Data, helper.exampleAccountInvitation)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, udm, sg, dbManager, dataChangesPublisher)
	})

	T.Run("with error collecting data", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeAccountInvitationCreationRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		udm := &mocktypes.UserDataManagerMock{}
		udm.On(
			"GetUserByEmail",
			testutils.ContextMatcher,
			strings.TrimSpace(strings.ToLower(exampleInput.ToEmail)),
		).Return(helper.exampleUser, nil)
		helper.service.userDataManager = udm

		sg := &randommock.Generator{}
		sg.On(
			"GenerateBase64EncodedString",
			testutils.ContextMatcher,
			64,
		).Return(t.Name(), nil)
		helper.service.secretGenerator = sg

		dbManager := database.NewMockDatabase()
		dbManager.AccountInvitationDataManagerMock.On(
			"CreateAccountInvitation",
			testutils.ContextMatcher,
			mock.MatchedBy(func(*types.AccountInvitationDatabaseCreationInput) bool { return true }),
		).Return(helper.exampleAccountInvitation, nil)
		helper.service.accountInvitationDataManager = dbManager

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(nil)
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.InviteMemberHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusCreated, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		helper.exampleAccountInvitation.FromUser.TwoFactorSecret = ""
		helper.exampleAccountInvitation.DestinationAccount.WebhookEncryptionKey = ""
		assert.Equal(t, actual.Data, helper.exampleAccountInvitation)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, udm, sg, dbManager, dataChangesPublisher)
	})

	T.Run("with error publishing email request", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeAccountInvitationCreationRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		udm := &mocktypes.UserDataManagerMock{}
		udm.On(
			"GetUserByEmail",
			testutils.ContextMatcher,
			strings.TrimSpace(strings.ToLower(exampleInput.ToEmail)),
		).Return(helper.exampleUser, nil)
		helper.service.userDataManager = udm

		sg := &randommock.Generator{}
		sg.On(
			"GenerateBase64EncodedString",
			testutils.ContextMatcher,
			64,
		).Return(t.Name(), nil)
		helper.service.secretGenerator = sg

		dbManager := database.NewMockDatabase()
		dbManager.AccountInvitationDataManagerMock.On(
			"CreateAccountInvitation",
			testutils.ContextMatcher,
			mock.MatchedBy(func(*types.AccountInvitationDatabaseCreationInput) bool { return true }),
		).Return(helper.exampleAccountInvitation, nil)
		helper.service.accountInvitationDataManager = dbManager

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(nil)
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.InviteMemberHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusCreated, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		helper.exampleAccountInvitation.FromUser.TwoFactorSecret = ""
		helper.exampleAccountInvitation.DestinationAccount.WebhookEncryptionKey = ""
		assert.Equal(t, actual.Data, helper.exampleAccountInvitation)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, udm, sg, dbManager, dataChangesPublisher)
	})
}

func Test_service_ReadHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)

		wd := &mocktypes.AccountInvitationDataManagerMock{}
		wd.On(
			"GetAccountInvitationByAccountAndID",
			testutils.ContextMatcher,
			helper.exampleAccount.ID,
			helper.exampleAccountInvitation.ID,
		).Return(helper.exampleAccountInvitation, nil)
		helper.service.accountInvitationDataManager = wd

		helper.service.ReadHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusOK, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		helper.exampleAccountInvitation.FromUser.TwoFactorSecret = ""
		helper.exampleAccountInvitation.DestinationAccount.WebhookEncryptionKey = ""
		assert.Equal(t, actual.Data, helper.exampleAccountInvitation)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, wd)
	})

	T.Run("with error retrieving session context data", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.sessionContextDataFetcher = testutils.BrokenSessionContextDataFetcher

		helper.service.ReadHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with no such account invitation in database", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)

		wd := &mocktypes.AccountInvitationDataManagerMock{}
		wd.On(
			"GetAccountInvitationByAccountAndID",
			testutils.ContextMatcher,
			helper.exampleAccount.ID,
			helper.exampleAccountInvitation.ID,
		).Return((*types.AccountInvitation)(nil), sql.ErrNoRows)
		helper.service.accountInvitationDataManager = wd

		helper.service.ReadHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusNotFound, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, wd)
	})

	T.Run("with error fetching account invitation from database", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)

		wd := &mocktypes.AccountInvitationDataManagerMock{}
		wd.On(
			"GetAccountInvitationByAccountAndID",
			testutils.ContextMatcher,
			helper.exampleAccount.ID,
			helper.exampleAccountInvitation.ID,
		).Return((*types.AccountInvitation)(nil), errors.New("blah"))
		helper.service.accountInvitationDataManager = wd

		helper.service.ReadHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, wd)
	})
}

func Test_service_InboundInvitesHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		exampleAccountInvitations := fakes.BuildFakeAccountInvitationList()

		wd := &mocktypes.AccountInvitationDataManagerMock{}
		wd.On(
			"GetPendingAccountInvitationsForUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			mock.IsType(&types.QueryFilter{}),
		).Return(exampleAccountInvitations, nil)
		helper.service.accountInvitationDataManager = wd

		helper.service.InboundInvitesHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusOK, helper.res.Code)
		var actual *types.APIResponse[[]*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NotEmpty(t, actual.Data)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, wd)
	})

	T.Run("with error fetching session context data", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.sessionContextDataFetcher = func(*http.Request) (*types.SessionContextData, error) {
			return nil, errors.New("blah")
		}

		helper.service.InboundInvitesHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with error reading from database", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)

		wd := &mocktypes.AccountInvitationDataManagerMock{}
		wd.On(
			"GetPendingAccountInvitationsForUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			mock.IsType(&types.QueryFilter{}),
		).Return((*types.QueryFilteredResult[types.AccountInvitation])(nil), errors.New("blah"))
		helper.service.accountInvitationDataManager = wd

		helper.service.InboundInvitesHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, wd)
	})
}

func Test_service_OutboundInvitesHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		exampleAccountInvitations := fakes.BuildFakeAccountInvitationList()

		wd := &mocktypes.AccountInvitationDataManagerMock{}
		wd.On(
			"GetPendingAccountInvitationsFromUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			mock.IsType(&types.QueryFilter{}),
		).Return(exampleAccountInvitations, nil)
		helper.service.accountInvitationDataManager = wd

		helper.service.OutboundInvitesHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusOK, helper.res.Code)
		var actual *types.APIResponse[[]*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NotEmpty(t, actual.Data)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, wd)
	})

	T.Run("with error fetching session context data", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.sessionContextDataFetcher = func(*http.Request) (*types.SessionContextData, error) {
			return nil, errors.New("blah")
		}

		helper.service.OutboundInvitesHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with error reading from database", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)

		wd := &mocktypes.AccountInvitationDataManagerMock{}
		wd.On(
			"GetPendingAccountInvitationsFromUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			mock.IsType(&types.QueryFilter{}),
		).Return((*types.QueryFilteredResult[types.AccountInvitation])(nil), errors.New("blah"))
		helper.service.accountInvitationDataManager = wd

		helper.service.OutboundInvitesHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, wd)
	})
}

func Test_service_AcceptInviteHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := converters.ConvertAccountInvitationToAccountInvitationUpdateInput(helper.exampleAccountInvitation)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		dataManager := &mocktypes.AccountInvitationDataManagerMock{}
		dataManager.On(
			"GetAccountInvitationByTokenAndID",
			testutils.ContextMatcher,
			helper.exampleAccountInvitation.Token,
			helper.exampleAccountInvitation.ID,
		).Return(helper.exampleAccountInvitation, nil)

		dataManager.On(
			"AcceptAccountInvitation",
			testutils.ContextMatcher,
			helper.exampleAccountInvitation.ID,
			helper.exampleAccountInvitation.Token,
			helper.exampleAccountInvitation.Note,
		).Return(nil)
		helper.service.accountInvitationDataManager = dataManager

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(nil)
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.AcceptInviteHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusAccepted, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, dataManager, dataChangesPublisher)
	})

	T.Run("with error fetching session context data", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.sessionContextDataFetcher = func(*http.Request) (*types.SessionContextData, error) {
			return nil, errors.New("blah")
		}

		helper.service.AcceptInviteHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with invalid input", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader([]byte("{ bad json lol")))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.service.AcceptInviteHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with invalid input", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := &types.AccountUpdateRequestInput{}
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.service.AcceptInviteHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with no matching invitation", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := converters.ConvertAccountInvitationToAccountInvitationUpdateInput(helper.exampleAccountInvitation)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		dataManager := &mocktypes.AccountInvitationDataManagerMock{}
		dataManager.On(
			"GetAccountInvitationByTokenAndID",
			testutils.ContextMatcher,
			helper.exampleAccountInvitation.Token,
			helper.exampleAccountInvitation.ID,
		).Return((*types.AccountInvitation)(nil), sql.ErrNoRows)
		helper.service.accountInvitationDataManager = dataManager

		helper.service.AcceptInviteHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusNotFound, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, dataManager)
	})

	T.Run("with error reading invitation", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := converters.ConvertAccountInvitationToAccountInvitationUpdateInput(helper.exampleAccountInvitation)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		dataManager := &mocktypes.AccountInvitationDataManagerMock{}
		dataManager.On(
			"GetAccountInvitationByTokenAndID",
			testutils.ContextMatcher,
			helper.exampleAccountInvitation.Token,
			helper.exampleAccountInvitation.ID,
		).Return((*types.AccountInvitation)(nil), errors.New("blah"))
		helper.service.accountInvitationDataManager = dataManager

		helper.service.AcceptInviteHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, dataManager)
	})

	T.Run("with error writing to database", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := converters.ConvertAccountInvitationToAccountInvitationUpdateInput(helper.exampleAccountInvitation)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		dataManager := &mocktypes.AccountInvitationDataManagerMock{}
		dataManager.On(
			"GetAccountInvitationByTokenAndID",
			testutils.ContextMatcher,
			helper.exampleAccountInvitation.Token,
			helper.exampleAccountInvitation.ID,
		).Return(helper.exampleAccountInvitation, nil)

		dataManager.On(
			"AcceptAccountInvitation",
			testutils.ContextMatcher,
			helper.exampleAccountInvitation.ID,
			helper.exampleAccountInvitation.Token,
			helper.exampleAccountInvitation.Note,
		).Return(errors.New("blah"))
		helper.service.accountInvitationDataManager = dataManager

		helper.service.AcceptInviteHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, dataManager)
	})

	T.Run("with error publishing service event", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := converters.ConvertAccountInvitationToAccountInvitationUpdateInput(helper.exampleAccountInvitation)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		dataManager := &mocktypes.AccountInvitationDataManagerMock{}
		dataManager.On(
			"GetAccountInvitationByTokenAndID",
			testutils.ContextMatcher,
			helper.exampleAccountInvitation.Token,
			helper.exampleAccountInvitation.ID,
		).Return(helper.exampleAccountInvitation, nil)

		dataManager.On(
			"AcceptAccountInvitation",
			testutils.ContextMatcher,
			helper.exampleAccountInvitation.ID,
			helper.exampleAccountInvitation.Token,
			helper.exampleAccountInvitation.Note,
		).Return(nil)
		helper.service.accountInvitationDataManager = dataManager

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(errors.New("blah"))
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.AcceptInviteHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusAccepted, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, dataManager, dataChangesPublisher)
	})
}

func Test_service_CancelInviteHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := converters.ConvertAccountInvitationToAccountInvitationUpdateInput(helper.exampleAccountInvitation)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		dataManager := &mocktypes.AccountInvitationDataManagerMock{}
		dataManager.On(
			"GetAccountInvitationByTokenAndID",
			testutils.ContextMatcher,
			helper.exampleAccountInvitation.Token,
			helper.exampleAccountInvitation.ID,
		).Return(helper.exampleAccountInvitation, nil)

		dataManager.On(
			"CancelAccountInvitation",
			testutils.ContextMatcher,
			helper.exampleAccountInvitation.ID,
			helper.exampleAccountInvitation.Note,
		).Return(nil)
		helper.service.accountInvitationDataManager = dataManager

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(nil)
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.CancelInviteHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusAccepted, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, dataManager, dataChangesPublisher)
	})

	T.Run("with invalid input", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := &types.AccountUpdateRequestInput{}
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.service.CancelInviteHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with unparseable input", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader([]byte("{ bad json lol")))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.service.CancelInviteHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with no rows returned", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := converters.ConvertAccountInvitationToAccountInvitationUpdateInput(helper.exampleAccountInvitation)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		dataManager := &mocktypes.AccountInvitationDataManagerMock{}
		dataManager.On(
			"GetAccountInvitationByTokenAndID",
			testutils.ContextMatcher,
			helper.exampleAccountInvitation.Token,
			helper.exampleAccountInvitation.ID,
		).Return((*types.AccountInvitation)(nil), sql.ErrNoRows)
		helper.service.accountInvitationDataManager = dataManager

		helper.service.CancelInviteHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusNotFound, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, dataManager)
	})

	T.Run("with error fetching invitation", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := converters.ConvertAccountInvitationToAccountInvitationUpdateInput(helper.exampleAccountInvitation)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		dataManager := &mocktypes.AccountInvitationDataManagerMock{}
		dataManager.On(
			"GetAccountInvitationByTokenAndID",
			testutils.ContextMatcher,
			helper.exampleAccountInvitation.Token,
			helper.exampleAccountInvitation.ID,
		).Return((*types.AccountInvitation)(nil), errors.New("blah"))
		helper.service.accountInvitationDataManager = dataManager

		helper.service.CancelInviteHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, dataManager)
	})

	T.Run("with error fetching session context data", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.sessionContextDataFetcher = func(*http.Request) (*types.SessionContextData, error) {
			return nil, errors.New("blah")
		}

		helper.service.CancelInviteHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with error writing to database", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := converters.ConvertAccountInvitationToAccountInvitationUpdateInput(helper.exampleAccountInvitation)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		dataManager := &mocktypes.AccountInvitationDataManagerMock{}
		dataManager.On(
			"GetAccountInvitationByTokenAndID",
			testutils.ContextMatcher,
			helper.exampleAccountInvitation.Token,
			helper.exampleAccountInvitation.ID,
		).Return(helper.exampleAccountInvitation, nil)

		dataManager.On(
			"CancelAccountInvitation",
			testutils.ContextMatcher,
			helper.exampleAccountInvitation.ID,
			helper.exampleAccountInvitation.Note,
		).Return(errors.New("blah"))
		helper.service.accountInvitationDataManager = dataManager

		helper.service.CancelInviteHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, dataManager)
	})

	T.Run("with error publishing service event", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := converters.ConvertAccountInvitationToAccountInvitationUpdateInput(helper.exampleAccountInvitation)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		dataManager := &mocktypes.AccountInvitationDataManagerMock{}
		dataManager.On(
			"GetAccountInvitationByTokenAndID",
			testutils.ContextMatcher,
			helper.exampleAccountInvitation.Token,
			helper.exampleAccountInvitation.ID,
		).Return(helper.exampleAccountInvitation, nil)

		dataManager.On(
			"CancelAccountInvitation",
			testutils.ContextMatcher,
			helper.exampleAccountInvitation.ID,
			helper.exampleAccountInvitation.Note,
		).Return(nil)
		helper.service.accountInvitationDataManager = dataManager

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(errors.New("blah"))
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.CancelInviteHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusAccepted, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, dataManager, dataChangesPublisher)
	})
}

func Test_service_RejectInviteHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := converters.ConvertAccountInvitationToAccountInvitationUpdateInput(helper.exampleAccountInvitation)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		dataManager := &mocktypes.AccountInvitationDataManagerMock{}
		dataManager.On(
			"GetAccountInvitationByTokenAndID",
			testutils.ContextMatcher,
			helper.exampleAccountInvitation.Token,
			helper.exampleAccountInvitation.ID,
		).Return(helper.exampleAccountInvitation, nil)

		dataManager.On(
			"RejectAccountInvitation",
			testutils.ContextMatcher,
			helper.exampleAccountInvitation.ID,
			helper.exampleAccountInvitation.Note,
		).Return(nil)
		helper.service.accountInvitationDataManager = dataManager

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(nil)
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.RejectInviteHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusAccepted, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, dataManager, dataChangesPublisher)
	})

	T.Run("with invalid input", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := &types.AccountInvitationUpdateRequestInput{}
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.service.RejectInviteHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with no rows returned", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := converters.ConvertAccountInvitationToAccountInvitationUpdateInput(helper.exampleAccountInvitation)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		dataManager := &mocktypes.AccountInvitationDataManagerMock{}
		dataManager.On(
			"GetAccountInvitationByTokenAndID",
			testutils.ContextMatcher,
			helper.exampleAccountInvitation.Token,
			helper.exampleAccountInvitation.ID,
		).Return((*types.AccountInvitation)(nil), sql.ErrNoRows)
		helper.service.accountInvitationDataManager = dataManager

		helper.service.RejectInviteHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusNotFound, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, dataManager)
	})

	T.Run("with error fetching invitation", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := converters.ConvertAccountInvitationToAccountInvitationUpdateInput(helper.exampleAccountInvitation)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		dataManager := &mocktypes.AccountInvitationDataManagerMock{}
		dataManager.On(
			"GetAccountInvitationByTokenAndID",
			testutils.ContextMatcher,
			helper.exampleAccountInvitation.Token,
			helper.exampleAccountInvitation.ID,
		).Return((*types.AccountInvitation)(nil), errors.New("blah"))

		helper.service.accountInvitationDataManager = dataManager

		helper.service.RejectInviteHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, dataManager)
	})

	T.Run("with error fetching session context data", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.sessionContextDataFetcher = func(*http.Request) (*types.SessionContextData, error) {
			return nil, errors.New("blah")
		}

		helper.service.RejectInviteHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with invalid input", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader([]byte("{ bad json lol")))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.service.RejectInviteHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with error writing to database", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := converters.ConvertAccountInvitationToAccountInvitationUpdateInput(helper.exampleAccountInvitation)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		dataManager := &mocktypes.AccountInvitationDataManagerMock{}
		dataManager.On(
			"GetAccountInvitationByTokenAndID",
			testutils.ContextMatcher,
			helper.exampleAccountInvitation.Token,
			helper.exampleAccountInvitation.ID,
		).Return(helper.exampleAccountInvitation, nil)

		dataManager.On(
			"RejectAccountInvitation",
			testutils.ContextMatcher,
			helper.exampleAccountInvitation.ID,
			helper.exampleAccountInvitation.Note,
		).Return(errors.New("blah"))
		helper.service.accountInvitationDataManager = dataManager

		helper.service.RejectInviteHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, dataManager)
	})

	T.Run("with error publishing service event", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := converters.ConvertAccountInvitationToAccountInvitationUpdateInput(helper.exampleAccountInvitation)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		dataManager := &mocktypes.AccountInvitationDataManagerMock{}
		dataManager.On(
			"GetAccountInvitationByTokenAndID",
			testutils.ContextMatcher,
			helper.exampleAccountInvitation.Token,
			helper.exampleAccountInvitation.ID,
		).Return(helper.exampleAccountInvitation, nil)

		dataManager.On(
			"RejectAccountInvitation",
			testutils.ContextMatcher,
			helper.exampleAccountInvitation.ID,
			helper.exampleAccountInvitation.Note,
		).Return(nil)
		helper.service.accountInvitationDataManager = dataManager

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(errors.New("blah"))
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.RejectInviteHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusAccepted, helper.res.Code)
		var actual *types.APIResponse[*types.AccountInvitation]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, dataManager, dataChangesPublisher)
	})
}
