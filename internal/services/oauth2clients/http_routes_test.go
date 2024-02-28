package oauth2clients

import (
	"bytes"
	"database/sql"
	"errors"
	"net/http"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/internal/database"
	"github.com/verygoodsoftwarenotvirus/starter/internal/encoding"
	mockpublishers "github.com/verygoodsoftwarenotvirus/starter/internal/messagequeue/mock"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	randommock "github.com/verygoodsoftwarenotvirus/starter/internal/pkg/random/mock"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"
	mocktypes "github.com/verygoodsoftwarenotvirus/starter/pkg/types/mock"
	testutils "github.com/verygoodsoftwarenotvirus/starter/tests/utils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var oauth2ClientCreationInputMatcher any = mock.MatchedBy(func(input *types.OAuth2ClientDatabaseCreationInput) bool {
	return true
})

func TestOAuth2ClientsService_CreateHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, helper.exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)
		helper.service.userDataManager = mockDB

		sg := &randommock.Generator{}
		sg.On(
			"GenerateHexEncodedString",
			testutils.ContextMatcher,
			clientIDSize,
		).Return(helper.exampleOAuth2Client.ClientID, nil)
		sg.On(
			"GenerateHexEncodedString",
			testutils.ContextMatcher,
			clientSecretSize,
		).Return(helper.exampleOAuth2Client.ClientSecret, nil)
		helper.service.secretGenerator = sg

		mockDB.OAuth2ClientDataManagerMock.On(
			"CreateOAuth2Client",
			testutils.ContextMatcher,
			oauth2ClientCreationInputMatcher,
		).Return(helper.exampleOAuth2Client, nil)
		helper.service.oauth2ClientDataManager = mockDB

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(nil)
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.CreateHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusCreated, helper.res.Code)
		var actual *types.APIResponse[*types.OAuth2ClientCreationResponse]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NotEmpty(t, actual.Data)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, mockDB, sg, dataChangesPublisher)
	})

	T.Run("with error retrieving session context data", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.sessionContextDataFetcher = testutils.BrokenSessionContextDataFetcher
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		helper.service.CreateHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)
		var actual *types.APIResponse[*types.OAuth2Client]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("without input attached to request", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(nil))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.service.CreateHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		var actual *types.APIResponse[*types.OAuth2Client]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with invalid input attached to request", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		helper.exampleInput.Name = ""
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, helper.exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.service.CreateHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		var actual *types.APIResponse[*types.OAuth2Client]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with error generating client ID", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, helper.exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)

		sg := &randommock.Generator{}
		sg.On(
			"GenerateHexEncodedString",
			testutils.ContextMatcher,
			clientIDSize,
		).Return("", errors.New("blah"))
		helper.service.secretGenerator = sg

		mockDB.OAuth2ClientDataManagerMock.On(
			"CreateOAuth2Client",
			testutils.ContextMatcher,
			oauth2ClientCreationInputMatcher,
		).Return(helper.exampleOAuth2Client, nil)

		helper.service.oauth2ClientDataManager = mockDB
		helper.service.userDataManager = mockDB

		helper.service.CreateHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.OAuth2Client]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockDB, sg)
	})

	T.Run("with error generating client secret", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, helper.exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)
		helper.service.userDataManager = mockDB

		sg := &randommock.Generator{}
		sg.On(
			"GenerateHexEncodedString",
			testutils.ContextMatcher,
			clientIDSize,
		).Return(helper.exampleOAuth2Client.ClientID, nil).Return("", errors.New("blah"))
		helper.service.secretGenerator = sg

		mockDB.OAuth2ClientDataManagerMock.On(
			"CreateOAuth2Client",
			testutils.ContextMatcher,
			oauth2ClientCreationInputMatcher,
		).Return(helper.exampleOAuth2Client, nil)
		helper.service.oauth2ClientDataManager = mockDB

		helper.service.CreateHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.OAuth2Client]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockDB, sg)
	})

	T.Run("with error creating OAuth2 client in data store", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, helper.exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)

		sg := &randommock.Generator{}
		sg.On(
			"GenerateHexEncodedString",
			testutils.ContextMatcher,
			clientIDSize,
		).Return(helper.exampleOAuth2Client.ClientID, nil)
		sg.On(
			"GenerateHexEncodedString",
			testutils.ContextMatcher,
			clientSecretSize,
		).Return(helper.exampleOAuth2Client.ClientSecret, nil)
		helper.service.secretGenerator = sg

		mockDB.OAuth2ClientDataManagerMock.On(
			"CreateOAuth2Client",
			testutils.ContextMatcher,
			oauth2ClientCreationInputMatcher,
		).Return((*types.OAuth2Client)(nil), errors.New("blah"))

		helper.service.oauth2ClientDataManager = mockDB
		helper.service.userDataManager = mockDB

		helper.service.CreateHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.OAuth2Client]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockDB, sg)
	})

	T.Run("with error publishing service event", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, helper.exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)
		helper.service.userDataManager = mockDB

		sg := &randommock.Generator{}
		sg.On(
			"GenerateHexEncodedString",
			testutils.ContextMatcher,
			clientIDSize,
		).Return(helper.exampleOAuth2Client.ClientID, nil)
		sg.On(
			"GenerateHexEncodedString",
			testutils.ContextMatcher,
			clientSecretSize,
		).Return(helper.exampleOAuth2Client.ClientSecret, nil)
		helper.service.secretGenerator = sg

		mockDB.OAuth2ClientDataManagerMock.On(
			"CreateOAuth2Client",
			testutils.ContextMatcher,
			oauth2ClientCreationInputMatcher,
		).Return(helper.exampleOAuth2Client, nil)
		helper.service.oauth2ClientDataManager = mockDB

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(errors.New("blah"))
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.CreateHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusCreated, helper.res.Code)
		var actual *types.APIResponse[*types.OAuth2ClientCreationResponse]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NotEmpty(t, actual.Data)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, mockDB, sg, dataChangesPublisher)
	})
}

func TestOAuth2ClientsService_ReadHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		oauth2ClientDataManager := &mocktypes.OAuth2ClientDataManagerMock{}
		oauth2ClientDataManager.On(
			"GetOAuth2ClientByDatabaseID",
			testutils.ContextMatcher,
			helper.exampleOAuth2Client.ID,
		).Return(helper.exampleOAuth2Client, nil)
		helper.service.oauth2ClientDataManager = oauth2ClientDataManager

		helper.service.ReadHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusOK, helper.res.Code)
		var actual *types.APIResponse[*types.OAuth2Client]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Equal(t, actual.Data, helper.exampleOAuth2Client)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, oauth2ClientDataManager)
	})

	T.Run("with error retrieving session context data", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.sessionContextDataFetcher = testutils.BrokenSessionContextDataFetcher

		helper.service.ReadHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)
		var actual *types.APIResponse[*types.OAuth2Client]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with no such OAuth2 client in the database", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		oauth2ClientDataManager := &mocktypes.OAuth2ClientDataManagerMock{}
		oauth2ClientDataManager.On(
			"GetOAuth2ClientByDatabaseID",
			testutils.ContextMatcher,
			helper.exampleOAuth2Client.ID,
		).Return((*types.OAuth2Client)(nil), sql.ErrNoRows)
		helper.service.oauth2ClientDataManager = oauth2ClientDataManager

		helper.service.ReadHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusNotFound, helper.res.Code)
		var actual *types.APIResponse[*types.OAuth2Client]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, oauth2ClientDataManager)
	})

	T.Run("with error fetching from database", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		oauth2ClientDataManager := &mocktypes.OAuth2ClientDataManagerMock{}
		oauth2ClientDataManager.On(
			"GetOAuth2ClientByDatabaseID",
			testutils.ContextMatcher,
			helper.exampleOAuth2Client.ID,
		).Return((*types.OAuth2Client)(nil), errors.New("blah"))
		helper.service.oauth2ClientDataManager = oauth2ClientDataManager

		helper.service.ReadHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.OAuth2Client]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, oauth2ClientDataManager)
	})
}

func TestOAuth2ClientsService_ListHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		exampleOAuth2ClientList := fakes.BuildFakeOAuth2ClientList()

		mockDB := database.NewMockDatabase()
		mockDB.OAuth2ClientDataManagerMock.On(
			"GetOAuth2Clients",
			testutils.ContextMatcher,
			mock.IsType(&types.QueryFilter{}),
		).Return(exampleOAuth2ClientList, nil)
		helper.service.oauth2ClientDataManager = mockDB

		helper.service.ListHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusOK, helper.res.Code)
		var actual *types.APIResponse[[]*types.OAuth2Client]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Equal(t, actual.Data, exampleOAuth2ClientList.Data)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, mockDB)
	})

	T.Run("with error retrieving session context data", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.sessionContextDataFetcher = testutils.BrokenSessionContextDataFetcher

		helper.service.ListHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)
		var actual *types.APIResponse[*types.OAuth2Client]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with no results returned from datastore", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		mockDB := database.NewMockDatabase()
		mockDB.OAuth2ClientDataManagerMock.On(
			"GetOAuth2Clients",
			testutils.ContextMatcher,
			mock.IsType(&types.QueryFilter{}),
		).Return((*types.QueryFilteredResult[types.OAuth2Client])(nil), sql.ErrNoRows)
		helper.service.oauth2ClientDataManager = mockDB
		helper.service.userDataManager = mockDB

		helper.service.ListHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusOK, helper.res.Code)
		var actual *types.APIResponse[[]*types.OAuth2Client]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, mockDB)
	})

	T.Run("with error retrieving clients from the datastore", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		mockDB := database.NewMockDatabase()
		mockDB.OAuth2ClientDataManagerMock.On(
			"GetOAuth2Clients",
			testutils.ContextMatcher,
			mock.IsType(&types.QueryFilter{}),
		).Return((*types.QueryFilteredResult[types.OAuth2Client])(nil), errors.New("blah"))
		helper.service.oauth2ClientDataManager = mockDB
		helper.service.userDataManager = mockDB

		helper.service.ListHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.OAuth2Client]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockDB)
	})
}

func TestOAuth2ClientsService_ArchiveHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		oauth2ClientDataManager := &mocktypes.OAuth2ClientDataManagerMock{}
		oauth2ClientDataManager.On(
			"ArchiveOAuth2Client",
			testutils.ContextMatcher,
			helper.exampleOAuth2Client.ID,
		).Return(nil)
		helper.service.oauth2ClientDataManager = oauth2ClientDataManager

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(nil)
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.ArchiveHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusOK, helper.res.Code)
		var actual *types.APIResponse[*types.OAuth2Client]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, oauth2ClientDataManager, dataChangesPublisher)
	})

	T.Run("with error retrieving session context data", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.sessionContextDataFetcher = testutils.BrokenSessionContextDataFetcher

		helper.service.ArchiveHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)
		var actual *types.APIResponse[*types.OAuth2Client]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with no such OAuth2 client in the database", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		oauth2ClientDataManager := &mocktypes.OAuth2ClientDataManagerMock{}
		oauth2ClientDataManager.On(
			"ArchiveOAuth2Client",
			testutils.ContextMatcher,
			helper.exampleOAuth2Client.ID,
		).Return(sql.ErrNoRows)
		helper.service.oauth2ClientDataManager = oauth2ClientDataManager

		helper.service.ArchiveHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusNotFound, helper.res.Code)
		var actual *types.APIResponse[*types.OAuth2Client]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, oauth2ClientDataManager)
	})

	T.Run("with error fetching from database", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		oauth2ClientDataManager := &mocktypes.OAuth2ClientDataManagerMock{}
		oauth2ClientDataManager.On(
			"ArchiveOAuth2Client",
			testutils.ContextMatcher,
			helper.exampleOAuth2Client.ID,
		).Return(errors.New("blah"))
		helper.service.oauth2ClientDataManager = oauth2ClientDataManager

		helper.service.ArchiveHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.OAuth2Client]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, oauth2ClientDataManager)
	})

	T.Run("with error publishing service event", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		oauth2ClientDataManager := &mocktypes.OAuth2ClientDataManagerMock{}
		oauth2ClientDataManager.On(
			"ArchiveOAuth2Client",
			testutils.ContextMatcher,
			helper.exampleOAuth2Client.ID,
		).Return(nil)
		helper.service.oauth2ClientDataManager = oauth2ClientDataManager

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(errors.New("blah"))
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.ArchiveHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusOK, helper.res.Code)
		var actual *types.APIResponse[*types.OAuth2Client]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, oauth2ClientDataManager, dataChangesPublisher)
	})
}
