package servicesettingconfigurations

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
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"
	mocktypes "github.com/verygoodsoftwarenotvirus/starter/pkg/types/mock"
	testutils "github.com/verygoodsoftwarenotvirus/starter/tests/utils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestServiceSettingConfigurationsService_CreateHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleCreationInput := fakes.BuildFakeServiceSettingConfigurationCreationRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleCreationInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		dbManager := database.NewMockDatabase()
		dbManager.ServiceSettingConfigurationDataManagerMock.On(
			"CreateServiceSettingConfiguration",
			testutils.ContextMatcher,
			mock.MatchedBy(func(*types.ServiceSettingConfigurationDatabaseCreationInput) bool { return true }),
		).Return(helper.exampleServiceSettingConfiguration, nil)
		helper.service.serviceSettingConfigurationDataManager = dbManager

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(nil)
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.CreateHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusCreated, helper.res.Code)
		var actual *types.APIResponse[*types.ServiceSettingConfiguration]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Equal(t, actual.Data, helper.exampleServiceSettingConfiguration)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, dbManager, dataChangesPublisher)
	})

	T.Run("without input attached", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(nil))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.service.CreateHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		var actual *types.APIResponse[*types.ServiceSettingConfiguration]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with invalid input attached", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleCreationInput := &types.ServiceSettingConfigurationCreationRequestInput{}
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleCreationInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.service.CreateHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		var actual *types.APIResponse[*types.ServiceSettingConfiguration]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with error retrieving session context data", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleCreationInput := fakes.BuildFakeServiceSettingConfigurationCreationRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleCreationInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.service.sessionContextDataFetcher = testutils.BrokenSessionContextDataFetcher

		helper.service.CreateHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)
		var actual *types.APIResponse[*types.ServiceSettingConfiguration]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with error writing to database", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleCreationInput := fakes.BuildFakeServiceSettingConfigurationCreationRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleCreationInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		dbManager := database.NewMockDatabase()
		dbManager.ServiceSettingConfigurationDataManagerMock.On(
			"CreateServiceSettingConfiguration",
			testutils.ContextMatcher,
			mock.MatchedBy(func(*types.ServiceSettingConfigurationDatabaseCreationInput) bool { return true }),
		).Return((*types.ServiceSettingConfiguration)(nil), errors.New("blah"))
		helper.service.serviceSettingConfigurationDataManager = dbManager

		helper.service.CreateHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.ServiceSettingConfiguration]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, dbManager)
	})

	T.Run("with error publishing event", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleCreationInput := fakes.BuildFakeServiceSettingConfigurationCreationRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleCreationInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		dbManager := database.NewMockDatabase()
		dbManager.ServiceSettingConfigurationDataManagerMock.On(
			"CreateServiceSettingConfiguration",
			testutils.ContextMatcher,
			mock.MatchedBy(func(*types.ServiceSettingConfigurationDatabaseCreationInput) bool { return true }),
		).Return(helper.exampleServiceSettingConfiguration, nil)
		helper.service.serviceSettingConfigurationDataManager = dbManager

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(errors.New("blah"))
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.CreateHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusCreated, helper.res.Code)
		var actual *types.APIResponse[*types.ServiceSettingConfiguration]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Equal(t, actual.Data, helper.exampleServiceSettingConfiguration)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, dbManager, dataChangesPublisher)
	})
}

func TestServiceSettingConfigurationsService_ByNameHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		serviceSettingConfigurationDataManager := &mocktypes.ServiceSettingConfigurationDataManagerMock{}
		serviceSettingConfigurationDataManager.On(
			"GetServiceSettingConfigurationForUserByName",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			helper.exampleServiceSettingConfiguration.ServiceSetting.Name,
		).Return(helper.exampleServiceSettingConfiguration, nil)
		helper.service.serviceSettingConfigurationDataManager = serviceSettingConfigurationDataManager

		helper.service.ForUserByNameHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusOK, helper.res.Code)
		var actual *types.APIResponse[*types.ServiceSettingConfiguration]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Equal(t, actual.Data, helper.exampleServiceSettingConfiguration)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, serviceSettingConfigurationDataManager)
	})

	T.Run("with error retrieving session context data", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.sessionContextDataFetcher = testutils.BrokenSessionContextDataFetcher

		helper.service.ForUserByNameHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)
		var actual *types.APIResponse[*types.ServiceSettingConfiguration]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with no such service setting configuration in the database", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		serviceSettingConfigurationDataManager := &mocktypes.ServiceSettingConfigurationDataManagerMock{}
		serviceSettingConfigurationDataManager.On(
			"GetServiceSettingConfigurationForUserByName",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			helper.exampleServiceSettingConfiguration.ServiceSetting.Name,
		).Return((*types.ServiceSettingConfiguration)(nil), sql.ErrNoRows)
		helper.service.serviceSettingConfigurationDataManager = serviceSettingConfigurationDataManager

		helper.service.ForUserByNameHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusNotFound, helper.res.Code)
		var actual *types.APIResponse[*types.ServiceSettingConfiguration]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, serviceSettingConfigurationDataManager)
	})

	T.Run("with error fetching from database", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		serviceSettingConfigurationDataManager := &mocktypes.ServiceSettingConfigurationDataManagerMock{}
		serviceSettingConfigurationDataManager.On(
			"GetServiceSettingConfigurationForUserByName",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			helper.exampleServiceSettingConfiguration.ServiceSetting.Name,
		).Return((*types.ServiceSettingConfiguration)(nil), errors.New("blah"))
		helper.service.serviceSettingConfigurationDataManager = serviceSettingConfigurationDataManager

		helper.service.ForUserByNameHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.ServiceSettingConfiguration]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, serviceSettingConfigurationDataManager)
	})
}

func TestServiceSettingConfigurationsService_ForUserHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		serviceSettingConfigurationDataManager := &mocktypes.ServiceSettingConfigurationDataManagerMock{}
		serviceSettingConfigurationDataManager.On(
			"GetServiceSettingConfigurationsForUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			testutils.QueryFilterMatcher,
		).Return(helper.exampleServiceSettingConfigurationList, nil)
		helper.service.serviceSettingConfigurationDataManager = serviceSettingConfigurationDataManager

		helper.service.ForUserHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusOK, helper.res.Code)
		var actual *types.APIResponse[[]*types.ServiceSettingConfiguration]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Equal(t, actual.Data, helper.exampleServiceSettingConfigurationList.Data)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, serviceSettingConfigurationDataManager)
	})

	T.Run("with error retrieving session context data", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.sessionContextDataFetcher = testutils.BrokenSessionContextDataFetcher

		helper.service.ForUserHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)
		var actual *types.APIResponse[*types.ServiceSettingConfiguration]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with no such service setting configuration in the database", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		serviceSettingConfigurationDataManager := &mocktypes.ServiceSettingConfigurationDataManagerMock{}
		serviceSettingConfigurationDataManager.On(
			"GetServiceSettingConfigurationsForUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			testutils.QueryFilterMatcher,
		).Return((*types.QueryFilteredResult[types.ServiceSettingConfiguration])(nil), sql.ErrNoRows)
		helper.service.serviceSettingConfigurationDataManager = serviceSettingConfigurationDataManager

		helper.service.ForUserHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusNotFound, helper.res.Code)
		var actual *types.APIResponse[*types.ServiceSettingConfiguration]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, serviceSettingConfigurationDataManager)
	})

	T.Run("with error fetching from database", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		serviceSettingConfigurationDataManager := &mocktypes.ServiceSettingConfigurationDataManagerMock{}
		serviceSettingConfigurationDataManager.On(
			"GetServiceSettingConfigurationsForUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			testutils.QueryFilterMatcher,
		).Return((*types.QueryFilteredResult[types.ServiceSettingConfiguration])(nil), errors.New("blah"))
		helper.service.serviceSettingConfigurationDataManager = serviceSettingConfigurationDataManager

		helper.service.ForUserHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.ServiceSettingConfiguration]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, serviceSettingConfigurationDataManager)
	})
}

func TestServiceSettingConfigurationsService_ForAccountHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		serviceSettingConfigurationDataManager := &mocktypes.ServiceSettingConfigurationDataManagerMock{}
		serviceSettingConfigurationDataManager.On(
			"GetServiceSettingConfigurationsForAccount",
			testutils.ContextMatcher,
			helper.exampleAccount.ID,
			testutils.QueryFilterMatcher,
		).Return(helper.exampleServiceSettingConfigurationList, nil)
		helper.service.serviceSettingConfigurationDataManager = serviceSettingConfigurationDataManager

		helper.service.ForAccountHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusOK, helper.res.Code)
		var actual *types.APIResponse[[]*types.ServiceSettingConfiguration]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Equal(t, actual.Data, helper.exampleServiceSettingConfigurationList.Data)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, serviceSettingConfigurationDataManager)
	})

	T.Run("with error retrieving session context data", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.sessionContextDataFetcher = testutils.BrokenSessionContextDataFetcher

		helper.service.ForAccountHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)
		var actual *types.APIResponse[*types.ServiceSettingConfiguration]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with no such service setting configuration in the database", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		serviceSettingConfigurationDataManager := &mocktypes.ServiceSettingConfigurationDataManagerMock{}
		serviceSettingConfigurationDataManager.On(
			"GetServiceSettingConfigurationsForAccount",
			testutils.ContextMatcher,
			helper.exampleAccount.ID,
			testutils.QueryFilterMatcher,
		).Return((*types.QueryFilteredResult[types.ServiceSettingConfiguration])(nil), sql.ErrNoRows)
		helper.service.serviceSettingConfigurationDataManager = serviceSettingConfigurationDataManager

		helper.service.ForAccountHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusNotFound, helper.res.Code)
		var actual *types.APIResponse[*types.ServiceSettingConfiguration]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, serviceSettingConfigurationDataManager)
	})

	T.Run("with error fetching from database", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		serviceSettingConfigurationDataManager := &mocktypes.ServiceSettingConfigurationDataManagerMock{}
		serviceSettingConfigurationDataManager.On(
			"GetServiceSettingConfigurationsForAccount",
			testutils.ContextMatcher,
			helper.exampleAccount.ID,
			testutils.QueryFilterMatcher,
		).Return((*types.QueryFilteredResult[types.ServiceSettingConfiguration])(nil), errors.New("blah"))
		helper.service.serviceSettingConfigurationDataManager = serviceSettingConfigurationDataManager

		helper.service.ForAccountHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.ServiceSettingConfiguration]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, serviceSettingConfigurationDataManager)
	})
}

func TestServiceSettingConfigurationsService_UpdateHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleCreationInput := fakes.BuildFakeServiceSettingConfigurationUpdateRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleCreationInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		dbManager := database.NewMockDatabase()
		dbManager.ServiceSettingConfigurationDataManagerMock.On(
			"GetServiceSettingConfiguration",
			testutils.ContextMatcher,
			helper.exampleServiceSettingConfiguration.ID,
		).Return(helper.exampleServiceSettingConfiguration, nil)

		dbManager.ServiceSettingConfigurationDataManagerMock.On(
			"UpdateServiceSettingConfiguration",
			testutils.ContextMatcher,
			mock.MatchedBy(func(*types.ServiceSettingConfiguration) bool { return true }),
		).Return(nil)
		helper.service.serviceSettingConfigurationDataManager = dbManager

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(nil)
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.UpdateHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusOK, helper.res.Code)
		var actual *types.APIResponse[*types.ServiceSettingConfiguration]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Equal(t, actual.Data, helper.exampleServiceSettingConfiguration)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, dbManager, dataChangesPublisher)
	})

	T.Run("with invalid input", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleCreationInput := &types.ServiceSettingConfigurationUpdateRequestInput{}
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleCreationInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.service.UpdateHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		var actual *types.APIResponse[*types.ServiceSettingConfiguration]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with error retrieving session context data", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.sessionContextDataFetcher = testutils.BrokenSessionContextDataFetcher

		helper.service.UpdateHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)
		var actual *types.APIResponse[*types.ServiceSettingConfiguration]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("without input attached to context", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(nil))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.service.UpdateHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		var actual *types.APIResponse[*types.ServiceSettingConfiguration]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with no such service setting configuration", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleCreationInput := fakes.BuildFakeServiceSettingConfigurationUpdateRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleCreationInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		serviceSettingConfigurationDataManager := &mocktypes.ServiceSettingConfigurationDataManagerMock{}
		serviceSettingConfigurationDataManager.On(
			"GetServiceSettingConfiguration",
			testutils.ContextMatcher,
			helper.exampleServiceSettingConfiguration.ID,
		).Return((*types.ServiceSettingConfiguration)(nil), sql.ErrNoRows)
		helper.service.serviceSettingConfigurationDataManager = serviceSettingConfigurationDataManager

		helper.service.UpdateHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusNotFound, helper.res.Code)
		var actual *types.APIResponse[*types.ServiceSettingConfiguration]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, serviceSettingConfigurationDataManager)
	})

	T.Run("with error retrieving service setting configuration from database", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleCreationInput := fakes.BuildFakeServiceSettingConfigurationUpdateRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleCreationInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		serviceSettingConfigurationDataManager := &mocktypes.ServiceSettingConfigurationDataManagerMock{}
		serviceSettingConfigurationDataManager.On(
			"GetServiceSettingConfiguration",
			testutils.ContextMatcher,
			helper.exampleServiceSettingConfiguration.ID,
		).Return((*types.ServiceSettingConfiguration)(nil), errors.New("blah"))
		helper.service.serviceSettingConfigurationDataManager = serviceSettingConfigurationDataManager

		helper.service.UpdateHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.ServiceSettingConfiguration]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, serviceSettingConfigurationDataManager)
	})

	T.Run("with problem writing to database", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleCreationInput := fakes.BuildFakeServiceSettingConfigurationUpdateRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleCreationInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		dbManager := database.NewMockDatabase()
		dbManager.ServiceSettingConfigurationDataManagerMock.On(
			"GetServiceSettingConfiguration",
			testutils.ContextMatcher,
			helper.exampleServiceSettingConfiguration.ID,
		).Return(helper.exampleServiceSettingConfiguration, nil)

		dbManager.ServiceSettingConfigurationDataManagerMock.On(
			"UpdateServiceSettingConfiguration",
			testutils.ContextMatcher,
			mock.MatchedBy(func(*types.ServiceSettingConfiguration) bool { return true }),
		).Return(errors.New("blah"))
		helper.service.serviceSettingConfigurationDataManager = dbManager

		helper.service.UpdateHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.ServiceSettingConfiguration]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, dbManager)
	})

	T.Run("with error publishing to message queue", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleCreationInput := fakes.BuildFakeServiceSettingConfigurationUpdateRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleCreationInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		dbManager := database.NewMockDatabase()
		dbManager.ServiceSettingConfigurationDataManagerMock.On(
			"GetServiceSettingConfiguration",
			testutils.ContextMatcher,
			helper.exampleServiceSettingConfiguration.ID,
		).Return(helper.exampleServiceSettingConfiguration, nil)

		dbManager.ServiceSettingConfigurationDataManagerMock.On(
			"UpdateServiceSettingConfiguration",
			testutils.ContextMatcher,
			mock.MatchedBy(func(*types.ServiceSettingConfiguration) bool { return true }),
		).Return(nil)
		helper.service.serviceSettingConfigurationDataManager = dbManager

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(errors.New("blah"))
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.UpdateHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusOK, helper.res.Code)
		var actual *types.APIResponse[*types.ServiceSettingConfiguration]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Equal(t, actual.Data, helper.exampleServiceSettingConfiguration)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, dbManager, dataChangesPublisher)
	})
}

func TestServiceSettingConfigurationsService_ArchiveHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		dbManager := database.NewMockDatabase()
		dbManager.ServiceSettingConfigurationDataManagerMock.On(
			"ServiceSettingConfigurationExists",
			testutils.ContextMatcher,
			helper.exampleServiceSettingConfiguration.ID,
		).Return(true, nil)

		dbManager.ServiceSettingConfigurationDataManagerMock.On(
			"ArchiveServiceSettingConfiguration",
			testutils.ContextMatcher,
			helper.exampleServiceSettingConfiguration.ID,
		).Return(nil)
		helper.service.serviceSettingConfigurationDataManager = dbManager

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(nil)
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.ArchiveHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusOK, helper.res.Code)
		var actual *types.APIResponse[*types.ServiceSettingConfiguration]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, dbManager, dataChangesPublisher)
	})

	T.Run("with error retrieving session context data", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.sessionContextDataFetcher = testutils.BrokenSessionContextDataFetcher

		helper.service.ArchiveHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)
		var actual *types.APIResponse[*types.ServiceSettingConfiguration]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with no such service setting configuration in the database", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		serviceSettingConfigurationDataManager := &mocktypes.ServiceSettingConfigurationDataManagerMock{}
		serviceSettingConfigurationDataManager.On(
			"ServiceSettingConfigurationExists",
			testutils.ContextMatcher,
			helper.exampleServiceSettingConfiguration.ID,
		).Return(false, nil)
		helper.service.serviceSettingConfigurationDataManager = serviceSettingConfigurationDataManager

		helper.service.ArchiveHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusNotFound, helper.res.Code)
		var actual *types.APIResponse[*types.ServiceSettingConfiguration]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, serviceSettingConfigurationDataManager)
	})

	T.Run("with error checking for item in database", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		serviceSettingConfigurationDataManager := &mocktypes.ServiceSettingConfigurationDataManagerMock{}
		serviceSettingConfigurationDataManager.On(
			"ServiceSettingConfigurationExists",
			testutils.ContextMatcher,
			helper.exampleServiceSettingConfiguration.ID,
		).Return(false, errors.New("blah"))
		helper.service.serviceSettingConfigurationDataManager = serviceSettingConfigurationDataManager

		helper.service.ArchiveHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.ServiceSettingConfiguration]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, serviceSettingConfigurationDataManager)
	})

	T.Run("with error writing to database", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		dbManager := database.NewMockDatabase()
		dbManager.ServiceSettingConfigurationDataManagerMock.On(
			"ServiceSettingConfigurationExists",
			testutils.ContextMatcher,
			helper.exampleServiceSettingConfiguration.ID,
		).Return(true, nil)

		dbManager.ServiceSettingConfigurationDataManagerMock.On(
			"ArchiveServiceSettingConfiguration",
			testutils.ContextMatcher,
			helper.exampleServiceSettingConfiguration.ID,
		).Return(errors.New("blah"))
		helper.service.serviceSettingConfigurationDataManager = dbManager

		helper.service.ArchiveHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.ServiceSettingConfiguration]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, dbManager)
	})

	T.Run("with error publishing to message queue", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		dbManager := database.NewMockDatabase()
		dbManager.ServiceSettingConfigurationDataManagerMock.On(
			"ServiceSettingConfigurationExists",
			testutils.ContextMatcher,
			helper.exampleServiceSettingConfiguration.ID,
		).Return(true, nil)

		dbManager.ServiceSettingConfigurationDataManagerMock.On(
			"ArchiveServiceSettingConfiguration",
			testutils.ContextMatcher,
			helper.exampleServiceSettingConfiguration.ID,
		).Return(nil)
		helper.service.serviceSettingConfigurationDataManager = dbManager

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(errors.New("blah"))
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.ArchiveHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusOK, helper.res.Code)
		var actual *types.APIResponse[*types.ServiceSettingConfiguration]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, dbManager, dataChangesPublisher)
	})
}
