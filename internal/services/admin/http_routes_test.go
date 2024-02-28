package admin

import (
	"bytes"
	"database/sql"
	"errors"
	"net/http"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/internal/authorization"
	"github.com/verygoodsoftwarenotvirus/starter/internal/encoding"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	mocktypes "github.com/verygoodsoftwarenotvirus/starter/pkg/types/mock"
	testutils "github.com/verygoodsoftwarenotvirus/starter/tests/utils"

	"github.com/alexedwards/scs/v2/mockstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestAdminService_UserAccountStatusChangeHandler(T *testing.T) {
	T.Parallel()

	T.Run("banning users", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		helper.exampleInput.NewStatus = string(types.BannedUserAccountStatus)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, helper.exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		userDataManager := &mocktypes.AdminUserDataManagerMock{}
		userDataManager.On(
			"UpdateUserAccountStatus",
			testutils.ContextMatcher,
			helper.exampleInput.TargetUserID,
			helper.exampleInput,
		).Return(nil)
		helper.service.userDB = userDataManager

		helper.service.UserAccountStatusChangeHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusAccepted, helper.res.Code)

		mock.AssertExpectationsForObjects(t, userDataManager)
	})

	T.Run("without adequate permission", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		sessionCtxData := &types.SessionContextData{
			Requester: types.RequesterInfo{
				ServicePermissions: authorization.NewServiceRolePermissionChecker(),
			},
			AccountPermissions: map[string]authorization.AccountRolePermissionsChecker{},
		}
		helper.service.sessionContextDataFetcher = func(*http.Request) (*types.SessionContextData, error) {
			return sessionCtxData, nil
		}

		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		helper.exampleInput.NewStatus = string(types.BannedUserAccountStatus)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, helper.exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.service.UserAccountStatusChangeHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusForbidden, helper.res.Code)
	})

	T.Run("back in good standing", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		helper.exampleInput.NewStatus = string(types.GoodStandingUserAccountStatus)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, helper.exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		userDataManager := &mocktypes.AdminUserDataManagerMock{}
		userDataManager.On(
			"UpdateUserAccountStatus",
			testutils.ContextMatcher,
			helper.exampleInput.TargetUserID,
			helper.exampleInput,
		).Return(nil)
		helper.service.userDB = userDataManager

		helper.service.UserAccountStatusChangeHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusAccepted, helper.res.Code)

		mock.AssertExpectationsForObjects(t, userDataManager)
	})

	T.Run("with error fetching session context data", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.sessionContextDataFetcher = testutils.BrokenSessionContextDataFetcher

		helper.exampleInput.NewStatus = string(types.BannedUserAccountStatus)

		helper.service.UserAccountStatusChangeHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)
		var actual *types.APIResponse[*types.Webhook]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with no input attached to request", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(nil))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.service.UserAccountStatusChangeHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		var actual *types.APIResponse[any]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with invalid input attached to request", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		helper.exampleInput = &types.UserAccountStatusUpdateInput{}
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, helper.exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.service.UserAccountStatusChangeHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		var actual *types.APIResponse[*types.Webhook]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with inadequate admin user attempting to ban", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		helper.exampleInput.NewStatus = string(types.BannedUserAccountStatus)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, helper.exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.service.sessionContextDataFetcher = func(*http.Request) (*types.SessionContextData, error) {
			scd := &types.SessionContextData{
				Requester: types.RequesterInfo{
					ServicePermissions: authorization.NewServiceRolePermissionChecker(authorization.ServiceUserRole.String()),
				},
			}

			return scd, nil
		}

		helper.service.UserAccountStatusChangeHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusForbidden, helper.res.Code)
	})

	T.Run("with inadequate admin user attempting to terminate accounts", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		helper.exampleInput.NewStatus = string(types.TerminatedUserAccountStatus)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, helper.exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.service.sessionContextDataFetcher = func(*http.Request) (*types.SessionContextData, error) {
			scd := &types.SessionContextData{
				Requester: types.RequesterInfo{
					ServicePermissions: authorization.NewServiceRolePermissionChecker(authorization.ServiceUserRole.String()),
				},
			}

			return scd, nil
		}

		helper.service.UserAccountStatusChangeHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusForbidden, helper.res.Code)
	})

	T.Run("with admin that has inadequate permissions", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.neuterAdminUser()

		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		helper.exampleInput.NewStatus = string(types.BannedUserAccountStatus)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, helper.exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.service.UserAccountStatusChangeHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusForbidden, helper.res.Code)
	})

	T.Run("with no such user in database", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		helper.exampleInput.NewStatus = string(types.BannedUserAccountStatus)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, helper.exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		userDataManager := &mocktypes.AdminUserDataManagerMock{}
		userDataManager.On(
			"UpdateUserAccountStatus",
			testutils.ContextMatcher,
			helper.exampleInput.TargetUserID,
			helper.exampleInput,
		).Return(sql.ErrNoRows)
		helper.service.userDB = userDataManager

		helper.service.UserAccountStatusChangeHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusNotFound, helper.res.Code)

		mock.AssertExpectationsForObjects(t, userDataManager)
	})

	T.Run("with error writing new account status to database", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		helper.exampleInput.NewStatus = string(types.BannedUserAccountStatus)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, helper.exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		userDataManager := &mocktypes.AdminUserDataManagerMock{}
		userDataManager.On(
			"UpdateUserAccountStatus",
			testutils.ContextMatcher,
			helper.exampleInput.TargetUserID,
			helper.exampleInput,
		).Return(errors.New("blah"))
		helper.service.userDB = userDataManager

		helper.service.UserAccountStatusChangeHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.Webhook]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, userDataManager)
	})

	T.Run("with error destroying session", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		helper.exampleInput.NewStatus = string(types.BannedUserAccountStatus)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, helper.exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockHandler := &mockstore.MockStore{}
		mockHandler.ExpectDelete("", errors.New("blah"))
		helper.service.sessionManager.Store = mockHandler

		userDataManager := &mocktypes.AdminUserDataManagerMock{}
		userDataManager.On(
			"UpdateUserAccountStatus",
			testutils.ContextMatcher,
			helper.exampleInput.TargetUserID,
			helper.exampleInput,
		).Return(nil)
		helper.service.userDB = userDataManager

		helper.service.UserAccountStatusChangeHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusAccepted, helper.res.Code)

		mock.AssertExpectationsForObjects(t, userDataManager)
	})
}
