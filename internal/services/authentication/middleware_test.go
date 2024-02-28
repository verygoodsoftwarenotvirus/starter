package authentication

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/internal/authorization"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	mocktypes "github.com/verygoodsoftwarenotvirus/starter/pkg/types/mock"
	testutils "github.com/verygoodsoftwarenotvirus/starter/tests/utils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestAuthenticationService_CookieAuthenticationMiddleware(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		accountUserMembershipDataManager := &mocktypes.AccountUserMembershipDataManagerMock{}
		accountUserMembershipDataManager.On(
			"BuildSessionContextDataForUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.sessionCtxData, nil)
		helper.service.accountMembershipManager = accountUserMembershipDataManager

		mockHandler := &testutils.MockHTTPHandler{}
		mockHandler.On(
			"ServeHTTP",
			testutils.HTTPResponseWriterMatcher,
			testutils.HTTPRequestMatcher,
		).Return()

		_, helper.req, _ = attachCookieToRequestForTest(t, helper.service, helper.req, helper.exampleUser)

		helper.service.CookieRequirementMiddleware(mockHandler).ServeHTTP(helper.res, helper.req)

		mock.AssertExpectationsForObjects(t, mockHandler)
	})
}

func TestAuthenticationService_UserAttributionMiddleware(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		sessionCtxData := &types.SessionContextData{
			Requester: types.RequesterInfo{
				UserID:                   helper.exampleUser.ID,
				AccountStatus:            helper.exampleUser.AccountStatus,
				AccountStatusExplanation: helper.exampleUser.AccountStatusExplanation,
				ServicePermissions:       authorization.NewServiceRolePermissionChecker(helper.exampleUser.ServiceRole),
			},
			ActiveAccountID:    helper.exampleAccount.ID,
			AccountPermissions: helper.examplePermCheckers,
		}

		mockAccountMembershipManager := &mocktypes.AccountUserMembershipDataManagerMock{}
		mockAccountMembershipManager.On(
			"BuildSessionContextDataForUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(sessionCtxData, nil)
		helper.service.accountMembershipManager = mockAccountMembershipManager

		_, helper.req, _ = attachCookieToRequestForTest(t, helper.service, helper.req, helper.exampleUser)

		h := &testutils.MockHTTPHandler{}
		h.On(
			"ServeHTTP",
			testutils.HTTPResponseWriterMatcher,
			testutils.HTTPRequestMatcher,
		).Return()

		helper.service.UserAttributionMiddleware(h).ServeHTTP(helper.res, helper.req)

		assert.Equal(t, http.StatusOK, helper.res.Code)

		mock.AssertExpectationsForObjects(t, mockAccountMembershipManager, h)
	})

	T.Run("with error building session context data for user", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		mockAccountMembershipManager := &mocktypes.AccountUserMembershipDataManagerMock{}
		mockAccountMembershipManager.On(
			"BuildSessionContextDataForUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return((*types.SessionContextData)(nil), errors.New("blah"))
		helper.service.accountMembershipManager = mockAccountMembershipManager

		_, helper.req, _ = attachCookieToRequestForTest(t, helper.service, helper.req, helper.exampleUser)

		mh := &testutils.MockHTTPHandler{}
		helper.service.UserAttributionMiddleware(mh).ServeHTTP(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[any]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockAccountMembershipManager, mh)
	})
}

func TestAuthenticationService_AuthorizationMiddleware(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		sessionCtxData := &types.SessionContextData{
			Requester: types.RequesterInfo{
				UserID:                   helper.exampleUser.ID,
				AccountStatus:            helper.exampleUser.AccountStatus,
				AccountStatusExplanation: helper.exampleUser.AccountStatusExplanation,
				ServicePermissions:       authorization.NewServiceRolePermissionChecker(helper.exampleUser.ServiceRole),
			},
			ActiveAccountID:    helper.exampleAccount.ID,
			AccountPermissions: helper.examplePermCheckers,
		}

		mockUserDataManager := &mocktypes.UserDataManagerMock{}
		mockUserDataManager.On(
			"GetSessionContextDataForUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(sessionCtxData, nil)
		helper.service.userDataManager = mockUserDataManager

		h := &testutils.MockHTTPHandler{}
		h.On(
			"ServeHTTP",
			testutils.HTTPResponseWriterMatcher,
			testutils.HTTPRequestMatcher,
		).Return()

		helper.req = helper.req.WithContext(context.WithValue(helper.ctx, types.SessionContextDataKey, sessionCtxData))

		helper.service.AuthorizationMiddleware(h).ServeHTTP(helper.res, helper.req)

		assert.Equal(t, http.StatusOK, helper.res.Code)

		mock.AssertExpectationsForObjects(t, h)
	})

	T.Run("with banned user", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		helper.exampleUser.AccountStatus = string(types.BannedUserAccountStatus)
		helper.setContextFetcher(t)

		sessionCtxData := &types.SessionContextData{
			Requester: types.RequesterInfo{
				UserID:                   helper.exampleUser.ID,
				AccountStatus:            helper.exampleUser.AccountStatus,
				AccountStatusExplanation: helper.exampleUser.AccountStatusExplanation,
				ServicePermissions:       authorization.NewServiceRolePermissionChecker(helper.exampleUser.ServiceRole),
			},
			ActiveAccountID:    helper.exampleAccount.ID,
			AccountPermissions: helper.examplePermCheckers,
		}

		mockUserDataManager := &mocktypes.UserDataManagerMock{}
		mockUserDataManager.On(
			"GetSessionContextDataForUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(sessionCtxData, nil)
		helper.service.userDataManager = mockUserDataManager

		h := &testutils.MockHTTPHandler{}
		h.On(
			"ServeHTTP",
			testutils.HTTPResponseWriterMatcher,
			testutils.HTTPRequestMatcher,
		).Return()

		helper.req = helper.req.WithContext(context.WithValue(helper.ctx, types.SessionContextDataKey, sessionCtxData))

		mh := &testutils.MockHTTPHandler{}
		helper.service.AuthorizationMiddleware(mh).ServeHTTP(helper.res, helper.req)

		assert.Equal(t, http.StatusForbidden, helper.res.Code)

		mock.AssertExpectationsForObjects(t, mh)
	})

	T.Run("with missing session context data", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		helper.service.sessionContextDataFetcher = func(*http.Request) (*types.SessionContextData, error) {
			return nil, nil
		}

		mh := &testutils.MockHTTPHandler{}
		helper.service.AuthorizationMiddleware(mh).ServeHTTP(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)

		mock.AssertExpectationsForObjects(t, mh)
	})

	T.Run("without authorization for account", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		sessionCtxData := &types.SessionContextData{
			Requester: types.RequesterInfo{
				UserID:                   helper.exampleUser.ID,
				AccountStatus:            helper.exampleUser.AccountStatus,
				AccountStatusExplanation: helper.exampleUser.AccountStatusExplanation,
				ServicePermissions:       authorization.NewServiceRolePermissionChecker(helper.exampleUser.ServiceRole),
			},
			ActiveAccountID:    helper.exampleAccount.ID,
			AccountPermissions: helper.examplePermCheckers,
		}

		sessionCtxData.AccountPermissions = map[string]authorization.AccountRolePermissionsChecker{}
		helper.service.sessionContextDataFetcher = func(*http.Request) (*types.SessionContextData, error) {
			return sessionCtxData, nil
		}

		helper.req = helper.req.WithContext(context.WithValue(helper.ctx, types.SessionContextDataKey, sessionCtxData))

		helper.service.AuthorizationMiddleware(&testutils.MockHTTPHandler{}).ServeHTTP(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)
	})
}

func TestAuthenticationService_PermissionFilterMiddleware(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		helper.exampleUser.ServiceRole = authorization.ServiceAdminRole.String()
		helper.setContextFetcher(t)

		sessionCtxData := &types.SessionContextData{
			Requester: types.RequesterInfo{
				UserID:                   helper.exampleUser.ID,
				AccountStatus:            helper.exampleUser.AccountStatus,
				AccountStatusExplanation: helper.exampleUser.AccountStatusExplanation,
				ServicePermissions:       authorization.NewServiceRolePermissionChecker(helper.exampleUser.ServiceRole),
			},
			ActiveAccountID:    helper.exampleAccount.ID,
			AccountPermissions: helper.examplePermCheckers,
		}

		helper.req = helper.req.WithContext(context.WithValue(helper.req.Context(), types.SessionContextDataKey, sessionCtxData))

		mockHandler := &testutils.MockHTTPHandler{}
		mockHandler.On(
			"ServeHTTP",
			testutils.HTTPResponseWriterMatcher,
			testutils.HTTPRequestMatcher,
		).Return()

		helper.service.PermissionFilterMiddleware(authorization.InviteUserToAccountPermission)(mockHandler).ServeHTTP(helper.res, helper.req)

		assert.Equal(t, http.StatusOK, helper.res.Code)

		mock.AssertExpectationsForObjects(t, mockHandler)
	})

	T.Run("with error fetching session context data", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		helper.exampleUser.ServiceRole = authorization.ServiceAdminRole.String()
		helper.setContextFetcher(t)

		helper.service.sessionContextDataFetcher = func(request *http.Request) (*types.SessionContextData, error) {
			return nil, errors.New("blah")
		}

		helper.service.PermissionFilterMiddleware(authorization.InviteUserToAccountPermission)(nil).ServeHTTP(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)
	})

	T.Run("unauthorized for account", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		helper.exampleUser.ServiceRole = authorization.ServiceAdminRole.String()
		helper.setContextFetcher(t)

		sessionCtxData := &types.SessionContextData{
			Requester: types.RequesterInfo{
				UserID:                   helper.exampleUser.ID,
				AccountStatus:            helper.exampleUser.AccountStatus,
				AccountStatusExplanation: helper.exampleUser.AccountStatusExplanation,
				ServicePermissions:       authorization.NewServiceRolePermissionChecker(),
			},
			ActiveAccountID:    "different account, lol",
			AccountPermissions: helper.examplePermCheckers,
		}

		helper.req = helper.req.WithContext(context.WithValue(helper.req.Context(), types.SessionContextDataKey, sessionCtxData))
		helper.service.sessionContextDataFetcher = func(*http.Request) (*types.SessionContextData, error) {
			return sessionCtxData, nil
		}

		helper.service.PermissionFilterMiddleware(authorization.InviteUserToAccountPermission)(nil).ServeHTTP(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)
	})

	T.Run("without permission to perform action", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		helper.exampleUser.ServiceRole = authorization.ServiceUserRole.String()
		helper.setContextFetcher(t)

		sessionCtxData := &types.SessionContextData{
			Requester: types.RequesterInfo{
				UserID:                   helper.exampleUser.ID,
				AccountStatus:            helper.exampleUser.AccountStatus,
				AccountStatusExplanation: helper.exampleUser.AccountStatusExplanation,
				ServicePermissions:       authorization.NewServiceRolePermissionChecker(authorization.InviteUserToAccountPermission.ID()),
			},
			ActiveAccountID: helper.exampleAccount.ID,
			AccountPermissions: map[string]authorization.AccountRolePermissionsChecker{
				helper.exampleAccount.ID: authorization.NewAccountRolePermissionChecker(authorization.InviteUserToAccountPermission.ID()),
			},
		}

		helper.req = helper.req.WithContext(context.WithValue(helper.req.Context(), types.SessionContextDataKey, sessionCtxData))
		helper.service.sessionContextDataFetcher = func(*http.Request) (*types.SessionContextData, error) {
			return sessionCtxData, nil
		}

		helper.service.PermissionFilterMiddleware(authorization.ArchiveAccountPermission)(nil).ServeHTTP(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)
	})
}

func TestAuthenticationService_AdminMiddleware(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		helper.exampleUser.ServiceRole = authorization.ServiceAdminRole.String()
		helper.setContextFetcher(t)

		sessionCtxData := &types.SessionContextData{
			Requester: types.RequesterInfo{
				UserID:                   helper.exampleUser.ID,
				AccountStatus:            helper.exampleUser.AccountStatus,
				AccountStatusExplanation: helper.exampleUser.AccountStatusExplanation,
				ServicePermissions:       authorization.NewServiceRolePermissionChecker(helper.exampleUser.ServiceRole),
			},
			ActiveAccountID:    helper.exampleAccount.ID,
			AccountPermissions: helper.examplePermCheckers,
		}

		helper.req = helper.req.WithContext(context.WithValue(helper.req.Context(), types.SessionContextDataKey, sessionCtxData))

		mockHandler := &testutils.MockHTTPHandler{}
		mockHandler.On(
			"ServeHTTP",
			testutils.HTTPResponseWriterMatcher,
			testutils.HTTPRequestMatcher,
		).Return()

		helper.service.ServiceAdminMiddleware(mockHandler).ServeHTTP(helper.res, helper.req)

		assert.Equal(t, http.StatusOK, helper.res.Code)

		mock.AssertExpectationsForObjects(t, mockHandler)
	})

	T.Run("with error fetching session context data", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		helper.exampleUser.ServiceRole = authorization.ServiceAdminRole.String()
		helper.service.sessionContextDataFetcher = testutils.BrokenSessionContextDataFetcher

		sessionCtxData := &types.SessionContextData{
			Requester: types.RequesterInfo{
				UserID:                   helper.exampleUser.ID,
				AccountStatus:            helper.exampleUser.AccountStatus,
				AccountStatusExplanation: helper.exampleUser.AccountStatusExplanation,
				ServicePermissions:       authorization.NewServiceRolePermissionChecker(helper.exampleUser.ServiceRole),
			},
			ActiveAccountID:    helper.exampleAccount.ID,
			AccountPermissions: helper.examplePermCheckers,
		}

		helper.req = helper.req.WithContext(context.WithValue(helper.req.Context(), types.SessionContextDataKey, sessionCtxData))

		mockHandler := &testutils.MockHTTPHandler{}
		helper.service.ServiceAdminMiddleware(mockHandler).ServeHTTP(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)

		mock.AssertExpectationsForObjects(t, mockHandler)
	})

	T.Run("with non-admin user", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		sessionCtxData := &types.SessionContextData{
			Requester: types.RequesterInfo{
				UserID:                   helper.exampleUser.ID,
				AccountStatus:            helper.exampleUser.AccountStatus,
				AccountStatusExplanation: helper.exampleUser.AccountStatusExplanation,
				ServicePermissions:       authorization.NewServiceRolePermissionChecker(helper.exampleUser.ServiceRole),
			},
			ActiveAccountID:    helper.exampleAccount.ID,
			AccountPermissions: helper.examplePermCheckers,
		}

		helper.req = helper.req.WithContext(context.WithValue(helper.req.Context(), types.SessionContextDataKey, sessionCtxData))

		mockHandler := &testutils.MockHTTPHandler{}
		helper.service.ServiceAdminMiddleware(mockHandler).ServeHTTP(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)

		mock.AssertExpectationsForObjects(t, mockHandler)
	})
}

func TestFetchContextFromRequest(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.WithValue(context.Background(), types.SessionContextDataKey, &types.SessionContextData{})
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "/", http.NoBody)
		require.NoError(t, err)
		require.NotNil(t, req)

		actual, err := FetchContextFromRequest(req)
		require.NoError(t, err)
		require.NotNil(t, actual)
	})

	T.Run("missing data", func(t *testing.T) {
		t.Parallel()

		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
		require.NoError(t, err)
		require.NotNil(t, req)

		actual, err := FetchContextFromRequest(req)
		require.Error(t, err)
		require.Nil(t, actual)
	})
}
