package authentication

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/verygoodsoftwarenotvirus/starter/internal/authorization"
	"github.com/verygoodsoftwarenotvirus/starter/internal/encoding"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func attachCookieToRequestForTest(t *testing.T, s *service, req *http.Request, user *types.User) (context.Context, *http.Request, string) {
	t.Helper()

	exampleAccount := fakes.BuildFakeAccount()

	ctx, sessionErr := s.sessionManager.Load(req.Context(), "")
	require.NoError(t, sessionErr)
	require.NoError(t, s.sessionManager.RenewToken(ctx))

	s.sessionManager.Put(ctx, userIDContextKey, user.ID)
	s.sessionManager.Put(ctx, accountIDContextKey, exampleAccount.ID)

	token, _, err := s.sessionManager.Commit(ctx)
	assert.NotEmpty(t, token)
	assert.NoError(t, err)

	c, err := s.buildCookie(ctx, s.config.Cookies.Domain, token, time.Now().Add(s.config.Cookies.Lifetime))
	require.NoError(t, err)
	req.AddCookie(c)

	return ctx, req.WithContext(ctx), token
}

type authServiceHTTPRoutesTestHelper struct {
	ctx                 context.Context
	req                 *http.Request
	res                 *httptest.ResponseRecorder
	sessionCtxData      *types.SessionContextData
	service             *service
	exampleUser         *types.User
	exampleAccount      *types.Account
	examplePerms        map[string]*types.UserAccountMembershipInfo
	examplePermCheckers map[string]authorization.AccountRolePermissionsChecker
	exampleLoginInput   *types.UserLoginInput
}

func (helper *authServiceHTTPRoutesTestHelper) setContextFetcher(t *testing.T) {
	t.Helper()

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

	helper.sessionCtxData = sessionCtxData
	helper.service.sessionContextDataFetcher = func(*http.Request) (*types.SessionContextData, error) {
		return sessionCtxData, nil
	}
}

func buildTestHelper(t *testing.T) *authServiceHTTPRoutesTestHelper {
	t.Helper()

	helper := &authServiceHTTPRoutesTestHelper{}

	helper.ctx = context.Background()
	helper.service = buildTestService(t)
	helper.exampleUser = fakes.BuildFakeUser()
	helper.exampleAccount = fakes.BuildFakeAccount()
	helper.exampleAccount.BelongsToUser = helper.exampleUser.ID
	helper.exampleLoginInput = fakes.BuildFakeUserLoginInputFromUser(helper.exampleUser)

	helper.examplePerms = map[string]*types.UserAccountMembershipInfo{
		helper.exampleAccount.ID: {
			AccountName: helper.exampleAccount.Name,
			AccountRole: authorization.AccountMemberRole.String(),
		},
	}
	helper.examplePermCheckers = map[string]authorization.AccountRolePermissionsChecker{
		helper.exampleAccount.ID: authorization.NewAccountRolePermissionChecker(authorization.AccountMemberRole.String()),
	}

	helper.setContextFetcher(t)

	helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

	var err error

	helper.res = httptest.NewRecorder()
	helper.req, err = http.NewRequestWithContext(
		helper.ctx,
		http.MethodGet,
		"https://whatever.whocares.gov",
		http.NoBody,
	)
	require.NotNil(t, helper.req)
	require.NoError(t, err)

	return helper
}
