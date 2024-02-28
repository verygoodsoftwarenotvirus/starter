package usernotifications

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/internal/authorization"
	"github.com/verygoodsoftwarenotvirus/starter/internal/encoding"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/converters"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"
	testutils "github.com/verygoodsoftwarenotvirus/starter/tests/utils"
)

type userNotificationsServiceHTTPRoutesTestHelper struct {
	ctx                     context.Context
	req                     *http.Request
	res                     *httptest.ResponseRecorder
	service                 *service
	exampleUser             *types.User
	exampleAccount          *types.Account
	exampleUserNotification *types.UserNotification
	exampleCreationInput    *types.UserNotificationCreationRequestInput
	exampleUpdateInput      *types.UserNotificationUpdateRequestInput
}

func buildTestHelper(t *testing.T) *userNotificationsServiceHTTPRoutesTestHelper {
	t.Helper()

	helper := &userNotificationsServiceHTTPRoutesTestHelper{}

	helper.ctx = context.Background()
	helper.service = buildTestService()
	helper.exampleUser = fakes.BuildFakeUser()
	helper.exampleAccount = fakes.BuildFakeAccount()
	helper.exampleAccount.BelongsToUser = helper.exampleUser.ID
	helper.exampleUserNotification = fakes.BuildFakeUserNotification()
	helper.exampleUserNotification.BelongsToUser = helper.exampleUser.ID
	helper.exampleCreationInput = converters.ConvertUserNotificationToUserNotificationCreationRequestInput(helper.exampleUserNotification)
	helper.exampleUpdateInput = converters.ConvertUserNotificationToUserNotificationUpdateRequestInput(helper.exampleUserNotification)

	helper.service.userNotificationIDFetcher = func(*http.Request) string {
		return helper.exampleUserNotification.ID
	}

	sessionCtxData := &types.SessionContextData{
		Requester: types.RequesterInfo{
			UserID:                   helper.exampleUser.ID,
			AccountStatus:            helper.exampleUser.AccountStatus,
			AccountStatusExplanation: helper.exampleUser.AccountStatusExplanation,
			ServicePermissions:       authorization.NewServiceRolePermissionChecker(helper.exampleUser.ServiceRole),
		},
		ActiveAccountID: helper.exampleAccount.ID,
		AccountPermissions: map[string]authorization.AccountRolePermissionsChecker{
			helper.exampleAccount.ID: authorization.NewAccountRolePermissionChecker(authorization.AccountMemberRole.String()),
		},
	}

	helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)
	helper.service.sessionContextDataFetcher = func(*http.Request) (*types.SessionContextData, error) {
		return sessionCtxData, nil
	}

	req := testutils.BuildTestRequest(t)

	helper.req = req.WithContext(context.WithValue(req.Context(), types.SessionContextDataKey, sessionCtxData))
	helper.res = httptest.NewRecorder()

	return helper
}
