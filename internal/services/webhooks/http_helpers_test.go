package webhooks

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

type webhooksServiceHTTPRoutesTestHelper struct {
	ctx                        context.Context
	req                        *http.Request
	res                        *httptest.ResponseRecorder
	service                    *service
	exampleUser                *types.User
	exampleAccount             *types.Account
	exampleWebhook             *types.Webhook
	exampleWebhookTriggerEvent *types.WebhookTriggerEvent
	exampleCreationInput       *types.WebhookCreationRequestInput
}

func newTestHelper(t *testing.T) *webhooksServiceHTTPRoutesTestHelper {
	t.Helper()

	helper := &webhooksServiceHTTPRoutesTestHelper{}

	helper.ctx = context.Background()
	helper.service = buildTestService()
	helper.exampleUser = fakes.BuildFakeUser()
	helper.exampleAccount = fakes.BuildFakeAccount()
	helper.exampleAccount.BelongsToUser = helper.exampleUser.ID
	helper.exampleWebhook = fakes.BuildFakeWebhook()
	helper.exampleWebhook.BelongsToAccount = helper.exampleAccount.ID
	helper.exampleWebhookTriggerEvent = fakes.BuildFakeWebhookTriggerEvent()
	helper.exampleWebhookTriggerEvent.BelongsToWebhook = helper.exampleWebhook.ID
	helper.exampleCreationInput = converters.ConvertWebhookToWebhookCreationRequestInput(helper.exampleWebhook)

	helper.service.webhookIDFetcher = func(*http.Request) string {
		return helper.exampleWebhook.ID
	}

	helper.service.webhookTriggerEventIDFetcher = func(*http.Request) string {
		return helper.exampleWebhookTriggerEvent.ID
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
