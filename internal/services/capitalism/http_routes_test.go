package capitalism

import (
	"bytes"
	"context"
	"net/http"
	"testing"

	capitalismmock "github.com/verygoodsoftwarenotvirus/starter/internal/capitalism/mock"
	"github.com/verygoodsoftwarenotvirus/starter/internal/encoding"
	mockpublishers "github.com/verygoodsoftwarenotvirus/starter/internal/messagequeue/mock"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/internal/pkg/random"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestValidInstrumentsService_StripeWebhookHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		secret, err := random.GenerateHexEncodedString(ctx, 32)
		require.NoError(t, err)
		require.NotEmpty(t, secret)

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		mpm := &capitalismmock.MockPaymentManager{}
		mpm.On("HandleEventWebhook", mock.AnythingOfType("*http.Request")).Return(nil)
		helper.service.paymentManager = mpm

		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(nil))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		dataChangesPublisher := &mockpublishers.Publisher{}
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.IncomingWebhookHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusOK, helper.res.Code)

		mock.AssertExpectationsForObjects(t, dataChangesPublisher)
	})
}
