package accountinvitations

import (
	"errors"
	"net/http"
	"testing"

	mock2 "github.com/verygoodsoftwarenotvirus/starter/internal/email/mock"
	encoding "github.com/verygoodsoftwarenotvirus/starter/internal/encoding"
	"github.com/verygoodsoftwarenotvirus/starter/internal/encoding/mock"
	mockpublishers "github.com/verygoodsoftwarenotvirus/starter/internal/messagequeue/mock"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/internal/pkg/random"
	mockrouting "github.com/verygoodsoftwarenotvirus/starter/internal/routing/mock"
	accountsservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/accounts"
	mocktypes "github.com/verygoodsoftwarenotvirus/starter/pkg/types/mock"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func buildTestService() *service {
	return &service{
		logger:                     logging.NewNoopLogger(),
		accountInvitationIDFetcher: func(req *http.Request) string { return "" },
		encoderDecoder:             encoding.ProvideServerEncoderDecoder(nil, nil, encoding.ContentTypeJSON),
		tracer:                     tracing.NewTracerForTest("test"),
	}
}

func TestProvideAccountInvitationsService(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		rpm := mockrouting.NewRouteParamManager()
		rpm.On(
			"BuildRouteParamStringIDFetcher",
			accountsservice.AccountIDURIParamKey,
		).Return(func(*http.Request) string { return "" })
		rpm.On(
			"BuildRouteParamStringIDFetcher",
			AccountInvitationIDURIParamKey,
		).Return(func(*http.Request) string { return "" })

		cfg := &Config{
			DataChangesTopicName: "data_changes",
		}

		pp := &mockpublishers.ProducerProvider{}
		pp.On("ProvidePublisher", cfg.DataChangesTopicName).Return(&mockpublishers.Publisher{}, nil)

		actual, err := ProvideAccountInvitationsService(
			logging.NewNoopLogger(),
			cfg,
			&mocktypes.UserDataManagerMock{},
			&mocktypes.AccountInvitationDataManagerMock{},
			mockencoding.NewMockEncoderDecoder(),
			rpm,
			pp,
			tracing.NewNoopTracerProvider(),
			&mock2.Emailer{},
			random.NewGenerator(logging.NewNoopLogger(), tracing.NewNoopTracerProvider()),
		)

		assert.NotNil(t, actual)
		assert.NoError(t, err)

		mock.AssertExpectationsForObjects(t, rpm, pp)
	})

	T.Run("with error providing data changes publisher", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{
			DataChangesTopicName: "pre-writes",
		}

		pp := &mockpublishers.ProducerProvider{}
		pp.On("ProvidePublisher", cfg.DataChangesTopicName).Return((*mockpublishers.Publisher)(nil), errors.New("blah"))

		actual, err := ProvideAccountInvitationsService(
			logging.NewNoopLogger(),
			cfg,
			&mocktypes.UserDataManagerMock{},
			&mocktypes.AccountInvitationDataManagerMock{},
			mockencoding.NewMockEncoderDecoder(),
			nil,
			pp,
			tracing.NewNoopTracerProvider(),
			&mock2.Emailer{},
			random.NewGenerator(logging.NewNoopLogger(), tracing.NewNoopTracerProvider()),
		)

		assert.Nil(t, actual)
		assert.Error(t, err)

		mock.AssertExpectationsForObjects(t, pp)
	})
}
