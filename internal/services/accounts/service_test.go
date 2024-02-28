package accounts

import (
	"errors"
	"net/http"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/internal/encoding"
	"github.com/verygoodsoftwarenotvirus/starter/internal/encoding/mock"
	mockpublishers "github.com/verygoodsoftwarenotvirus/starter/internal/messagequeue/mock"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/internal/pkg/random"
	mockrouting "github.com/verygoodsoftwarenotvirus/starter/internal/routing/mock"
	mocktypes "github.com/verygoodsoftwarenotvirus/starter/pkg/types/mock"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func buildTestService() *service {
	return &service{
		logger:                       logging.NewNoopLogger(),
		accountDataManager:           &mocktypes.AccountDataManagerMock{},
		accountMembershipDataManager: &mocktypes.AccountUserMembershipDataManagerMock{},
		accountIDFetcher:             func(req *http.Request) string { return "" },
		encoderDecoder:               encoding.ProvideServerEncoderDecoder(nil, nil, encoding.ContentTypeJSON),
		secretGenerator:              random.NewGenerator(nil, nil),
		tracer:                       tracing.NewTracerForTest("test"),
	}
}

func TestProvideAccountsService(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		rpm := mockrouting.NewRouteParamManager()
		rpm.On(
			"BuildRouteParamStringIDFetcher",
			AccountIDURIParamKey,
		).Return(func(*http.Request) string { return "" })
		rpm.On(
			"BuildRouteParamStringIDFetcher",
			UserIDURIParamKey,
		).Return(func(*http.Request) string { return "" })

		cfg := Config{
			DataChangesTopicName: "data changes",
		}

		pp := &mockpublishers.ProducerProvider{}
		pp.On("ProvidePublisher", cfg.DataChangesTopicName).Return(&mockpublishers.Publisher{}, nil)

		s, err := ProvideService(
			logging.NewNoopLogger(),
			cfg,
			&mocktypes.AccountDataManagerMock{},
			&mocktypes.AccountInvitationDataManagerMock{},
			&mocktypes.AccountUserMembershipDataManagerMock{},
			mockencoding.NewMockEncoderDecoder(),
			rpm,
			pp,
			tracing.NewNoopTracerProvider(),
			random.NewGenerator(logging.NewNoopLogger(), tracing.NewNoopTracerProvider()),
		)

		assert.NotNil(t, s)
		assert.NoError(t, err)

		mock.AssertExpectationsForObjects(t, rpm, pp)
	})

	T.Run("with error providing publisher", func(t *testing.T) {
		t.Parallel()

		rpm := mockrouting.NewRouteParamManager()
		cfg := Config{
			DataChangesTopicName: "data changes",
		}

		pp := &mockpublishers.ProducerProvider{}
		pp.On("ProvidePublisher", cfg.DataChangesTopicName).Return(&mockpublishers.Publisher{}, errors.New("blah"))

		s, err := ProvideService(
			logging.NewNoopLogger(),
			cfg,
			&mocktypes.AccountDataManagerMock{},
			&mocktypes.AccountInvitationDataManagerMock{},
			&mocktypes.AccountUserMembershipDataManagerMock{},
			mockencoding.NewMockEncoderDecoder(),
			rpm,
			pp,
			tracing.NewNoopTracerProvider(),
			random.NewGenerator(logging.NewNoopLogger(), tracing.NewNoopTracerProvider()),
		)

		assert.Nil(t, s)
		assert.Error(t, err)

		mock.AssertExpectationsForObjects(t, rpm, pp)
	})
}
