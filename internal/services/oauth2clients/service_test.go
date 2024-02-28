package oauth2clients

import (
	"net/http"
	"testing"

	mockauthn "github.com/verygoodsoftwarenotvirus/starter/internal/authentication/mock"
	"github.com/verygoodsoftwarenotvirus/starter/internal/database"
	"github.com/verygoodsoftwarenotvirus/starter/internal/encoding"
	"github.com/verygoodsoftwarenotvirus/starter/internal/encoding/mock"
	mockpublishers "github.com/verygoodsoftwarenotvirus/starter/internal/messagequeue/mock"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/internal/pkg/random"
	randommock "github.com/verygoodsoftwarenotvirus/starter/internal/pkg/random/mock"
	mockrouting "github.com/verygoodsoftwarenotvirus/starter/internal/routing/mock"
	authservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/authentication"
	mocktypes "github.com/verygoodsoftwarenotvirus/starter/pkg/types/mock"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func buildTestService(t *testing.T) *service {
	t.Helper()

	return &service{
		oauth2ClientDataManager:   database.NewMockDatabase(),
		logger:                    logging.NewNoopLogger(),
		encoderDecoder:            encoding.ProvideServerEncoderDecoder(nil, nil, encoding.ContentTypeJSON),
		authenticator:             &mockauthn.Authenticator{},
		sessionContextDataFetcher: authservice.FetchContextFromRequest,
		urlClientIDExtractor:      func(req *http.Request) string { return "" },
		secretGenerator:           &randommock.Generator{},
		tracer:                    tracing.NewTracerForTest(serviceName),
		cfg:                       &Config{},
	}
}

func TestProvideOAuth2ClientsService(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()
		mockOAuth2ClientDataManager := &mocktypes.OAuth2ClientDataManagerMock{}

		rpm := mockrouting.NewRouteParamManager()
		rpm.On(
			"BuildRouteParamStringIDFetcher",
			OAuth2ClientIDURIParamKey,
		).Return(func(*http.Request) string { return "" })

		cfg := &Config{
			DataChangesTopicName: t.Name(),
		}

		pp := &mockpublishers.ProducerProvider{}
		pp.On("ProvidePublisher", cfg.DataChangesTopicName).Return(&mockpublishers.Publisher{}, nil)

		s, err := ProvideOAuth2ClientsService(
			logging.NewNoopLogger(),
			mockOAuth2ClientDataManager,
			&mocktypes.UserDataManagerMock{},
			&mockauthn.Authenticator{},
			mockencoding.NewMockEncoderDecoder(),
			rpm,
			cfg,
			tracing.NewNoopTracerProvider(),
			random.NewGenerator(logging.NewNoopLogger(), tracing.NewNoopTracerProvider()),
			pp,
		)
		assert.NotNil(t, s)
		assert.NoError(t, err)

		mock.AssertExpectationsForObjects(t, mockOAuth2ClientDataManager, rpm)
	})
}
