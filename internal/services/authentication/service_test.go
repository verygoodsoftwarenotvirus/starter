package authentication

import (
	"context"
	"net/http"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/internal/analytics"
	"github.com/verygoodsoftwarenotvirus/starter/internal/authentication/mock"
	"github.com/verygoodsoftwarenotvirus/starter/internal/database"
	"github.com/verygoodsoftwarenotvirus/starter/internal/encoding"
	"github.com/verygoodsoftwarenotvirus/starter/internal/featureflags"
	"github.com/verygoodsoftwarenotvirus/starter/internal/messagequeue/mock"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/internal/pkg/random"
	"github.com/verygoodsoftwarenotvirus/starter/internal/routing/mock"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/mock"

	"github.com/alexedwards/scs/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func buildTestService(t *testing.T) *service {
	t.Helper()

	logger := logging.NewNoopLogger()
	encoderDecoder := encoding.ProvideServerEncoderDecoder(logger, tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

	cfg := &Config{
		Cookies: CookieConfig{
			Name:     DefaultCookieName,
			BlockKey: "BLAHBLAHBLAHPRETENDTHISISSECRET!",
			Domain:   ".whocares.gov",
		},
	}

	pp := &mockpublishers.ProducerProvider{}
	pp.On("ProvidePublisher", cfg.DataChangesTopicName).Return(&mockpublishers.Publisher{}, nil)

	rpm := mockrouting.NewRouteParamManager()
	rpm.On(
		"BuildRouteParamStringIDFetcher",
		AuthProviderParamKey,
	).Return(func(*http.Request) string { return "" })

	s, err := ProvideService(
		context.Background(),
		logger,
		cfg,
		&mockauthn.Authenticator{},
		database.NewMockDatabase(),
		&mocktypes.AccountUserMembershipDataManagerMock{},
		scs.New(),
		encoderDecoder,
		tracing.NewNoopTracerProvider(),
		pp,
		random.NewGenerator(logging.NewNoopLogger(), tracing.NewNoopTracerProvider()),
		&featureflags.NoopFeatureFlagManager{},
		analytics.NewNoopEventReporter(),
		rpm,
	)
	require.NoError(t, err)

	return s.(*service)
}

func TestProvideService(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()
		logger := logging.NewNoopLogger()
		encoderDecoder := encoding.ProvideServerEncoderDecoder(logger, tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		cfg := &Config{
			Cookies: CookieConfig{
				Name:     DefaultCookieName,
				BlockKey: "BLAHBLAHBLAHPRETENDTHISISSECRET!",
			},
		}

		pp := &mockpublishers.ProducerProvider{}
		pp.On("ProvidePublisher", cfg.DataChangesTopicName).Return(&mockpublishers.Publisher{}, nil)

		rpm := mockrouting.NewRouteParamManager()
		rpm.On(
			"BuildRouteParamStringIDFetcher",
			AuthProviderParamKey,
		).Return(func(*http.Request) string { return "" })

		s, err := ProvideService(
			context.Background(),
			logger,
			cfg,
			&mockauthn.Authenticator{},
			database.NewMockDatabase(),
			&mocktypes.AccountUserMembershipDataManagerMock{},
			scs.New(),
			encoderDecoder,
			tracing.NewNoopTracerProvider(),
			pp,
			random.NewGenerator(logging.NewNoopLogger(), tracing.NewNoopTracerProvider()),
			&featureflags.NoopFeatureFlagManager{},
			analytics.NewNoopEventReporter(),
			rpm,
		)

		assert.NotNil(t, s)
		assert.NoError(t, err)
	})

	T.Run("with invalid cookie key", func(t *testing.T) {
		t.Parallel()
		logger := logging.NewNoopLogger()
		encoderDecoder := encoding.ProvideServerEncoderDecoder(logger, tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		cfg := &Config{
			Cookies: CookieConfig{
				Name:     DefaultCookieName,
				BlockKey: "BLAHBLAHBLAH",
			},
		}

		pp := &mockpublishers.ProducerProvider{}
		pp.On("ProvidePublisher", cfg.DataChangesTopicName).Return(&mockpublishers.Publisher{}, nil)

		rpm := mockrouting.NewRouteParamManager()
		rpm.On(
			"BuildRouteParamStringIDFetcher",
			AuthProviderParamKey,
		).Return(func(*http.Request) string { return "" })

		s, err := ProvideService(
			context.Background(),
			logger,
			&Config{
				Cookies: CookieConfig{
					Name:     DefaultCookieName,
					BlockKey: "BLAHBLAHBLAH",
				},
			},
			&mockauthn.Authenticator{},
			database.NewMockDatabase(),
			&mocktypes.AccountUserMembershipDataManagerMock{},
			scs.New(),
			encoderDecoder,
			tracing.NewNoopTracerProvider(),
			pp,
			random.NewGenerator(logging.NewNoopLogger(), tracing.NewNoopTracerProvider()),
			&featureflags.NoopFeatureFlagManager{},
			analytics.NewNoopEventReporter(),
			rpm,
		)

		assert.Nil(t, s)
		assert.Error(t, err)
	})
}
