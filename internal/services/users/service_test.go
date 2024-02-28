package users

import (
	"context"
	"net/http"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/internal/analytics"
	mockauthn "github.com/verygoodsoftwarenotvirus/starter/internal/authentication/mock"
	"github.com/verygoodsoftwarenotvirus/starter/internal/encoding/mock"
	"github.com/verygoodsoftwarenotvirus/starter/internal/featureflags"
	mockpublishers "github.com/verygoodsoftwarenotvirus/starter/internal/messagequeue/mock"
	"github.com/verygoodsoftwarenotvirus/starter/internal/objectstorage"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/internal/pkg/random"
	"github.com/verygoodsoftwarenotvirus/starter/internal/routing/chi"
	mockrouting "github.com/verygoodsoftwarenotvirus/starter/internal/routing/mock"
	authservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/authentication"
	"github.com/verygoodsoftwarenotvirus/starter/internal/uploads"
	"github.com/verygoodsoftwarenotvirus/starter/internal/uploads/images"
	mocktypes "github.com/verygoodsoftwarenotvirus/starter/pkg/types/mock"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func buildTestService(t *testing.T) *service {
	t.Helper()

	cfg := &Config{
		Uploads: uploads.Config{
			Storage: objectstorage.Config{
				BucketName: t.Name(),
				Provider:   objectstorage.MemoryProvider,
			},
			Debug: false,
		},
	}

	pp := &mockpublishers.ProducerProvider{}
	pp.On("ProvidePublisher", cfg.DataChangesTopicName).Return(&mockpublishers.Publisher{}, nil)

	s, err := ProvideUsersService(
		context.Background(),
		cfg,
		&authservice.Config{},
		logging.NewNoopLogger(),
		&mocktypes.UserDataManagerMock{},
		&mocktypes.AccountDataManagerMock{},
		&mocktypes.AccountInvitationDataManagerMock{},
		&mocktypes.AccountUserMembershipDataManagerMock{},
		&mockauthn.Authenticator{},
		mockencoding.NewMockEncoderDecoder(),
		&images.MockImageUploadProcessor{},
		chi.NewRouteParamManager(),
		tracing.NewNoopTracerProvider(),
		pp,
		random.NewGenerator(logging.NewNoopLogger(), tracing.NewNoopTracerProvider()),
		&mocktypes.PasswordResetTokenDataManagerMock{},
		&featureflags.NoopFeatureFlagManager{},
		analytics.NewNoopEventReporter(),
	)

	require.NoError(t, err)

	return s.(*service)
}

func TestProvideUsersService(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		rpm := mockrouting.NewRouteParamManager()
		rpm.On(
			"BuildRouteParamStringIDFetcher",
			UserIDURIParamKey,
		).Return(func(*http.Request) string { return "" })

		cfg := &Config{
			Uploads: uploads.Config{
				Storage: objectstorage.Config{
					BucketName: t.Name(),
					Provider:   objectstorage.MemoryProvider,
				},
				Debug: false,
			},
		}

		rpm.On(
			"BuildRouteParamStringIDFetcher",
			cfg.Uploads.Storage.UploadFilenameKey,
		).Return(func(*http.Request) string { return "" })

		pp := &mockpublishers.ProducerProvider{}
		pp.On("ProvidePublisher", cfg.DataChangesTopicName).Return(&mockpublishers.Publisher{}, nil)

		s, err := ProvideUsersService(
			context.Background(),
			cfg,
			&authservice.Config{},
			logging.NewNoopLogger(),
			&mocktypes.UserDataManagerMock{},
			&mocktypes.AccountDataManagerMock{},
			&mocktypes.AccountInvitationDataManagerMock{},
			&mocktypes.AccountUserMembershipDataManagerMock{},
			&mockauthn.Authenticator{},
			mockencoding.NewMockEncoderDecoder(),
			&images.MockImageUploadProcessor{},
			rpm,
			tracing.NewNoopTracerProvider(),
			pp,
			random.NewGenerator(logging.NewNoopLogger(), tracing.NewNoopTracerProvider()),
			&mocktypes.PasswordResetTokenDataManagerMock{},
			&featureflags.NoopFeatureFlagManager{},
			analytics.NewNoopEventReporter(),
		)

		assert.NotNil(t, s)
		require.NoError(t, err)

		mock.AssertExpectationsForObjects(t, rpm)
	})
}
