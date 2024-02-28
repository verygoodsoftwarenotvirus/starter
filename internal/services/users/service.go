package users

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/verygoodsoftwarenotvirus/starter/internal/analytics"
	"github.com/verygoodsoftwarenotvirus/starter/internal/authentication"
	"github.com/verygoodsoftwarenotvirus/starter/internal/encoding"
	"github.com/verygoodsoftwarenotvirus/starter/internal/featureflags"
	"github.com/verygoodsoftwarenotvirus/starter/internal/messagequeue"
	"github.com/verygoodsoftwarenotvirus/starter/internal/objectstorage"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/internal/pkg/random"
	"github.com/verygoodsoftwarenotvirus/starter/internal/routing"
	authservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/authentication"
	"github.com/verygoodsoftwarenotvirus/starter/internal/uploads"
	"github.com/verygoodsoftwarenotvirus/starter/internal/uploads/images"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

const (
	serviceName = "users_service"
)

var _ types.UserDataService = (*service)(nil)

type (
	// RequestValidator validates request.
	RequestValidator interface {
		Validate(req *http.Request) (bool, error)
	}

	// service handles our users.
	service struct {
		accountDataManager               types.AccountDataManager
		accountUserMembershipDataManager types.AccountUserMembershipDataManager
		accountInvitationDataManager     types.AccountInvitationDataManager
		passwordResetTokenDataManager    types.PasswordResetTokenDataManager
		tracer                           tracing.Tracer
		authenticator                    authentication.Authenticator
		logger                           logging.Logger
		encoderDecoder                   encoding.ServerEncoderDecoder
		dataChangesPublisher             messagequeue.Publisher
		analyticsReporter                analytics.EventReporter
		userDataManager                  types.UserDataManager
		secretGenerator                  random.Generator
		imageUploadProcessor             images.MediaUploadProcessor
		uploadManager                    uploads.UploadManager
		userIDFetcher                    func(*http.Request) string
		authSettings                     *authservice.Config
		sessionContextDataFetcher        func(*http.Request) (*types.SessionContextData, error)
		cfg                              *Config
		featureFlagManager               featureflags.FeatureFlagManager
	}
)

// ErrNilConfig is returned when you provide a nil configuration to the users service constructor.
var ErrNilConfig = errors.New("nil config provided")

// ProvideUsersService builds a new UsersService.
func ProvideUsersService(
	ctx context.Context,
	cfg *Config,
	authSettings *authservice.Config,
	logger logging.Logger,
	userDataManager types.UserDataManager,
	accountDataManager types.AccountDataManager,
	accountInvitationDataManager types.AccountInvitationDataManager,
	accountUserMembershipDataManager types.AccountUserMembershipDataManager,
	authenticator authentication.Authenticator,
	encoder encoding.ServerEncoderDecoder,
	imageUploadProcessor images.MediaUploadProcessor,
	routeParamManager routing.RouteParamManager,
	tracerProvider tracing.TracerProvider,
	publisherProvider messagequeue.PublisherProvider,
	secretGenerator random.Generator,
	passwordResetTokenDataManager types.PasswordResetTokenDataManager,
	featureFlagManager featureflags.FeatureFlagManager,
	analyticsReporter analytics.EventReporter,
) (types.UserDataService, error) {
	if cfg == nil {
		return nil, ErrNilConfig
	}

	dataChangesPublisher, err := publisherProvider.ProvidePublisher(cfg.DataChangesTopicName)
	if err != nil {
		return nil, fmt.Errorf("setting up users service data changes publisher: %w", err)
	}

	uploadManager, err := objectstorage.NewUploadManager(ctx, logger, tracerProvider, &cfg.Uploads.Storage, routeParamManager)
	if err != nil {
		return nil, fmt.Errorf("initializing users service upload manager: %w", err)
	}

	s := &service{
		cfg:                              cfg,
		logger:                           logging.EnsureLogger(logger).WithName(serviceName),
		userDataManager:                  userDataManager,
		accountDataManager:               accountDataManager,
		accountInvitationDataManager:     accountInvitationDataManager,
		authenticator:                    authenticator,
		userIDFetcher:                    routeParamManager.BuildRouteParamStringIDFetcher(UserIDURIParamKey),
		sessionContextDataFetcher:        authservice.FetchContextFromRequest,
		encoderDecoder:                   encoder,
		authSettings:                     authSettings,
		secretGenerator:                  secretGenerator,
		accountUserMembershipDataManager: accountUserMembershipDataManager,
		tracer:                           tracing.NewTracer(tracing.EnsureTracerProvider(tracerProvider).Tracer(serviceName)),
		imageUploadProcessor:             imageUploadProcessor,
		uploadManager:                    uploadManager,
		dataChangesPublisher:             dataChangesPublisher,
		passwordResetTokenDataManager:    passwordResetTokenDataManager,
		featureFlagManager:               featureFlagManager,
		analyticsReporter:                analyticsReporter,
	}

	return s, nil
}
