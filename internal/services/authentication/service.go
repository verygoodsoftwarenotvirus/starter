package authentication

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/verygoodsoftwarenotvirus/starter/internal/analytics"
	"github.com/verygoodsoftwarenotvirus/starter/internal/authentication"
	"github.com/verygoodsoftwarenotvirus/starter/internal/database"
	"github.com/verygoodsoftwarenotvirus/starter/internal/encoding"
	"github.com/verygoodsoftwarenotvirus/starter/internal/featureflags"
	"github.com/verygoodsoftwarenotvirus/starter/internal/messagequeue"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/internal/pkg/random"
	"github.com/verygoodsoftwarenotvirus/starter/internal/routing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"

	"github.com/alexedwards/scs/v2"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/gorilla/securecookie"
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/google"
)

const (
	serviceName          = "auth_service"
	userIDContextKey     = string(types.UserIDContextKey)
	accountIDContextKey  = string(types.AccountIDContextKey)
	cookieErrorLogName   = "_COOKIE_CONSTRUCTION_ERROR_"
	cookieSecretSize     = 64
	AuthProviderParamKey = "auth_provider"
)

// TODO: remove this.
var useProvidersMutex = sync.Mutex{}

type (
	// cookieEncoderDecoder is a stand-in interface for gorilla/securecookie.
	cookieEncoderDecoder interface {
		Encode(name string, value any) (string, error)
		Decode(name, value string, dst any) error
	}

	// service handles passwords service-wide.
	service struct {
		config                    *Config
		logger                    logging.Logger
		authenticator             authentication.Authenticator
		analyticsReporter         analytics.EventReporter
		featureFlagManager        featureflags.FeatureFlagManager
		userDataManager           types.UserDataManager
		accountMembershipManager  types.AccountUserMembershipDataManager
		encoderDecoder            encoding.ServerEncoderDecoder
		secretGenerator           random.Generator
		cookieManager             cookieEncoderDecoder
		sessionManager            sessionManager
		sessionContextDataFetcher func(*http.Request) (*types.SessionContextData, error)
		authProviderFetcher       func(*http.Request) string
		tracer                    tracing.Tracer
		dataChangesPublisher      messagequeue.Publisher
		oauth2Server              *server.Server
	}
)

// ProvideService builds a new AuthService.
func ProvideService(
	ctx context.Context,
	logger logging.Logger,
	cfg *Config,
	authenticator authentication.Authenticator,
	dataManager database.DataManager,
	accountMembershipManager types.AccountUserMembershipDataManager,
	sessionManager *scs.SessionManager,
	encoder encoding.ServerEncoderDecoder,
	tracerProvider tracing.TracerProvider,
	publisherProvider messagequeue.PublisherProvider,
	secretGenerator random.Generator,
	featureFlagManager featureflags.FeatureFlagManager,
	analyticsReporter analytics.EventReporter,
	routeParamManager routing.RouteParamManager,
) (types.AuthService, error) {
	hashKey := []byte(cfg.Cookies.HashKey)
	if len(hashKey) == 0 {
		hashKey = securecookie.GenerateRandomKey(cookieSecretSize)
	}

	dataChangesPublisher, publisherProviderErr := publisherProvider.ProvidePublisher(cfg.DataChangesTopicName)
	if publisherProviderErr != nil {
		return nil, fmt.Errorf("setting up auth service data changes publisher: %w", publisherProviderErr)
	}

	tracer := tracing.NewTracer(tracing.EnsureTracerProvider(tracerProvider).Tracer(serviceName))

	svc := &service{
		logger:                    logging.EnsureLogger(logger).WithName(serviceName),
		encoderDecoder:            encoder,
		config:                    cfg,
		userDataManager:           dataManager,
		accountMembershipManager:  accountMembershipManager,
		authenticator:             authenticator,
		sessionManager:            sessionManager,
		secretGenerator:           secretGenerator,
		sessionContextDataFetcher: FetchContextFromRequest,
		cookieManager:             securecookie.New(hashKey, []byte(cfg.Cookies.BlockKey)),
		tracer:                    tracer,
		dataChangesPublisher:      dataChangesPublisher,
		featureFlagManager:        featureFlagManager,
		analyticsReporter:         analyticsReporter,
		authProviderFetcher:       routeParamManager.BuildRouteParamStringIDFetcher(AuthProviderParamKey),
		oauth2Server:              ProvideOAuth2ServerImplementation(ctx, logger, tracer, &cfg.OAuth2, dataManager),
	}

	if _, err := svc.cookieManager.Encode(cfg.Cookies.Name, "blah"); err != nil {
		logger.WithValue("cookie_signing_key_length", len(cfg.Cookies.BlockKey)).Error(err, "building test cookie")
		return nil, fmt.Errorf("building test cookie: %w", err)
	}

	useProvidersMutex.Lock()
	goth.UseProviders(
		google.New(svc.config.SSO.Google.ClientID, svc.config.SSO.Google.ClientID, svc.config.SSO.Google.CallbackURL),
	)
	useProvidersMutex.Unlock()

	return svc, nil
}
