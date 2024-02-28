package accountinvitations

import (
	"fmt"
	"net/http"

	"github.com/verygoodsoftwarenotvirus/starter/internal/email"
	"github.com/verygoodsoftwarenotvirus/starter/internal/encoding"
	"github.com/verygoodsoftwarenotvirus/starter/internal/messagequeue"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/internal/pkg/random"
	"github.com/verygoodsoftwarenotvirus/starter/internal/routing"
	accountsservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/accounts"
	authservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/authentication"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

const (
	serviceName string = "account_invitations_service"
)

var (
	_ types.AccountInvitationDataService = (*service)(nil)
)

type (
	// service handles webhooks.
	service struct {
		logger                       logging.Logger
		userDataManager              types.UserDataManager
		accountInvitationDataManager types.AccountInvitationDataManager
		tracer                       tracing.Tracer
		encoderDecoder               encoding.ServerEncoderDecoder
		emailer                      email.Emailer
		secretGenerator              random.Generator
		dataChangesPublisher         messagequeue.Publisher
		accountIDFetcher             func(*http.Request) string
		accountInvitationIDFetcher   func(*http.Request) string
		sessionContextDataFetcher    func(*http.Request) (*types.SessionContextData, error)
	}
)

// ProvideAccountInvitationsService builds a new AccountInvitationDataService.
func ProvideAccountInvitationsService(
	logger logging.Logger,
	cfg *Config,
	userDataManager types.UserDataManager,
	accountInvitationDataManager types.AccountInvitationDataManager,
	encoder encoding.ServerEncoderDecoder,
	routeParamManager routing.RouteParamManager,
	publisherProvider messagequeue.PublisherProvider,
	tracerProvider tracing.TracerProvider,
	emailer email.Emailer,
	secretGenerator random.Generator,
) (types.AccountInvitationDataService, error) {
	dataChangesPublisher, err := publisherProvider.ProvidePublisher(cfg.DataChangesTopicName)
	if err != nil {
		return nil, fmt.Errorf("setting up account invitations service data changes publisher: %w", err)
	}

	s := &service{
		logger:                       logging.EnsureLogger(logger).WithName(serviceName),
		userDataManager:              userDataManager,
		accountInvitationDataManager: accountInvitationDataManager,
		encoderDecoder:               encoder,
		dataChangesPublisher:         dataChangesPublisher,
		emailer:                      emailer,
		secretGenerator:              secretGenerator,
		sessionContextDataFetcher:    authservice.FetchContextFromRequest,
		accountIDFetcher:             routeParamManager.BuildRouteParamStringIDFetcher(accountsservice.AccountIDURIParamKey),
		accountInvitationIDFetcher:   routeParamManager.BuildRouteParamStringIDFetcher(AccountInvitationIDURIParamKey),
		tracer:                       tracing.NewTracer(tracing.EnsureTracerProvider(tracerProvider).Tracer(serviceName)),
	}

	return s, nil
}
