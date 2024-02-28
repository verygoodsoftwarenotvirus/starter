package accounts

import (
	"fmt"
	"net/http"

	"github.com/verygoodsoftwarenotvirus/starter/internal/encoding"
	"github.com/verygoodsoftwarenotvirus/starter/internal/messagequeue"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/internal/pkg/random"
	"github.com/verygoodsoftwarenotvirus/starter/internal/routing"
	authservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/authentication"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

const (
	serviceName string = "accounts_service"
)

var _ types.AccountDataService = (*service)(nil)

type (
	// service handles to-do list accounts.
	service struct {
		logger                       logging.Logger
		accountDataManager           types.AccountDataManager
		accountInvitationDataManager types.AccountInvitationDataManager
		accountMembershipDataManager types.AccountUserMembershipDataManager
		tracer                       tracing.Tracer
		encoderDecoder               encoding.ServerEncoderDecoder
		dataChangesPublisher         messagequeue.Publisher
		secretGenerator              random.Generator
		sessionContextDataFetcher    func(*http.Request) (*types.SessionContextData, error)
		userIDFetcher                func(*http.Request) string
		accountIDFetcher             func(*http.Request) string
	}
)

// ProvideService builds a new AccountsService.
func ProvideService(
	logger logging.Logger,
	cfg Config,
	accountDataManager types.AccountDataManager,
	accountInvitationDataManager types.AccountInvitationDataManager,
	accountMembershipDataManager types.AccountUserMembershipDataManager,
	encoder encoding.ServerEncoderDecoder,
	routeParamManager routing.RouteParamManager,
	publisherProvider messagequeue.PublisherProvider,
	tracerProvider tracing.TracerProvider,
	secretGenerator random.Generator,
) (types.AccountDataService, error) {
	dataChangesPublisher, err := publisherProvider.ProvidePublisher(cfg.DataChangesTopicName)
	if err != nil {
		return nil, fmt.Errorf("setting up account service data changes publisher: %w", err)
	}

	s := &service{
		logger:                       logging.EnsureLogger(logger).WithName(serviceName),
		accountIDFetcher:             routeParamManager.BuildRouteParamStringIDFetcher(AccountIDURIParamKey),
		userIDFetcher:                routeParamManager.BuildRouteParamStringIDFetcher(UserIDURIParamKey),
		sessionContextDataFetcher:    authservice.FetchContextFromRequest,
		accountDataManager:           accountDataManager,
		accountInvitationDataManager: accountInvitationDataManager,
		accountMembershipDataManager: accountMembershipDataManager,
		encoderDecoder:               encoder,
		dataChangesPublisher:         dataChangesPublisher,
		secretGenerator:              secretGenerator,
		tracer:                       tracing.NewTracer(tracing.EnsureTracerProvider(tracerProvider).Tracer(serviceName)),
	}

	return s, nil
}
