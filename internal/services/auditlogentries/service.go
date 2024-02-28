package auditlogentries

import (
	"context"
	"net/http"

	"github.com/verygoodsoftwarenotvirus/starter/internal/encoding"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/internal/routing"
	authservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/authentication"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

const (
	serviceName string = "audit_log_entries_service"
)

var _ types.AuditLogEntryDataService = (*service)(nil)

type (
	// service handles audit log entries.
	service struct {
		cfg                       *Config
		logger                    logging.Logger
		auditLogEntryDataManager  types.AuditLogEntryDataManager
		auditLogEntryIDFetcher    func(*http.Request) string
		sessionContextDataFetcher func(*http.Request) (*types.SessionContextData, error)
		encoderDecoder            encoding.ServerEncoderDecoder
		tracer                    tracing.Tracer
	}
)

// ProvideService builds a new AuditLogEntriesService.
func ProvideService(
	_ context.Context,
	logger logging.Logger,
	cfg *Config,
	auditLogEntryDataManager types.AuditLogEntryDataManager,
	encoder encoding.ServerEncoderDecoder,
	routeParamManager routing.RouteParamManager,
	tracerProvider tracing.TracerProvider,
) (types.AuditLogEntryDataService, error) {
	svc := &service{
		cfg:                       cfg,
		logger:                    logging.EnsureLogger(logger).WithName(serviceName),
		auditLogEntryIDFetcher:    routeParamManager.BuildRouteParamStringIDFetcher(AuditLogEntryIDURIParamKey),
		sessionContextDataFetcher: authservice.FetchContextFromRequest,
		auditLogEntryDataManager:  auditLogEntryDataManager,
		encoderDecoder:            encoder,
		tracer:                    tracing.NewTracer(tracing.EnsureTracerProvider(tracerProvider).Tracer(serviceName)),
	}

	return svc, nil
}
