package servicesettings

import (
	"fmt"
	"net/http"

	"github.com/verygoodsoftwarenotvirus/starter/internal/encoding"
	"github.com/verygoodsoftwarenotvirus/starter/internal/messagequeue"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/internal/routing"
	authservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/authentication"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

const (
	serviceName string = "service_settings_service"
)

var _ types.ServiceSettingDataService = (*service)(nil)

type (
	// service handles service settings.
	service struct {
		logger                    logging.Logger
		serviceSettingDataManager types.ServiceSettingDataManager
		serviceSettingIDFetcher   func(*http.Request) string
		sessionContextDataFetcher func(*http.Request) (*types.SessionContextData, error)
		dataChangesPublisher      messagequeue.Publisher
		encoderDecoder            encoding.ServerEncoderDecoder
		tracer                    tracing.Tracer
	}
)

// ProvideService builds a new ServiceSettingsService.
func ProvideService(
	logger logging.Logger,
	cfg *Config,
	serviceSettingDataManager types.ServiceSettingDataManager,
	encoder encoding.ServerEncoderDecoder,
	routeParamManager routing.RouteParamManager,
	publisherProvider messagequeue.PublisherProvider,
	tracerProvider tracing.TracerProvider,
) (types.ServiceSettingDataService, error) {
	dataChangesPublisher, err := publisherProvider.ProvidePublisher(cfg.DataChangesTopicName)
	if err != nil {
		return nil, fmt.Errorf("setting up service settingss service data changes publisher: %w", err)
	}

	svc := &service{
		logger:                    logging.EnsureLogger(logger).WithName(serviceName),
		serviceSettingIDFetcher:   routeParamManager.BuildRouteParamStringIDFetcher(ServiceSettingIDURIParamKey),
		sessionContextDataFetcher: authservice.FetchContextFromRequest,
		serviceSettingDataManager: serviceSettingDataManager,
		dataChangesPublisher:      dataChangesPublisher,
		encoderDecoder:            encoder,
		tracer:                    tracing.NewTracer(tracing.EnsureTracerProvider(tracerProvider).Tracer(serviceName)),
	}

	return svc, nil
}
