package capitalism

import (
	"context"
	"fmt"
	"net/http"

	"github.com/verygoodsoftwarenotvirus/starter/internal/capitalism"
	"github.com/verygoodsoftwarenotvirus/starter/internal/encoding"
	"github.com/verygoodsoftwarenotvirus/starter/internal/messagequeue"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	authservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/authentication"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

const (
	serviceName string = "capitalism_service"
)

var _ types.CapitalismService = (*service)(nil)

type (
	// service handles valid instruments.
	service struct {
		cfg                       *Config
		logger                    logging.Logger
		sessionContextDataFetcher func(*http.Request) (*types.SessionContextData, error)
		dataChangesPublisher      messagequeue.Publisher
		encoderDecoder            encoding.ServerEncoderDecoder
		tracer                    tracing.Tracer
		paymentManager            capitalism.PaymentManager
	}
)

// ProvideService builds a new ValidInstrumentsService.
func ProvideService(
	_ context.Context,
	logger logging.Logger,
	cfg *Config,
	encoder encoding.ServerEncoderDecoder,
	publisherProvider messagequeue.PublisherProvider,
	tracerProvider tracing.TracerProvider,
	paymentManager capitalism.PaymentManager,
) (types.CapitalismService, error) {
	dataChangesPublisher, err := publisherProvider.ProvidePublisher(cfg.DataChangesTopicName)
	if err != nil {
		return nil, fmt.Errorf("setting up valid instruments service data changes publisher: %w", err)
	}

	svc := &service{
		cfg:                       cfg,
		logger:                    logging.EnsureLogger(logger).WithName(serviceName),
		sessionContextDataFetcher: authservice.FetchContextFromRequest,
		dataChangesPublisher:      dataChangesPublisher,
		encoderDecoder:            encoder,
		paymentManager:            paymentManager,
		tracer:                    tracing.NewTracer(tracing.EnsureTracerProvider(tracerProvider).Tracer(serviceName)),
	}

	return svc, nil
}
