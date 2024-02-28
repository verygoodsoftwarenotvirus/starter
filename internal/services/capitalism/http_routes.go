package capitalism

import (
	"net/http"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"

	servertiming "github.com/mitchellh/go-server-timing"
)

// IncomingWebhookHandler is our webhook handling route.
func (s *service) IncomingWebhookHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	webhookHandleTimer := timing.NewMetric("handler").WithDesc("handle webhook event").Start()
	statusToWrite := http.StatusOK
	if err := s.paymentManager.HandleEventWebhook(req); err != nil {
		logger.Error(err, "handling subscription event webhook")
		statusToWrite = http.StatusInternalServerError
	}
	webhookHandleTimer.Stop()

	res.WriteHeader(statusToWrite)
}
