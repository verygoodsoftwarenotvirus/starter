package chi

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
)

// buildLoggingMiddleware builds a logging middleware.
func buildLoggingMiddleware(logger logging.Logger, tracer tracing.Tracer, silenceRouteLogging bool) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			_, span := tracer.StartSpan(req.Context())
			defer span.End()

			ww := chimiddleware.NewWrapResponseWriter(res, req.ProtoMajor)
			start := time.Now()

			next.ServeHTTP(ww, req)

			if !silenceRouteLogging {
				logger.WithRequest(req).WithSpan(span).WithValues(map[string]any{
					"status":  ww.Status(),
					"elapsed": time.Since(start).Milliseconds(),
					"written": ww.BytesWritten(),
				}).Debug("response served")
			}
		})
	}
}

// buildTracingMiddleware builds a tracing middleware.
func buildTracingMiddleware(tracer tracing.Tracer) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			ctx := otel.GetTextMapPropagator().Extract(req.Context(), propagation.HeaderCarrier(req.Header))
			spanName := fmt.Sprintf("%s %s", req.Method, req.URL.Path)

			ctx, span := tracer.StartCustomSpan(ctx, spanName)
			defer span.End()

			tracing.AttachRequestToSpan(span, req)
			req = req.WithContext(ctx)

			responseWriter := chimiddleware.NewWrapResponseWriter(res, req.ProtoMajor)
			next.ServeHTTP(responseWriter, req)

			for k, v := range responseWriter.Header() {
				span.SetAttributes(attribute.String(fmt.Sprintf("%s.%s", keys.ResponseHeadersKey, k), strings.Join(v, ";")))
			}

			span.SetAttributes(attribute.Int(keys.ResponseStatusKey, responseWriter.Status()))
			span.SetAttributes(attribute.Int(keys.ResponseBytesWrittenKey, responseWriter.BytesWritten()))
		})
	}
}
