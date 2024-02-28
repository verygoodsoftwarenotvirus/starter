package apiclient

import (
	"context"
	"net/http"
	"time"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
)

// cookieRoundtripper is a http.Transport that uses a cookie.
type cookieRoundtripper struct {
	cookie *http.Cookie

	logger logging.Logger
	tracer tracing.Tracer

	// base is the base RoundTripper used to make HTTP requests. If nil, http.DefaultTransport is used.
	base http.RoundTripper
}

func newCookieRoundTripper(logger logging.Logger, tracer tracing.Tracer, timeout time.Duration, cookie *http.Cookie) *cookieRoundtripper {
	return &cookieRoundtripper{
		cookie: cookie,
		logger: logger,
		tracer: tracer,
		base:   newDefaultRoundTripper(timeout),
	}
}

// RoundTrip authorizes and authenticates the request with a cookie.
func (t *cookieRoundtripper) RoundTrip(req *http.Request) (*http.Response, error) {
	_, span := t.tracer.StartSpan(req.Context())
	defer span.End()

	reqBodyClosed := false
	if req.Body != nil {
		defer func() {
			if !reqBodyClosed {
				if err := req.Body.Close(); err != nil {
					observability.AcknowledgeError(err, t.logger, span, "closing response body")
				}
			}
		}()
	}

	if c, err := req.Cookie(t.cookie.Name); c == nil || err != nil {
		req.AddCookie(t.cookie)
	}

	// req.Body is assumed to be closed by the base RoundTripper.
	reqBodyClosed = true

	res, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, observability.PrepareError(err, span, "executing RoundTrip")
	}

	if responseCookies := res.Cookies(); len(responseCookies) >= 1 {
		t.cookie = responseCookies[0]
	}

	return res, nil
}

// BuildRequestHeaders builds an example request header.
func (t *cookieRoundtripper) BuildRequestHeaders(ctx context.Context) (http.Header, error) {
	_, span := t.tracer.StartSpan(ctx)
	defer span.End()

	r := http.Request{Header: http.Header{}}
	r.AddCookie(t.cookie)

	return r.Header, nil
}
