package apiclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"time"

	"github.com/verygoodsoftwarenotvirus/starter/internal/encoding"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/internal/pkg/panicking"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/apiclient/requests"

	"github.com/gorilla/websocket"
	"github.com/moul/http2curl"
)

const (
	defaultTimeout = 30 * time.Second
	clientName     = "service_api_client_v1"
)

type authMethod struct{}

var (
	cookieAuthMethod   = new(authMethod)
	oauth2AuthMethod   = new(authMethod)
	defaultContentType = encoding.ContentTypeJSON

	errInvalidResponseCode = errors.New("invalid response code")
)

// Client is a client for interacting with v1 of our HTTP API.
type Client struct {
	logger                logging.Logger
	tracer                tracing.Tracer
	panicker              panicking.Panicker
	url                   *url.URL
	requestBuilder        *requests.Builder
	encoder               encoding.ClientEncoder
	unauthenticatedClient *http.Client
	authedClient          *http.Client
	authMethod            *authMethod
	authHeaderBuilder     authHeaderBuilder
	websocketDialer       *websocket.Dialer
	accountID             string
	debug                 bool
}

// AuthenticatedClient returns the authenticated *apiclient.Client that we use to make most requests.
func (c *Client) AuthenticatedClient() *http.Client {
	return c.authedClient
}

// PlainClient returns the unauthenticated *apiclient.Client that we use to make certain requests.
func (c *Client) PlainClient() *http.Client {
	return c.unauthenticatedClient
}

// URL provides the client's URL.
func (c *Client) URL() *url.URL {
	return c.url
}

// RequestBuilder provides the client's *requests.Builder.
func (c *Client) RequestBuilder() *requests.Builder {
	return c.requestBuilder
}

// NewClient builds a new API client for us.
func NewClient(u *url.URL, tracerProvider tracing.TracerProvider, options ...option) (*Client, error) {
	l := logging.NewNoopLogger()

	c := &Client{
		url:                   u,
		logger:                logging.EnsureLogger(nil),
		debug:                 false,
		tracer:                tracing.NewTracer(tracing.EnsureTracerProvider(tracerProvider).Tracer(clientName)),
		panicker:              panicking.NewProductionPanicker(),
		encoder:               encoding.ProvideClientEncoder(l, tracerProvider, encoding.ContentTypeJSON),
		authedClient:          tracing.BuildTracedHTTPClient(),
		unauthenticatedClient: tracing.BuildTracedHTTPClient(),
		websocketDialer:       websocket.DefaultDialer,
	}

	requestBuilder, err := requests.NewBuilder(c.url, c.logger, tracerProvider, encoding.ProvideClientEncoder(l, tracerProvider, defaultContentType))
	if err != nil {
		return nil, err
	}

	c.requestBuilder = requestBuilder

	for _, opt := range options {
		if optionSetErr := opt(c); optionSetErr != nil {
			return nil, optionSetErr
		}
	}

	if c.url == nil {
		return nil, ErrNoURLProvided
	}

	return c, nil
}

// closeResponseBody takes a given HTTP response and closes its body, logging if an error occurs.
func (c *Client) closeResponseBody(ctx context.Context, res *http.Response) {
	_, span := c.tracer.StartSpan(ctx)
	defer span.End()

	if res != nil {
		if err := res.Body.Close(); err != nil {
			observability.AcknowledgeError(err, c.logger.WithResponse(res), span, "closing response body")
		}
	}
}

// BuildURL builds standard service URLs.
func (c *Client) BuildURL(ctx context.Context, qp url.Values, parts ...string) string {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	if u := c.buildRawURL(ctx, qp, parts...); u != nil {
		return u.String()
	}

	return ""
}

// buildRawURL takes a given set of query parameters and url parts, and returns a parsed url object from them.
func (c *Client) buildRawURL(ctx context.Context, queryParams url.Values, parts ...string) *url.URL {
	_, span := c.tracer.StartSpan(ctx)
	defer span.End()

	tu := *c.url
	logger := c.logger.WithValue(keys.URLQueryKey, queryParams.Encode())

	u, err := url.Parse(path.Join(append([]string{"api", "v1"}, parts...)...))
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "building URL")
		return nil
	}

	if queryParams != nil {
		u.RawQuery = queryParams.Encode()
	}

	return tu.ResolveReference(u)
}

// buildVersionlessURL builds a URL without the `/api/v1/` prefix. It should otherwise be identical to buildRawURL.
func (c *Client) buildVersionlessURL(ctx context.Context, qp url.Values, parts ...string) string {
	_, span := c.tracer.StartSpan(ctx)
	defer span.End()

	tu := *c.url

	u, err := url.Parse(path.Join(parts...))
	if err != nil {
		tracing.AttachErrorToSpan(span, "building url", err)
		return ""
	}

	if qp != nil {
		u.RawQuery = qp.Encode()
	}

	return tu.ResolveReference(u).String()
}

// IsUp returns whether the service's health endpoint is returning 200s.
func (c *Client) IsUp(ctx context.Context) bool {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	logger := c.logger.Clone()

	req, err := c.requestBuilder.BuildHealthCheckRequest(ctx)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "building health check request")

		return false
	}

	res, err := c.fetchResponseToRequest(ctx, c.unauthenticatedClient, req)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "performing health check")

		return false
	}

	c.closeResponseBody(ctx, res)

	return res.StatusCode == http.StatusOK
}

func (c *Client) logRequest(logger logging.Logger, res *http.Response) {
	if bdump, err := httputil.DumpResponse(res, true); err == nil {
		logger = logger.WithValue("response_body", string(bdump))
	}

	logger.WithValue(keys.ResponseStatusKey, res.StatusCode).Debug("request executed")
}

// fetchResponseToRequest takes a given *http.Request and executes it with the provided.
// client, alongside some debugging logging.
func (c *Client) fetchResponseToRequest(ctx context.Context, client *http.Client, req *http.Request) (*http.Response, error) {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	logger := c.logger.WithRequest(req).WithSpan(span)

	if command, err := http2curl.GetCurlCommand(req); err == nil && c.debug {
		logger = logger.WithValue("curl", command.String())
	}

	// this should be the only use of .Do in this package
	res, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "executing request")
	}

	return res, nil
}

// executeAndUnmarshal executes a request and unmarshals it to the provided interface.
func (c *Client) executeAndUnmarshal(ctx context.Context, req *http.Request, httpClient *http.Client, out any) error {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	logger := c.logger.WithRequest(req).WithSpan(span)
	logger.Debug("executing request")

	res, err := c.fetchResponseToRequest(ctx, httpClient, req)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "executing request")
	}

	if resErr := errorFromResponse(res); resErr != nil {
		return resErr
	}

	if out != nil {
		if err = c.unmarshalBody(ctx, res, out); err != nil {
			return observability.PrepareAndLogError(err, logger, span, "%s %s %d", res.Request.Method, res.Request.URL.Path, res.StatusCode)
		}
	}

	if err = res.Body.Close(); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "closing response body")
	}

	return nil
}

// fetchAndUnmarshal takes a given request and executes it with the auth client.
func (c *Client) fetchAndUnmarshal(ctx context.Context, req *http.Request, out any) error {
	return c.executeAndUnmarshal(ctx, req, c.authedClient, out)
}

// fetchAndUnmarshalWithoutAuthentication takes a given request and executes it with the plain client.
func (c *Client) fetchAndUnmarshalWithoutAuthentication(ctx context.Context, req *http.Request, out any) error {
	return c.executeAndUnmarshal(ctx, req, c.unauthenticatedClient, out)
}

// responseIsOK executes an HTTP request and loads the response content into a bool.
func (c *Client) responseIsOK(ctx context.Context, req *http.Request) (bool, error) {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	res, err := c.fetchResponseToRequest(ctx, c.authedClient, req)
	if err != nil {
		return false, observability.PrepareError(err, span, "executing existence request")
	}

	c.closeResponseBody(ctx, res)

	return res.StatusCode == http.StatusOK, nil
}
