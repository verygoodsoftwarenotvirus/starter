package apiclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/verygoodsoftwarenotvirus/starter/internal/encoding"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/apiclient/requests"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"

	"github.com/gorilla/websocket"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/oauth2"
)

type option func(*Client) error

// SetOptions sets a new option on the client.
func (c *Client) SetOptions(opts ...option) error {
	for _, opt := range opts {
		if err := opt(c); err != nil {
			return err
		}
	}

	return nil
}

// UsingURL sets the url on the client.
func UsingURL(u string) func(*Client) error {
	return func(c *Client) error {
		parsed, err := url.Parse(u)
		if err != nil {
			return err
		}

		c.url = parsed

		return nil
	}
}

// UsingTracingProvider sets the url on the client.
func UsingTracingProvider(tracerProvider tracing.TracerProvider) option {
	return func(c *Client) error {
		c.tracer = tracing.NewTracer(tracing.EnsureTracerProvider(tracerProvider).Tracer(clientName))

		return nil
	}
}

// UsingJSON sets the url on the client.
func UsingJSON() func(*Client) error {
	return func(c *Client) error {
		requestBuilder, err := requests.NewBuilder(c.url, c.logger, tracing.NewNoopTracerProvider(), encoding.ProvideClientEncoder(c.logger, tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON))
		if err != nil {
			return err
		}

		c.requestBuilder = requestBuilder
		c.encoder = encoding.ProvideClientEncoder(c.logger, tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		return nil
	}
}

// UsingXML sets the url on the client.
func UsingXML() func(*Client) error {
	return func(c *Client) error {
		requestBuilder, err := requests.NewBuilder(c.url, c.logger, tracing.NewNoopTracerProvider(), encoding.ProvideClientEncoder(c.logger, tracing.NewNoopTracerProvider(), encoding.ContentTypeXML))
		if err != nil {
			return err
		}

		c.requestBuilder = requestBuilder
		c.encoder = encoding.ProvideClientEncoder(c.logger, tracing.NewNoopTracerProvider(), encoding.ContentTypeXML)

		return nil
	}
}

// UsingLogger sets the logger on the client.
func UsingLogger(logger logging.Logger) func(*Client) error {
	return func(c *Client) error {
		c.logger = logging.EnsureLogger(logger)

		return nil
	}
}

// UsingDebug sets the debug value on the client.
func UsingDebug(debug bool) func(*Client) error {
	return func(c *Client) error {
		c.debug = debug
		return nil
	}
}

// UsingTimeout sets the debug value on the client.
func UsingTimeout(timeout time.Duration) func(*Client) error {
	return func(c *Client) error {
		if timeout == 0 {
			timeout = defaultTimeout
		}

		c.authedClient.Timeout = timeout
		c.unauthenticatedClient.Timeout = timeout

		return nil
	}
}

// UsingCookie sets the authCookie value on the client.
func UsingCookie(cookie *http.Cookie) func(*Client) error {
	return func(c *Client) error {
		if cookie == nil {
			return ErrCookieRequired
		}

		crt := newCookieRoundTripper(c.logger, c.tracer, c.authedClient.Timeout, cookie)
		c.authMethod = cookieAuthMethod
		c.authedClient.Transport = crt
		c.authHeaderBuilder = crt
		c.websocketDialer = websocket.DefaultDialer
		c.authedClient = buildRetryingClient(c.authedClient, c.logger, c.tracer)

		c.logger.Debug("set client auth cookie")

		return nil
	}
}

// UsingLogin sets the authCookie value on the client.
func UsingLogin(ctx context.Context, input *types.UserLoginInput) func(*Client) error {
	return func(c *Client) error {
		body, err := json.Marshal(input)
		if err != nil {
			return fmt.Errorf("generating login request body: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.buildVersionlessURL(ctx, nil, "users", "login"), bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("building request: %w", err)
		}

		res, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("executing request: %w", err)
		}

		cookies := res.Cookies()
		if len(cookies) == 0 {
			return http.ErrNoCookie
		}
		cookie := cookies[0]

		if closeErr := res.Body.Close(); closeErr != nil {
			return closeErr
		}

		crt := newCookieRoundTripper(c.logger, c.tracer, c.authedClient.Timeout, cookie)
		c.authMethod = cookieAuthMethod
		c.authedClient.Transport = crt
		c.authHeaderBuilder = crt
		c.websocketDialer = websocket.DefaultDialer
		c.authedClient = buildRetryingClient(c.authedClient, c.logger, c.tracer)

		c.logger.Debug("set client auth cookie")

		return nil
	}
}

// UsingOAuth2 sets the client to use OAuth2.
func UsingOAuth2(ctx context.Context, clientID, clientSecret string, cookie *http.Cookie) func(*Client) error {
	genCodeChallengeS256 := func(s string) string {
		s256 := sha256.Sum256([]byte(s))
		return base64.URLEncoding.EncodeToString(s256[:])
	}

	return func(c *Client) error {
		oauth2Config := oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Scopes:       []string{"account_member"},
			RedirectURL:  c.url.String(),
			Endpoint: oauth2.Endpoint{
				AuthStyle: oauth2.AuthStyleAutoDetect,
				AuthURL:   c.URL().String() + "/oauth2/authorize",
				TokenURL:  c.URL().String() + "/oauth2/token",
			},
		}

		req, err := http.NewRequestWithContext(
			ctx,
			http.MethodGet,
			oauth2Config.AuthCodeURL(
				"state",
				oauth2.SetAuthURLParam("code_challenge", genCodeChallengeS256("s256example")),
				oauth2.SetAuthURLParam("code_challenge_method", "S256"),
			),
			http.NoBody,
		)
		if err != nil {
			return fmt.Errorf("failed to get oauth2 code: %w", err)
		}

		req.AddCookie(cookie)
		client := otelhttp.DefaultClient
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}

		res, err := otelhttp.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to get oauth2 code: %w", err)
		}
		defer func() {
			if closeErr := res.Body.Close(); closeErr != nil {
				c.logger.Error(err, "failed to close oauth2 response body")
			}
		}()

		rl, err := res.Location()
		if err != nil {
			return err
		}

		code := rl.Query().Get("code")
		if code == "" {
			return errors.New("oauth2 code not found")
		}

		token, err := oauth2Config.Exchange(ctx, code,
			oauth2.SetAuthURLParam("code_verifier", "s256example"),
		)
		if err != nil {
			return err
		}

		c.authMethod = oauth2AuthMethod
		c.authedClient.Transport = &oauth2.Transport{
			Source: oauth2.ReuseTokenSource(token, oauth2.StaticTokenSource(token)),
			Base:   otelhttp.DefaultClient.Transport,
		}

		// TODO: set authHeaderBuilder
		c.authedClient = buildRetryingClient(c.authedClient, c.logger, c.tracer)

		c.logger.Debug("set client oauth2 token")

		return nil
	}
}
