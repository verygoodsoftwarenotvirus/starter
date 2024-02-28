package mailgun

import (
	"context"
	"errors"
	"net/http"

	"github.com/verygoodsoftwarenotvirus/starter/internal/email"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"

	"github.com/mailgun/mailgun-go/v4"
)

const (
	name = "mailgun_emailer"
)

var (
	_ email.Emailer = (*Emailer)(nil)

	// ErrNilConfig indicates an empty API token was provided.
	ErrNilConfig = errors.New("mailgun config is nil")
	// ErrEmptyDomain indicates an empty API token was provided.
	ErrEmptyDomain = errors.New("empty domain")
	// ErrEmptyPrivateAPIKey indicates an empty API token was provided.
	ErrEmptyPrivateAPIKey = errors.New("empty API token")
	// ErrNilHTTPClient indicates a nil HTTP client was provided.
	ErrNilHTTPClient = errors.New("nil HTTP client")
)

type (
	// Config configures Mailgun to send email.
	Config struct {
		PrivateAPIKey string `json:"privateAPIKey" toml:"private_api_key,omitempty"`
		Domain        string `json:"domain"        toml:"domain,omitempty"`
	}

	// Emailer uses Mailgun to send email.
	Emailer struct {
		logger logging.Logger
		tracer tracing.Tracer
		client mailgun.Mailgun
	}
)

// NewMailgunEmailer returns a new Mailgun-backed Emailer.
func NewMailgunEmailer(cfg *Config, logger logging.Logger, tracerProvider tracing.TracerProvider, client *http.Client) (*Emailer, error) {
	if cfg == nil {
		return nil, ErrNilConfig
	}

	if cfg.Domain == "" {
		return nil, ErrEmptyDomain
	}

	if cfg.PrivateAPIKey == "" {
		return nil, ErrEmptyPrivateAPIKey
	}

	if client == nil {
		return nil, ErrNilHTTPClient
	}

	mg := mailgun.NewMailgun(cfg.Domain, cfg.PrivateAPIKey)
	mg.SetClient(client)

	e := &Emailer{
		logger: logging.EnsureLogger(logger).WithName(name),
		tracer: tracing.NewTracer(tracing.EnsureTracerProvider(tracerProvider).Tracer(name)),
		client: mg,
	}

	return e, nil
}

// SendEmail sends an email.
func (e *Emailer) SendEmail(ctx context.Context, details *email.OutboundEmailMessage) error {
	_, span := e.tracer.StartSpan(ctx)
	defer span.End()

	tracing.AttachToSpan(span, "to_email", details.ToAddress)

	msg := e.client.NewMessage(details.FromName, details.Subject, details.HTMLContent, details.ToAddress)

	if _, _, err := e.client.Send(ctx, msg); err != nil {
		return observability.PrepareError(err, span, "sending email")
	}

	return nil
}
