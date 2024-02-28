package mailjet

import (
	"context"
	"errors"
	"net/http"

	"github.com/verygoodsoftwarenotvirus/starter/internal/email"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"

	"github.com/mailjet/mailjet-apiv3-go/v4"
)

const (
	name = "mailjet_emailer"
)

var (
	_ email.Emailer = (*Emailer)(nil)

	// ErrNilConfig indicates an empty API token was provided.
	ErrNilConfig = errors.New("mailjet config is nil")
	// ErrEmptySecretKey indicates an empty API token was provided.
	ErrEmptySecretKey = errors.New("empty domain")
	// ErrEmptyPrivateAPIKey indicates an empty API token was provided.
	ErrEmptyPrivateAPIKey = errors.New("empty API token")
	// ErrNilHTTPClient indicates a nil HTTP client was provided.
	ErrNilHTTPClient = errors.New("nil HTTP client")
)

type (
	mailjetClient interface {
		SendMailV31(data *mailjet.MessagesV31, options ...mailjet.RequestOptions) (*mailjet.ResultsV31, error)
	}

	// Config configures Mailjet to send email.
	Config struct {
		APIKey    string `json:"publicKey" toml:"public_key,omitempty"`
		SecretKey string `json:"secretKey" toml:"secret_key,omitempty"`
	}

	// Emailer uses Mailjet to send email.
	Emailer struct {
		logger logging.Logger
		tracer tracing.Tracer
		client mailjetClient
	}
)

// NewMailjetEmailer returns a new Mailjet-backed Emailer.
func NewMailjetEmailer(cfg *Config, logger logging.Logger, tracerProvider tracing.TracerProvider, client *http.Client) (*Emailer, error) {
	if cfg == nil {
		return nil, ErrNilConfig
	}

	if cfg.SecretKey == "" {
		return nil, ErrEmptySecretKey
	}

	if cfg.APIKey == "" {
		return nil, ErrEmptyPrivateAPIKey
	}

	if client == nil {
		return nil, ErrNilHTTPClient
	}

	mj := mailjet.NewMailjetClient(cfg.APIKey, cfg.SecretKey)
	mj.SetClient(client)

	e := &Emailer{
		logger: logging.EnsureLogger(logger).WithName(name),
		tracer: tracing.NewTracer(tracing.EnsureTracerProvider(tracerProvider).Tracer(name)),
		client: mj,
	}

	return e, nil
}

// SendEmail sends an email.
func (e *Emailer) SendEmail(ctx context.Context, details *email.OutboundEmailMessage) error {
	_, span := e.tracer.StartSpan(ctx)
	defer span.End()

	tracing.AttachToSpan(span, "to_email", details.ToAddress)

	messagesInfo := []mailjet.InfoMessagesV31{
		{
			From: &mailjet.RecipientV31{
				Email: details.FromAddress,
				Name:  details.FromName,
			},
			To: &mailjet.RecipientsV31{
				mailjet.RecipientV31{
					Email: details.ToAddress,
					Name:  details.ToName,
				},
			},
			Subject:  details.Subject,
			HTMLPart: details.HTMLContent,
		},
	}

	if _, err := e.client.SendMailV31(&mailjet.MessagesV31{Info: messagesInfo}); err != nil {
		return observability.PrepareError(err, span, "sending email")
	}

	return nil
}
