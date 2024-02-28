package config

import (
	"context"
	"strings"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing/cloudtrace"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing/oteltracehttp"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

const (
	// ProviderOtel represents the open source tracing server.
	ProviderOtel = "otel"
	// ProviderCloudTrace represents the GCP Cloud Trace service.
	ProviderCloudTrace = "cloudtrace"
)

type (
	// Config contains settings related to tracing.
	Config struct {
		_ struct{} `json:"-"`

		CloudTrace *cloudtrace.Config    `json:"cloudTrace,omitempty" toml:"cloud_trace,omitempty"`
		Otel       *oteltracehttp.Config `json:"otel,omitempty"       toml:"otel,omitempty"`
		Provider   string                `json:"provider,omitempty"   toml:"provider,omitempty"`
	}
)

// ProvideTracerProvider provides an instrumentation handler.
func (c *Config) ProvideTracerProvider(ctx context.Context, l logging.Logger) (traceProvider tracing.TracerProvider, err error) {
	logger := l.WithValue("tracing_provider", c.Provider)

	p := strings.TrimSpace(strings.ToLower(c.Provider))

	switch p {
	case ProviderOtel:
		return oteltracehttp.SetupOtelHTTP(ctx, c.Otel)
	case ProviderCloudTrace:
		return cloudtrace.SetupCloudTrace(ctx, c.CloudTrace)
	default:
		logger.Debug("invalid tracing provider")
		return tracing.NewNoopTracerProvider(), nil
	}
}

var _ validation.ValidatableWithContext = (*Config)(nil)

// ValidateWithContext validates the config struct.
func (c *Config) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(ctx, c,
		validation.Field(&c.Provider, validation.In("", ProviderOtel, ProviderCloudTrace)),
		validation.Field(&c.Otel, validation.When(c.Provider == ProviderOtel, validation.Required).Else(validation.Nil)),
		validation.Field(&c.CloudTrace, validation.When(c.Provider == ProviderCloudTrace, validation.Required).Else(validation.Nil)),
	)
}
