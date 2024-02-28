package config

import (
	"context"
	"strings"

	"github.com/verygoodsoftwarenotvirus/starter/internal/analytics"
	"github.com/verygoodsoftwarenotvirus/starter/internal/analytics/posthog"
	"github.com/verygoodsoftwarenotvirus/starter/internal/analytics/rudderstack"
	"github.com/verygoodsoftwarenotvirus/starter/internal/analytics/segment"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

const (
	// ProviderSegment represents Segment.
	ProviderSegment = "segment"
	// ProviderRudderstack represents Rudderstack.
	ProviderRudderstack = "rudderstack"
	// ProviderPostHog represents PostHog.
	ProviderPostHog = "posthog"
)

type (
	// Config is the configuration structure.
	Config struct {
		Segment     *segment.Config     `json:"segment"     toml:"segment,omitempty"`
		Posthog     *posthog.Config     `json:"posthog"     toml:"posthog,omitempty"`
		Rudderstack *rudderstack.Config `json:"rudderstack" toml:"rudderstack,omitempty"`
		Provider    string              `json:"provider"    toml:"provider,omitempty"`
	}
)

var _ validation.ValidatableWithContext = (*Config)(nil)

// ValidateWithContext validates a Config struct.
func (cfg *Config) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(ctx, cfg,
		validation.Field(&cfg.Provider, validation.In(ProviderSegment, ProviderRudderstack, ProviderPostHog)),
		validation.Field(&cfg.Segment, validation.When(cfg.Provider == ProviderSegment, validation.Required), validation.When(cfg.Provider != ProviderSegment, validation.Nil)),
		validation.Field(&cfg.Posthog, validation.When(cfg.Provider == ProviderPostHog, validation.Required), validation.When(cfg.Provider != ProviderPostHog, validation.Nil)),
		validation.Field(&cfg.Rudderstack, validation.When(cfg.Provider == ProviderRudderstack, validation.Required), validation.When(cfg.Provider != ProviderRudderstack, validation.Nil)),
	)
}

// ProvideCollector provides a collector.
func (cfg *Config) ProvideCollector(logger logging.Logger, tracerProvider tracing.TracerProvider) (analytics.EventReporter, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Provider)) {
	case ProviderSegment:
		return segment.NewSegmentEventReporter(logger, tracerProvider, cfg.Segment.APIToken)
	case ProviderRudderstack:
		return rudderstack.NewRudderstackEventReporter(logger, tracerProvider, cfg.Rudderstack)
	case ProviderPostHog:
		return posthog.NewPostHogEventReporter(logger, tracerProvider, cfg.Posthog)
	default:
		return analytics.NewNoopEventReporter(), nil
	}
}
