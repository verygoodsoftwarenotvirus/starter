package config

import (
	"context"
	"net/http"
	"strings"

	"github.com/verygoodsoftwarenotvirus/starter/internal/featureflags"
	"github.com/verygoodsoftwarenotvirus/starter/internal/featureflags/launchdarkly"
	"github.com/verygoodsoftwarenotvirus/starter/internal/featureflags/posthog"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

const (
	// ProviderLaunchDarkly is used to indicate the LaunchDarkly provider.
	ProviderLaunchDarkly = "launchdarkly"
	// ProviderPostHog is used to indicate the PostHog provider.
	ProviderPostHog = "posthog"
)

type (
	// Config configures our feature flag managers.
	Config struct {
		LaunchDarkly *launchdarkly.Config
		PostHog      *posthog.Config
		Provider     string
	}
)

var _ validation.ValidatableWithContext = (*Config)(nil)

// ValidateWithContext validates the config.
func (c *Config) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(ctx, c,
		validation.Field(&c.Provider, validation.In(ProviderLaunchDarkly, ProviderPostHog)),
		validation.Field(&c.LaunchDarkly, validation.When(c.Provider == ProviderLaunchDarkly, validation.Required)),
		validation.Field(&c.PostHog, validation.When(c.Provider == ProviderPostHog, validation.Required)),
	)
}

func (c *Config) ProvideFeatureFlagManager(logger logging.Logger, tracerProvider tracing.TracerProvider, httpClient *http.Client) (featureflags.FeatureFlagManager, error) {
	switch strings.TrimSpace(strings.ToLower(c.Provider)) {
	case ProviderLaunchDarkly:
		return launchdarkly.NewFeatureFlagManager(c.LaunchDarkly, logger, tracerProvider, httpClient)
	case ProviderPostHog:
		return posthog.NewFeatureFlagManager(c.PostHog, logger, tracerProvider)
	default:
		return featureflags.NewNoopFeatureFlagManager(), nil
	}
}
