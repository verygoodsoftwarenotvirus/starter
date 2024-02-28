package config

import (
	"context"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/internal/analytics/posthog"
	"github.com/verygoodsoftwarenotvirus/starter/internal/analytics/rudderstack"
	"github.com/verygoodsoftwarenotvirus/starter/internal/analytics/segment"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"

	"github.com/stretchr/testify/require"
)

func TestConfig_ValidateWithContext(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		cfg := &Config{
			Provider: ProviderSegment,
			Segment:  &segment.Config{APIToken: t.Name()},
		}

		require.NoError(t, cfg.ValidateWithContext(ctx))
	})

	T.Run("with invalid token", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		cfg := &Config{
			Provider: ProviderSegment,
		}

		require.Error(t, cfg.ValidateWithContext(ctx))
	})
}

func TestConfig_ProvideCollector(T *testing.T) {
	T.Parallel()

	allProviders := []string{
		ProviderSegment,
		ProviderRudderstack,
		ProviderPostHog,
	}

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		for _, provider := range allProviders {
			cfg := &Config{
				Provider:    provider,
				Segment:     &segment.Config{APIToken: t.Name()},
				Rudderstack: &rudderstack.Config{DataPlaneURL: t.Name(), APIKey: t.Name()},
				Posthog:     &posthog.Config{APIKey: t.Name()},
			}

			_, err := cfg.ProvideCollector(logging.NewNoopLogger(), tracing.NewNoopTracerProvider())
			require.NoError(t, err)
		}
	})

	T.Run("with invalid values", func(t *testing.T) {
		t.Parallel()

		for _, provider := range allProviders {
			cfg := &Config{
				Provider:    provider,
				Segment:     &segment.Config{},
				Rudderstack: &rudderstack.Config{},
				Posthog:     &posthog.Config{},
			}

			_, err := cfg.ProvideCollector(logging.NewNoopLogger(), tracing.NewNoopTracerProvider())
			require.Error(t, err)
		}
	})
}
