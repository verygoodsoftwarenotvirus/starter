package posthog

import (
	"context"
	"errors"
	"fmt"

	"github.com/verygoodsoftwarenotvirus/starter/internal/featureflags"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"

	"github.com/posthog/posthog-go"
)

var (
	ErrNilConfig          = errors.New("missing config")
	ErrNilUser            = errors.New("missing user")
	ErrMissingCredentials = errors.New("missing PostHog credentials")
)

type (
	Config struct {
		ProjectAPIKey  string `json:"projectAPIKey"  toml:"project_api_key"`
		PersonalAPIKey string `json:"personalAPIKey" toml:"personal_api_key"`
	}

	// featureFlagManager implements the feature flag interface.
	featureFlagManager struct {
		logger        logging.Logger
		tracer        tracing.Tracer
		posthogClient posthog.Client
	}
)

// NewFeatureFlagManager constructs a new featureFlagManager.
func NewFeatureFlagManager(cfg *Config, logger logging.Logger, tracerProvider tracing.TracerProvider, configModifiers ...func(config *posthog.Config)) (featureflags.FeatureFlagManager, error) {
	if cfg == nil {
		return nil, ErrNilConfig
	}

	if cfg.ProjectAPIKey == "" {
		return nil, fmt.Errorf("missing credential 'ProjectAPIKey': %w", ErrMissingCredentials)
	}

	if cfg.PersonalAPIKey == "" {
		return nil, fmt.Errorf("missing credential 'PersonalAPIKey': %w", ErrMissingCredentials)
	}

	phc := posthog.Config{
		PersonalApiKey: cfg.PersonalAPIKey,
	}

	for _, modifier := range configModifiers {
		modifier(&phc)
	}

	client, err := posthog.NewWithConfig(
		cfg.ProjectAPIKey,
		phc,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create posthog client: %w", err)
	}

	ffm := &featureFlagManager{
		posthogClient: client,
		logger:        logger,
		tracer:        tracing.NewTracer(tracing.EnsureTracerProvider(tracerProvider).Tracer("posthog_feature_flag_manager")),
	}

	return ffm, nil
}

// CanUseFeature returns whether a user can use a feature or not.
func (f *featureFlagManager) CanUseFeature(ctx context.Context, userID, feature string) (bool, error) {
	_, span := tracing.StartSpan(ctx)
	defer span.End()

	flagEnabled, err := f.posthogClient.IsFeatureEnabled(posthog.FeatureFlagPayload{
		Key:        feature,
		DistinctId: userID,
	})
	if err != nil {
		return false, fmt.Errorf("failed to determine if feature is enabled: %w", err)
	}

	if enabled, ok := flagEnabled.(bool); ok {
		return enabled, nil
	}

	return false, nil
}

// Identify identifies a user in PostHog.
func (f *featureFlagManager) Identify(ctx context.Context, user *types.User) error {
	_, span := tracing.StartSpan(ctx)
	defer span.End()

	if user == nil {
		return ErrNilUser
	}

	return f.posthogClient.Enqueue(posthog.Identify{
		DistinctId: user.ID,
		Properties: map[string]any{
			"username":   user.Username,
			"first_name": user.FirstName,
			"last_name":  user.LastName,
		},
	})
}

// Close closes the PostHog client.
func (f *featureFlagManager) Close() error {
	return f.posthogClient.Close()
}
