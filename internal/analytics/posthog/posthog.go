package posthog

import (
	"context"
	"errors"

	"github.com/verygoodsoftwarenotvirus/starter/internal/analytics"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"

	"github.com/posthog/posthog-go"
)

const (
	name = "posthog_event_reporter"
)

var (
	// ErrNilConfig indicates a nil config was provided.
	ErrNilConfig = errors.New("nil Posthog configuration")
	// ErrEmptyAPIToken indicates an empty API token was provided.
	ErrEmptyAPIToken = errors.New("empty API token")
)

type (
	// EventReporter is a PostHog-backed EventReporter.
	EventReporter struct {
		tracer tracing.Tracer
		logger logging.Logger
		client posthog.Client
	}
)

// NewPostHogEventReporter returns a new PostHog-backed EventReporter.
func NewPostHogEventReporter(logger logging.Logger, tracerProvider tracing.TracerProvider, cfg *Config, configModifiers ...func(*posthog.Config)) (analytics.EventReporter, error) {
	if cfg == nil {
		return nil, ErrNilConfig
	}

	if cfg.APIKey == "" {
		return nil, ErrEmptyAPIToken
	}

	phc := posthog.Config{Endpoint: "https://app.posthog.com"}
	for _, f := range configModifiers {
		f(&phc)
	}

	client, err := posthog.NewWithConfig(cfg.APIKey, phc)
	if err != nil {
		return nil, err
	}

	c := &EventReporter{
		tracer: tracing.NewTracer(tracing.EnsureTracerProvider(tracerProvider).Tracer(name)),
		logger: logging.EnsureLogger(logger).WithName(name),
		client: client,
	}

	return c, nil
}

// Close wraps the internal client's Close method.
func (c *EventReporter) Close() {
	if err := c.client.Close(); err != nil {
		c.logger.Error(err, "closing connection")
	}
}

// AddUser upsert's a user's identity.
func (c *EventReporter) AddUser(ctx context.Context, userID string, properties map[string]any) error {
	_, span := c.tracer.StartSpan(ctx)
	defer span.End()

	props := posthog.NewProperties()
	for k, v := range properties {
		props.Set(k, v)
	}

	return c.client.Enqueue(posthog.Identify{
		DistinctId: userID,
		Properties: props,
	})
}

// EventOccurred associates events with a user.
func (c *EventReporter) EventOccurred(ctx context.Context, event types.ServiceEventType, userID string, properties map[string]any) error {
	_, span := c.tracer.StartSpan(ctx)
	defer span.End()

	props := posthog.NewProperties()
	for k, v := range properties {
		props.Set(k, v)
	}

	return c.client.Enqueue(posthog.Capture{
		DistinctId: userID,
		Event:      string(event),
		Properties: props,
	})
}
