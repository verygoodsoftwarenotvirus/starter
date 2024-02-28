package rudderstack

import (
	"context"
	"errors"

	"github.com/verygoodsoftwarenotvirus/starter/internal/analytics"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"

	rudderstack "github.com/rudderlabs/analytics-go/v4"
)

const (
	name = "rudderstack_event_reporter"
)

var (
	// ErrNilConfig indicates an nil config was provided.
	ErrNilConfig = errors.New("nil config")
	// ErrEmptyAPIToken indicates an empty API token was provided.
	ErrEmptyAPIToken = errors.New("empty API token")
	// ErrEmptyDataPlaneURL indicates an empty data plane URL was provided.
	ErrEmptyDataPlaneURL = errors.New("empty data plane URL")
)

type (
	// EventReporter is a Segment-backed EventReporter.
	EventReporter struct {
		tracer tracing.Tracer
		logger logging.Logger
		client rudderstack.Client
	}
)

// NewRudderstackEventReporter returns a new Segment-backed EventReporter.
func NewRudderstackEventReporter(logger logging.Logger, tracerProvider tracing.TracerProvider, cfg *Config) (analytics.EventReporter, error) {
	if cfg == nil {
		return nil, ErrNilConfig
	}

	if cfg.APIKey == "" {
		return nil, ErrEmptyAPIToken
	}

	if cfg.DataPlaneURL == "" {
		return nil, ErrEmptyDataPlaneURL
	}

	c := &EventReporter{
		tracer: tracing.NewTracer(tracing.EnsureTracerProvider(tracerProvider).Tracer(name)),
		logger: logging.EnsureLogger(logger).WithName(name),
		client: rudderstack.New(cfg.APIKey, cfg.DataPlaneURL),
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

	t := rudderstack.NewTraits()
	for k, v := range properties {
		t.Set(k, v)
	}

	i := rudderstack.NewIntegrations().EnableAll()

	return c.client.Enqueue(rudderstack.Identify{
		UserId:       userID,
		Traits:       t,
		Integrations: i,
	})
}

// EventOccurred associates events with a user.
func (c *EventReporter) EventOccurred(ctx context.Context, event types.ServiceEventType, userID string, properties map[string]any) error {
	_, span := c.tracer.StartSpan(ctx)
	defer span.End()

	p := rudderstack.NewProperties()
	for k, v := range properties {
		p.Set(k, v)
	}

	i := rudderstack.NewIntegrations().EnableAll()

	return c.client.Enqueue(rudderstack.Track{
		Event:        string(event),
		UserId:       userID,
		Properties:   p,
		Integrations: i,
	})
}
