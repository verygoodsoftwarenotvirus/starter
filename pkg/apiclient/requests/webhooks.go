package requests

import (
	"context"
	"net/http"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

const (
	webhooksBasePath = "webhooks"
)

// BuildGetWebhookRequest builds an HTTP request for fetching a webhook.
func (b *Builder) BuildGetWebhookRequest(ctx context.Context, webhookID string) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	if webhookID == "" {
		return nil, ErrInvalidIDProvided
	}

	tracing.AttachToSpan(span, keys.WebhookIDKey, webhookID)

	uri := b.BuildURL(ctx, nil, webhooksBasePath, webhookID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, http.NoBody)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building request")
	}

	return req, nil
}

// BuildGetWebhooksRequest builds an HTTP request for fetching a list of webhooks.
func (b *Builder) BuildGetWebhooksRequest(ctx context.Context, filter *types.QueryFilter) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	tracing.AttachQueryFilterToSpan(span, filter)
	uri := b.BuildURL(ctx, filter.ToValues(), webhooksBasePath)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, http.NoBody)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building request")
	}

	return req, nil
}

// BuildCreateWebhookRequest builds an HTTP request for creating a webhook.
func (b *Builder) BuildCreateWebhookRequest(ctx context.Context, input *types.WebhookCreationRequestInput) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	if input == nil {
		return nil, ErrNilInputProvided
	}

	if err := input.ValidateWithContext(ctx); err != nil {
		return nil, observability.PrepareError(err, span, "validating input")
	}

	uri := b.BuildURL(ctx, nil, webhooksBasePath)

	return b.buildDataRequest(ctx, http.MethodPost, uri, input)
}

// BuildArchiveWebhookRequest builds an HTTP request for archiving a webhook.
func (b *Builder) BuildArchiveWebhookRequest(ctx context.Context, webhookID string) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	if webhookID == "" {
		return nil, ErrInvalidIDProvided
	}

	tracing.AttachToSpan(span, keys.WebhookIDKey, webhookID)

	uri := b.BuildURL(ctx, nil, webhooksBasePath, webhookID)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, uri, http.NoBody)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building request")
	}

	return req, nil
}

// BuildArchiveWebhookTriggerEventRequest builds an HTTP request for archiving a webhook trigger event.
func (b *Builder) BuildArchiveWebhookTriggerEventRequest(ctx context.Context, webhookID, webhookTriggerEventID string) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	if webhookID == "" || webhookTriggerEventID == "" {
		return nil, ErrInvalidIDProvided
	}

	tracing.AttachToSpan(span, keys.WebhookIDKey, webhookID)
	tracing.AttachToSpan(span, keys.WebhookTriggerEventIDKey, webhookTriggerEventID)

	uri := b.BuildURL(ctx, nil, webhooksBasePath, webhookID, "trigger_events", webhookTriggerEventID)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, uri, http.NoBody)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building request")
	}

	return req, nil
}
