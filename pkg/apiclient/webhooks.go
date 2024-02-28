package apiclient

import (
	"context"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

// GetWebhook retrieves a webhook.
func (c *Client) GetWebhook(ctx context.Context, webhookID string) (*types.Webhook, error) {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	logger := c.logger.Clone()

	if webhookID == "" {
		return nil, ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.WebhookIDKey, webhookID)

	req, err := c.requestBuilder.BuildGetWebhookRequest(ctx, webhookID)
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "building get webhook request")
	}

	var apiResponse *types.APIResponse[*types.Webhook]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "retrieving webhook")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return nil, err
	}

	return apiResponse.Data, nil
}

// GetWebhooks gets a list of webhooks.
func (c *Client) GetWebhooks(ctx context.Context, filter *types.QueryFilter) (*types.QueryFilteredResult[types.Webhook], error) {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	logger := c.logger.Clone()
	logger = filter.AttachToLogger(logger)
	tracing.AttachQueryFilterToSpan(span, filter)

	req, err := c.requestBuilder.BuildGetWebhooksRequest(ctx, filter)
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "building webhooks list request")
	}

	var apiResponse *types.APIResponse[[]*types.Webhook]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "retrieving webhooks")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return nil, err
	}

	webhooks := &types.QueryFilteredResult[types.Webhook]{
		Data:       apiResponse.Data,
		Pagination: *apiResponse.Pagination,
	}

	return webhooks, nil
}

// CreateWebhook creates a webhook.
func (c *Client) CreateWebhook(ctx context.Context, input *types.WebhookCreationRequestInput) (*types.Webhook, error) {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	logger := c.logger.Clone()

	if input == nil {
		return nil, ErrNilInputProvided
	}

	if err := input.ValidateWithContext(ctx); err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "validating input")
	}

	req, err := c.requestBuilder.BuildCreateWebhookRequest(ctx, input)
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "building create webhook request")
	}

	var apiResponse *types.APIResponse[*types.Webhook]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "creating webhook")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return nil, err
	}

	return apiResponse.Data, nil
}

// ArchiveWebhook archives a webhook.
func (c *Client) ArchiveWebhook(ctx context.Context, webhookID string) error {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	logger := c.logger.Clone()

	if webhookID == "" {
		return ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.WebhookIDKey, webhookID)

	req, err := c.requestBuilder.BuildArchiveWebhookRequest(ctx, webhookID)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "building archive webhook request")
	}

	var apiResponse *types.APIResponse[*types.Webhook]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "archiving webhook")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return err
	}

	return nil
}

// ArchiveWebhookTriggerEvent archives a webhook trigger event.
func (c *Client) ArchiveWebhookTriggerEvent(ctx context.Context, webhookID, webhookTriggerEventID string) error {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	logger := c.logger.Clone()

	if webhookID == "" {
		return ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.WebhookIDKey, webhookID)

	if webhookTriggerEventID == "" {
		return ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.WebhookTriggerEventIDKey, webhookTriggerEventID)

	req, err := c.requestBuilder.BuildArchiveWebhookTriggerEventRequest(ctx, webhookID, webhookTriggerEventID)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "building archive webhook request")
	}

	var apiResponse *types.APIResponse[*types.Webhook]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "archiving webhook")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return err
	}

	return nil
}
