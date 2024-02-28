package converters

import (
	"github.com/verygoodsoftwarenotvirus/starter/internal/identifiers"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

// ConvertWebhookToWebhookCreationRequestInput builds a WebhookCreationRequestInput from a Webhook.
func ConvertWebhookToWebhookCreationRequestInput(webhook *types.Webhook) *types.WebhookCreationRequestInput {
	eventStrings := []string{}
	for _, evt := range webhook.Events {
		eventStrings = append(eventStrings, evt.TriggerEvent)
	}

	return &types.WebhookCreationRequestInput{
		Name:        webhook.Name,
		ContentType: webhook.ContentType,
		URL:         webhook.URL,
		Method:      webhook.Method,
		Events:      eventStrings,
	}
}

// ConvertWebhookToWebhookDatabaseCreationInput builds a WebhookCreationRequestInput from a Webhook.
func ConvertWebhookToWebhookDatabaseCreationInput(webhook *types.Webhook) *types.WebhookDatabaseCreationInput {
	events := []*types.WebhookTriggerEventDatabaseCreationInput{}
	for i := range webhook.Events {
		events = append(events, ConvertWebhookTriggerEventToWebhookTriggerEventDatabaseCreationInput(webhook.Events[i]))
	}

	return &types.WebhookDatabaseCreationInput{
		ID:               webhook.ID,
		Name:             webhook.Name,
		ContentType:      webhook.ContentType,
		URL:              webhook.URL,
		Method:           webhook.Method,
		Events:           events,
		BelongsToAccount: webhook.BelongsToAccount,
	}
}

// ConvertWebhookTriggerEventToWebhookTriggerEventDatabaseCreationInput builds a WebhookTriggerEventCreationRequestInput from a WebhookTriggerEvent.
func ConvertWebhookTriggerEventToWebhookTriggerEventDatabaseCreationInput(event *types.WebhookTriggerEvent) *types.WebhookTriggerEventDatabaseCreationInput {
	return &types.WebhookTriggerEventDatabaseCreationInput{
		ID:               event.ID,
		BelongsToWebhook: event.BelongsToWebhook,
		TriggerEvent:     event.TriggerEvent,
	}
}

// ConvertWebhookCreationRequestInputToWebhookDatabaseCreationInput creates a WebhookDatabaseCreationInput from a WebhookCreationRequestInput.
func ConvertWebhookCreationRequestInputToWebhookDatabaseCreationInput(input *types.WebhookCreationRequestInput) *types.WebhookDatabaseCreationInput {
	x := &types.WebhookDatabaseCreationInput{
		ID:          identifiers.New(),
		Name:        input.Name,
		ContentType: input.ContentType,
		URL:         input.URL,
		Method:      input.Method,
	}

	for _, evt := range input.Events {
		x.Events = append(x.Events, &types.WebhookTriggerEventDatabaseCreationInput{
			ID:               identifiers.New(),
			BelongsToWebhook: x.ID,
			TriggerEvent:     evt,
		})
	}

	return x
}
