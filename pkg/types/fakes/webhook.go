package fakes

import (
	"net/http"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/converters"

	fake "github.com/brianvoe/gofakeit/v7"
)

// BuildFakeWebhook builds a faked Webhook.
func BuildFakeWebhook() *types.Webhook {
	webhookID := BuildFakeID()

	fakeEvent := BuildFakeWebhookTriggerEvent()
	fakeEvent.BelongsToWebhook = webhookID
	events := []*types.WebhookTriggerEvent{fakeEvent}

	return &types.Webhook{
		ID:               webhookID,
		Name:             fake.UUID(),
		ContentType:      "application/json",
		URL:              fake.URL(),
		Method:           http.MethodPost,
		Events:           events,
		CreatedAt:        BuildFakeTime(),
		ArchivedAt:       nil,
		BelongsToAccount: fake.UUID(),
	}
}

// BuildFakeWebhookList builds a faked WebhookList.
func BuildFakeWebhookList() *types.QueryFilteredResult[types.Webhook] {
	var examples []*types.Webhook
	for i := 0; i < exampleQuantity; i++ {
		examples = append(examples, BuildFakeWebhook())
	}

	return &types.QueryFilteredResult[types.Webhook]{
		Pagination: types.Pagination{
			Page:          1,
			Limit:         50,
			FilteredCount: exampleQuantity / 2,
			TotalCount:    exampleQuantity,
		},
		Data: examples,
	}
}

// BuildFakeWebhookTriggerEvent builds a faked WebhookTriggerEvent.
func BuildFakeWebhookTriggerEvent() *types.WebhookTriggerEvent {
	return &types.WebhookTriggerEvent{
		ID:               BuildFakeID(),
		TriggerEvent:     string(types.WebhookCreatedCustomerEventType),
		BelongsToWebhook: BuildFakeID(),
		CreatedAt:        BuildFakeTime(),
		ArchivedAt:       nil,
	}
}

// BuildFakeWebhookTriggerEventList builds a faked WebhookList.
func BuildFakeWebhookTriggerEventList() *types.QueryFilteredResult[types.WebhookTriggerEvent] {
	var examples []*types.WebhookTriggerEvent
	for i := 0; i < exampleQuantity; i++ {
		examples = append(examples, BuildFakeWebhookTriggerEvent())
	}

	return &types.QueryFilteredResult[types.WebhookTriggerEvent]{
		Pagination: types.Pagination{
			Page:          1,
			Limit:         50,
			FilteredCount: exampleQuantity / 2,
			TotalCount:    exampleQuantity,
		},
		Data: examples,
	}
}

// BuildFakeWebhookCreationRequestInput builds a faked WebhookCreationRequestInput from a webhook.
func BuildFakeWebhookCreationRequestInput() *types.WebhookCreationRequestInput {
	webhook := BuildFakeWebhook()
	return converters.ConvertWebhookToWebhookCreationRequestInput(webhook)
}
