package types

import (
	"context"
	"net/http"
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

const (
	// WebhookCreatedCustomerEventType indicates a webhook was created.
	WebhookCreatedCustomerEventType ServiceEventType = "webhook_created"
	// WebhookArchivedCustomerEventType indicates a webhook was archived.
	WebhookArchivedCustomerEventType ServiceEventType = "webhook_archived"
)

type (
	// Webhook represents a webhook listener, an endpoint to send an HTTP request to upon an event.
	Webhook struct {
		_ struct{} `json:"-"`

		CreatedAt        time.Time              `json:"createdAt"`
		ArchivedAt       *time.Time             `json:"archivedAt"`
		LastUpdatedAt    *time.Time             `json:"lastUpdatedAt"`
		Name             string                 `json:"name"`
		URL              string                 `json:"url"`
		Method           string                 `json:"method"`
		ID               string                 `json:"id"`
		BelongsToAccount string                 `json:"belongsToAccount"`
		ContentType      string                 `json:"contentType"`
		Events           []*WebhookTriggerEvent `json:"events"`
	}

	// WebhookTriggerEvent represents a webhook trigger event.
	WebhookTriggerEvent struct {
		_ struct{} `json:"-"`

		CreatedAt        time.Time  `json:"createdAt"`
		ArchivedAt       *time.Time `json:"archivedAt"`
		ID               string     `json:"id"`
		BelongsToWebhook string     `json:"belongsToWebhook"`
		TriggerEvent     string     `json:"triggerEvent"`
	}

	// WebhookCreationRequestInput represents what a User could set as input for creating a webhook.
	WebhookCreationRequestInput struct {
		_ struct{} `json:"-"`

		Name        string   `json:"name"`
		ContentType string   `json:"contentType"`
		URL         string   `json:"url"`
		Method      string   `json:"method"`
		Events      []string `json:"events"`
	}

	// WebhookDatabaseCreationInput is used for creating a webhook.
	WebhookDatabaseCreationInput struct {
		_ struct{} `json:"-"`

		ID               string
		Name             string
		ContentType      string
		URL              string
		Method           string
		BelongsToAccount string
		Events           []*WebhookTriggerEventDatabaseCreationInput
	}

	// WebhookTriggerEventDatabaseCreationInput is used for creating a webhook trigger event.
	WebhookTriggerEventDatabaseCreationInput struct {
		_ struct{} `json:"-"`

		ID               string
		BelongsToWebhook string
		TriggerEvent     string
	}

	// WebhookExecutionRequest represents a webhook listener, an endpoint to send an HTTP request to upon an event.
	WebhookExecutionRequest struct {
		_ struct{} `json:"-"`

		Payload      any    `json:"payload"`
		WebhookID    string `json:"webhookID"`
		AccountID    string `json:"accountID"`
		TriggerEvent string `json:"triggerEvent"`
	}

	// WebhookDataManager describes a structure capable of storing webhooks.
	WebhookDataManager interface {
		WebhookExists(ctx context.Context, webhookID, accountID string) (bool, error)
		GetWebhook(ctx context.Context, webhookID, accountID string) (*Webhook, error)
		GetWebhooks(ctx context.Context, accountID string, filter *QueryFilter) (*QueryFilteredResult[Webhook], error)
		GetWebhooksForAccountAndEvent(ctx context.Context, accountID string, eventType ServiceEventType) ([]*Webhook, error)
		CreateWebhook(ctx context.Context, input *WebhookDatabaseCreationInput) (*Webhook, error)
		ArchiveWebhook(ctx context.Context, webhookID, accountID string) error
		ArchiveWebhookTriggerEvent(ctx context.Context, webhookID, webhookTriggerEventID string) error
	}

	// WebhookDataService describes a structure capable of serving traffic related to webhooks.
	WebhookDataService interface {
		ListWebhooksHandler(http.ResponseWriter, *http.Request)
		CreateWebhookHandler(http.ResponseWriter, *http.Request)
		ReadWebhookHandler(http.ResponseWriter, *http.Request)
		ArchiveWebhookHandler(http.ResponseWriter, *http.Request)
		ArchiveWebhookTriggerEventHandler(http.ResponseWriter, *http.Request)
	}
)

var _ validation.ValidatableWithContext = (*WebhookCreationRequestInput)(nil)

// ValidateWithContext validates a WebhookCreationRequestInput.
func (w *WebhookCreationRequestInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(ctx, w,
		validation.Field(&w.Name, validation.Required),
		validation.Field(&w.URL, validation.Required, is.URL),
		validation.Field(&w.Method, validation.Required, validation.In(http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodPost, http.MethodDelete)),
		validation.Field(&w.ContentType, validation.Required, validation.In("application/json", "application/xml")),
		validation.Field(&w.Events, validation.Required),
	)
}

var _ validation.ValidatableWithContext = (*WebhookDatabaseCreationInput)(nil)

// ValidateWithContext validates a WebhookDatabaseCreationInput.
func (w *WebhookDatabaseCreationInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(ctx, w,
		validation.Field(&w.ID, validation.Required),
		validation.Field(&w.Name, validation.Required),
		validation.Field(&w.URL, validation.Required, is.URL),
		validation.Field(&w.Method, validation.Required, validation.In(http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodPost, http.MethodDelete)),
		validation.Field(&w.ContentType, validation.Required, validation.In("application/json", "application/xml")),
		validation.Field(&w.Events, validation.Required),
		validation.Field(&w.BelongsToAccount, validation.Required),
	)
}
