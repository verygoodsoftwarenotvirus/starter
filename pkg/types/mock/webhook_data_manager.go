package mocktypes

import (
	"context"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"

	"github.com/stretchr/testify/mock"
)

var _ types.WebhookDataManager = (*WebhookDataManagerMock)(nil)

// WebhookDataManagerMock is a mocked types.WebhookDataManager for testing.
type WebhookDataManagerMock struct {
	mock.Mock
}

// WebhookExists satisfies our WebhookDataManagerMock interface.
func (m *WebhookDataManagerMock) WebhookExists(ctx context.Context, webhookID, accountID string) (bool, error) {
	args := m.Called(ctx, webhookID, accountID)
	return args.Bool(0), args.Error(1)
}

// GetWebhook satisfies our WebhookDataManagerMock interface.
func (m *WebhookDataManagerMock) GetWebhook(ctx context.Context, webhookID, accountID string) (*types.Webhook, error) {
	args := m.Called(ctx, webhookID, accountID)
	return args.Get(0).(*types.Webhook), args.Error(1)
}

// GetWebhooks satisfies our WebhookDataManagerMock interface.
func (m *WebhookDataManagerMock) GetWebhooks(ctx context.Context, accountID string, filter *types.QueryFilter) (*types.QueryFilteredResult[types.Webhook], error) {
	args := m.Called(ctx, accountID, filter)
	return args.Get(0).(*types.QueryFilteredResult[types.Webhook]), args.Error(1)
}

// GetWebhooksForAccountAndEvent satisfies our WebhookDataManagerMock interface.
func (m *WebhookDataManagerMock) GetWebhooksForAccountAndEvent(ctx context.Context, accountID string, eventType types.ServiceEventType) ([]*types.Webhook, error) {
	args := m.Called(ctx, accountID, eventType)
	return args.Get(0).([]*types.Webhook), args.Error(1)
}

// GetAllWebhooks satisfies our WebhookDataManagerMock interface.
func (m *WebhookDataManagerMock) GetAllWebhooks(ctx context.Context, results chan []*types.Webhook, bucketSize uint16) error {
	return m.Called(ctx, results, bucketSize).Error(0)
}

// CreateWebhook satisfies our WebhookDataManagerMock interface.
func (m *WebhookDataManagerMock) CreateWebhook(ctx context.Context, input *types.WebhookDatabaseCreationInput) (*types.Webhook, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(*types.Webhook), args.Error(1)
}

// ArchiveWebhook satisfies our WebhookDataManagerMock interface.
func (m *WebhookDataManagerMock) ArchiveWebhook(ctx context.Context, webhookID, accountID string) error {
	return m.Called(ctx, webhookID, accountID).Error(0)
}

// ArchiveWebhookTriggerEvent satisfies our WebhookDataManagerMock interface.
func (m *WebhookDataManagerMock) ArchiveWebhookTriggerEvent(ctx context.Context, webhookID, webhookTriggerEventID string) error {
	return m.Called(ctx, webhookID, webhookTriggerEventID).Error(0)
}
