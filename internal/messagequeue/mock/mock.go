package mockpublishers

import (
	"context"

	"github.com/verygoodsoftwarenotvirus/starter/internal/messagequeue"

	"github.com/stretchr/testify/mock"
)

var _ messagequeue.Publisher = (*Publisher)(nil)

// Publisher implements our interface.
type Publisher struct {
	mock.Mock
}

// Publish implements our interface.
func (m *Publisher) Publish(ctx context.Context, data any) error {
	return m.Called(ctx, data).Error(0)
}

// Stop implements our interface.
func (m *Publisher) Stop() {
	m.Called()
}

// ProducerProvider implements our interface.
type ProducerProvider struct {
	mock.Mock
}

// ProvidePublisher implements our interface.
func (m *ProducerProvider) ProvidePublisher(topic string) (messagequeue.Publisher, error) {
	args := m.Called(topic)

	return args.Get(0).(messagequeue.Publisher), args.Error(1)
}

// Close implements our interface.
func (m *ProducerProvider) Close() {
	m.Called()
}
