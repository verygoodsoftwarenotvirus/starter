package messagequeue

import (
	"context"
	"errors"
)

type (
	// Publisher produces events onto a queue.
	Publisher interface {
		Stop()
		Publish(ctx context.Context, data any) error
	}

	// PublisherProvider is a function that provides a Publisher for a given topic.
	PublisherProvider interface {
		Close()
		ProvidePublisher(topic string) (Publisher, error)
	}
)

var (
	// ErrEmptyTopicName is returned when a topic name is empty.
	ErrEmptyTopicName = errors.New("empty topic name")
)

type noopPublisher struct{}

// Publish does nothing.
func (n *noopPublisher) Publish(_ context.Context, _ any) error { return nil }

// Stop does nothing.
func (n *noopPublisher) Stop() {}

// NewNoopPublisher is a noop Publisher.
func NewNoopPublisher() Publisher {
	return &noopPublisher{}
}

type noopPublisherProvider struct{}

// ProvidePublisher does nothing.
func (n *noopPublisherProvider) ProvidePublisher(_ string) (Publisher, error) {
	return NewNoopPublisher(), nil
}

// Close does nothing.
func (n *noopPublisherProvider) Close() {}

// NewNoopPublisherProvider is a noop PublisherProvider.
func NewNoopPublisherProvider() PublisherProvider {
	return &noopPublisherProvider{}
}
