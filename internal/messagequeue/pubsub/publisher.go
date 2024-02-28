package pubsub

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"github.com/verygoodsoftwarenotvirus/starter/internal/encoding"
	"github.com/verygoodsoftwarenotvirus/starter/internal/messagequeue"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"

	"cloud.google.com/go/pubsub"
)

type (
	messagePublisher interface {
		Stop()
		Publish(context.Context, *pubsub.Message) *pubsub.PublishResult
	}

	pubSubPublisher struct {
		tracer    tracing.Tracer
		encoder   encoding.ClientEncoder
		logger    logging.Logger
		publisher messagePublisher
		topic     string
	}
)

// buildPubSubPublisher provides a Pub/Sub-backed pubSubPublisher.
func buildPubSubPublisher(logger logging.Logger, pubsubClient *pubsub.Topic, tracerProvider tracing.TracerProvider, topic string) *pubSubPublisher {
	return &pubSubPublisher{
		topic:     topic,
		encoder:   encoding.ProvideClientEncoder(logger, tracerProvider, encoding.ContentTypeJSON),
		logger:    logging.EnsureLogger(logger),
		publisher: pubsubClient,
		tracer:    tracing.NewTracer(tracing.EnsureTracerProvider(tracerProvider).Tracer(fmt.Sprintf("%s_publisher", topic))),
	}
}

// Stop calls Stop on the topic.
func (p *pubSubPublisher) Stop() {
	p.publisher.Stop()
}

type publisherProvider struct {
	logger            logging.Logger
	publisherCache    map[string]messagequeue.Publisher
	pubsubClient      *pubsub.Client
	tracerProvider    tracing.TracerProvider
	publisherCacheHat sync.RWMutex
}

// ProvidePubSubPublisherProvider returns a PublisherProvider for a given address.
func ProvidePubSubPublisherProvider(logger logging.Logger, tracerProvider tracing.TracerProvider, client *pubsub.Client) messagequeue.PublisherProvider {
	return &publisherProvider{
		logger:         logging.EnsureLogger(logger),
		pubsubClient:   client,
		publisherCache: map[string]messagequeue.Publisher{},
		tracerProvider: tracerProvider,
	}
}

// Close closes the connection topic.
func (p *publisherProvider) Close() {
	if err := p.pubsubClient.Close(); err != nil {
		p.logger.Error(err, "closing pubsub connection")
	}
}

// ProvidePublisher returns a pubSubPublisher for a given topic.
func (p *publisherProvider) ProvidePublisher(topic string) (messagequeue.Publisher, error) {
	if topic == "" {
		return nil, messagequeue.ErrEmptyTopicName
	}

	logger := logging.EnsureLogger(p.logger.Clone())

	p.publisherCacheHat.Lock()
	defer p.publisherCacheHat.Unlock()
	if cachedPub, ok := p.publisherCache[topic]; ok {
		return cachedPub, nil
	}

	t := p.pubsubClient.Topic(topic)

	pub := buildPubSubPublisher(logger, t, p.tracerProvider, topic)
	p.publisherCache[topic] = pub

	return pub, nil
}

func (p *pubSubPublisher) Publish(ctx context.Context, data any) error {
	_, span := p.tracer.StartSpan(ctx)
	defer span.End()

	logger := p.logger.Clone()

	var b bytes.Buffer
	if err := p.encoder.Encode(ctx, &b, data); err != nil {
		return observability.PrepareError(err, span, "encoding topic message")
	}

	msg := &pubsub.Message{Data: b.Bytes()}
	result := p.publisher.Publish(ctx, msg)

	<-result.Ready()

	// The Get method blocks until a server-generated ID or an error is returned for the published message.
	if _, resultCheckErr := result.Get(ctx); resultCheckErr != nil {
		observability.AcknowledgeError(resultCheckErr, logger, span, "publishing pubsub message")
	}

	logger.Debug("published message")

	return nil
}
