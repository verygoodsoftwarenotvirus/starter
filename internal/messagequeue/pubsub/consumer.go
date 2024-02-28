package pubsub

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/verygoodsoftwarenotvirus/starter/internal/encoding"
	"github.com/verygoodsoftwarenotvirus/starter/internal/messagequeue"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"

	"cloud.google.com/go/pubsub"
)

type (
	messageConsumer interface {
		Topic(string) *pubsub.Topic
		CreateSubscription(ctx context.Context, id string, cfg pubsub.SubscriptionConfig) (*pubsub.Subscription, error)
	}

	pubSubConsumer struct {
		tracer      tracing.Tracer
		encoder     encoding.ClientEncoder
		logger      logging.Logger
		consumer    messageConsumer
		handlerFunc func(context.Context, []byte) error
		topic       string
	}
)

// buildPubSubConsumer provides a Pub/Sub-backed pubSubConsumer.
func buildPubSubConsumer(
	logger logging.Logger,
	pubsubClient *pubsub.Client,
	tracerProvider tracing.TracerProvider,
	topic string,
	handlerFunc func(context.Context, []byte) error,
) messagequeue.Consumer {
	return &pubSubConsumer{
		topic:       topic,
		encoder:     encoding.ProvideClientEncoder(logger, tracerProvider, encoding.ContentTypeJSON),
		logger:      logging.EnsureLogger(logger),
		consumer:    pubsubClient,
		handlerFunc: handlerFunc,
		tracer:      tracing.NewTracer(tracing.EnsureTracerProvider(tracerProvider).Tracer(fmt.Sprintf("%s_consumer", topic))),
	}
}

func (c *pubSubConsumer) Consume(stopChan chan bool, errors chan error) {
	if stopChan == nil {
		stopChan = make(chan bool, 1)
	}

	ctx := context.Background()
	sub, err := c.consumer.CreateSubscription(ctx, c.topic, pubsub.SubscriptionConfig{Topic: c.consumer.Topic(c.topic)})
	if err != nil {
		errors <- err
		return
	}

	go func() {
		<-stopChan
		if err = sub.Delete(ctx); err != nil {
			errors <- err
		}
	}()

	if err = sub.Receive(ctx, func(receivedContext context.Context, m *pubsub.Message) {
		if handleErr := c.handlerFunc(receivedContext, m.Data); handleErr != nil {
			errors <- err
		} else {
			m.Ack()
		}
	}); err != nil {
		log.Println(err)
	}
}

type pubsubConsumerProvider struct {
	logger           logging.Logger
	consumerCache    map[string]messagequeue.Consumer
	pubsubClient     *pubsub.Client
	tracerProvider   tracing.TracerProvider
	consumerCacheHat sync.RWMutex
}

// ProvidePubSubConsumerProvider returns a ConsumerProvider for a given address.
func ProvidePubSubConsumerProvider(logger logging.Logger, tracerProvider tracing.TracerProvider, client *pubsub.Client) messagequeue.ConsumerProvider {
	return &pubsubConsumerProvider{
		logger:         logging.EnsureLogger(logger),
		pubsubClient:   client,
		consumerCache:  map[string]messagequeue.Consumer{},
		tracerProvider: tracerProvider,
	}
}

// Close closes the connection topic.
func (p *pubsubConsumerProvider) Close() {
	if err := p.pubsubClient.Close(); err != nil {
		p.logger.Error(err, "closing pubsub connection")
	}
}

// ProvideConsumer returns a pubSubConsumer for a given topic.
func (p *pubsubConsumerProvider) ProvideConsumer(_ context.Context, topic string, handlerFunc func(context.Context, []byte) error) (messagequeue.Consumer, error) {
	if topic == "" {
		return nil, messagequeue.ErrEmptyTopicName
	}

	logger := logging.EnsureLogger(p.logger.Clone())

	p.consumerCacheHat.Lock()
	defer p.consumerCacheHat.Unlock()
	if cachedPub, ok := p.consumerCache[topic]; ok {
		return cachedPub, nil
	}

	pub := buildPubSubConsumer(logger, p.pubsubClient, p.tracerProvider, topic, handlerFunc)
	p.consumerCache[topic] = pub

	return pub, nil
}
