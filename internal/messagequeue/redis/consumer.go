package redis

import (
	"context"
	"sync"

	"github.com/verygoodsoftwarenotvirus/starter/internal/encoding"
	"github.com/verygoodsoftwarenotvirus/starter/internal/messagequeue"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"

	"github.com/go-redis/redis/v8"
)

type (
	subscriptionProvider interface {
		Subscribe(ctx context.Context, channels ...string) *redis.PubSub
	}

	channelProvider interface {
		Channel(...redis.ChannelOption) <-chan *redis.Message
	}

	redisConsumer struct {
		encoder      encoding.ClientEncoder
		logger       logging.Logger
		handlerFunc  func(context.Context, []byte) error
		subscription channelProvider
		topic        string
	}
)

func provideRedisConsumer(ctx context.Context, logger logging.Logger, redisClient subscriptionProvider, tracerProvider tracing.TracerProvider, topic string, handlerFunc func(context.Context, []byte) error) *redisConsumer {
	subscription := redisClient.Subscribe(ctx, topic)

	logger.Debug("subscribed to topic!")

	return &redisConsumer{
		topic:        topic,
		handlerFunc:  handlerFunc,
		subscription: subscription,
		logger:       logging.EnsureLogger(logger),
		encoder:      encoding.ProvideClientEncoder(logger, tracerProvider, encoding.ContentTypeJSON),
	}
}

// Consume reads messages and applies the handler to their payloads.
// Writes errors to the error chan if it isn't nil.
func (r *redisConsumer) Consume(stopChan chan bool, errs chan error) {
	if stopChan == nil {
		stopChan = make(chan bool, 1)
	}
	subChan := r.subscription.Channel()

	for {
		select {
		case msg := <-subChan:
			if err := r.handlerFunc(context.Background(), []byte(msg.Payload)); err != nil {
				r.logger.Error(err, "handling message")
				if errs != nil {
					errs <- err
				}
			}
		case <-stopChan:
			return
		}
	}
}

type consumerProvider struct {
	logger           logging.Logger
	consumerCache    map[string]messagequeue.Consumer
	redisClient      subscriptionProvider
	tracerProvider   tracing.TracerProvider
	consumerCacheHat sync.RWMutex
}

// ProvideRedisConsumerProvider returns a ConsumerProvider for a given address.
func ProvideRedisConsumerProvider(logger logging.Logger, tracerProvider tracing.TracerProvider, cfg Config) messagequeue.ConsumerProvider {
	logger.WithValue("queue_addresses", cfg.QueueAddresses).
		WithValue("username", cfg.Username).
		WithValue("password", cfg.Password).Info("setting up redis consumer")

	var redisClient subscriptionProvider
	if len(cfg.QueueAddresses) > 1 {
		redisClient = redis.NewClusterClient(&redis.ClusterOptions{
			Addrs:    cfg.QueueAddresses,
			Username: cfg.Username,
			Password: cfg.Password,
		})
	} else if len(cfg.QueueAddresses) == 1 {
		redisClient = redis.NewClient(&redis.Options{
			Addr:     cfg.QueueAddresses[0],
			Username: cfg.Username,
			Password: cfg.Password,
		})
	}

	return &consumerProvider{
		logger:         logging.EnsureLogger(logger),
		redisClient:    redisClient,
		tracerProvider: tracerProvider,
		consumerCache:  map[string]messagequeue.Consumer{},
	}
}

// ProvideConsumer returns a Consumer for a given topic.
func (p *consumerProvider) ProvideConsumer(ctx context.Context, topic string, handlerFunc func(context.Context, []byte) error) (messagequeue.Consumer, error) {
	logger := logging.EnsureLogger(p.logger).WithValue("topic", topic)

	if topic == "" {
		return nil, ErrEmptyInputProvided
	}

	p.consumerCacheHat.Lock()
	defer p.consumerCacheHat.Unlock()
	if cachedPub, ok := p.consumerCache[topic]; ok {
		return cachedPub, nil
	}

	c := provideRedisConsumer(ctx, logger, p.redisClient, p.tracerProvider, topic, handlerFunc)
	p.consumerCache[topic] = c

	return c, nil
}
