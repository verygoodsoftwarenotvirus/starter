package config

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/verygoodsoftwarenotvirus/starter/internal/messagequeue"
	"github.com/verygoodsoftwarenotvirus/starter/internal/messagequeue/pubsub"
	"github.com/verygoodsoftwarenotvirus/starter/internal/messagequeue/redis"
	"github.com/verygoodsoftwarenotvirus/starter/internal/messagequeue/sqs"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"

	ps "cloud.google.com/go/pubsub"
)

const (
	// ProviderRedis is used to refer to redis.
	ProviderRedis = "redis"
	// ProviderSQS is used to refer to sqs.
	ProviderSQS = "sqs"
	// ProviderPubSub is used to refer to GCP Pub/Sub.
	ProviderPubSub = "pubsub"
)

type (
	// Provider is used to indicate what messaging provider we'll use.
	Provider string

	// RedisConfig configures a Redis-backed consumer.
	RedisConfig struct {
		QueueAddress string `json:"message_queue_address,omitempty" toml:"message_queue_address,omitempty"`
	}

	// SQSConfig configures a SQS-backed consumer.
	SQSConfig struct {
		QueueAddress string `json:"message_queue_address,omitempty" toml:"message_queue_address,omitempty"`
	}

	// MessageQueueConfig is used to indicate how the messaging provider should be configured.
	MessageQueueConfig struct {
		_ struct{} `json:"-"`

		Provider Provider      `json:"provider,omitempty" toml:"provider,omitempty"`
		SQS      sqs.Config    `json:"sqs,omitempty"      toml:"sqs,omitempty"`
		PubSub   pubsub.Config `json:"pubsub,omitempty"   toml:"pubsub,omitempty"`
		Redis    redis.Config  `json:"redis,omitempty"    toml:"redis,omitempty"`
	}

	// Config is used to indicate how the messaging provider should be configured.
	Config struct {
		_ struct{} `json:"-"`

		Consumers  MessageQueueConfig `json:"consumers,omitempty"  toml:"consumers,omitempty"`
		Publishers MessageQueueConfig `json:"publishers,omitempty" toml:"publishers,omitempty"`
	}
)

func cleanString(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// ProvideConsumerProvider provides a PublisherProvider.
func ProvideConsumerProvider(ctx context.Context, logger logging.Logger, tracerProvider tracing.TracerProvider, c *Config) (messagequeue.ConsumerProvider, error) {
	switch cleanString(string(c.Consumers.Provider)) {
	case ProviderRedis:
		return redis.ProvideRedisConsumerProvider(logger, tracerProvider, c.Consumers.Redis), nil
	case ProviderPubSub:
		client, err := ps.NewClient(ctx, os.Getenv("GOOGLE_CLOUD_PROJECT_ID"))
		if err != nil {
			return nil, fmt.Errorf("establishing PubSub client: %w", err)
		}

		return pubsub.ProvidePubSubConsumerProvider(logger, tracerProvider, client), nil
	default:
		return nil, fmt.Errorf("invalid provider: %q", c.Consumers.Provider)
	}
}

// ProvidePublisherProvider provides a PublisherProvider.
func ProvidePublisherProvider(ctx context.Context, logger logging.Logger, tracerProvider tracing.TracerProvider, c *Config) (messagequeue.PublisherProvider, error) {
	switch cleanString(string(c.Publishers.Provider)) {
	case ProviderRedis:
		return redis.ProvideRedisPublisherProvider(logger, tracerProvider, c.Publishers.Redis), nil
	case ProviderSQS:
		return sqs.ProvideSQSPublisherProvider(logger, tracerProvider), nil
	case ProviderPubSub:
		client, err := ps.NewClient(ctx, os.Getenv("GOOGLE_CLOUD_PROJECT_ID"))
		if err != nil {
			return nil, fmt.Errorf("establishing PubSub client: %w", err)
		}

		return pubsub.ProvidePubSubPublisherProvider(logger, tracerProvider, client), nil
	default:
		return nil, fmt.Errorf("invalid publisher provider: %q", c.Publishers.Provider)
	}
}
