package config

import (
	"context"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"

	"github.com/stretchr/testify/assert"
)

func Test_cleanString(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		assert.NotEmpty(t, cleanString(t.Name()))
	})
}

func TestProvideConsumerProvider(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		logger := logging.NewNoopLogger()
		cfg := &Config{
			Consumers: MessageQueueConfig{
				Provider: ProviderRedis,
			},
		}

		provider, err := ProvideConsumerProvider(ctx, logger, tracing.NewNoopTracerProvider(), cfg)
		assert.NoError(t, err)
		assert.NotNil(t, provider)
	})

	T.Run("with invalid provider", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		logger := logging.NewNoopLogger()
		cfg := &Config{}

		provider, err := ProvideConsumerProvider(ctx, logger, tracing.NewNoopTracerProvider(), cfg)
		assert.Error(t, err)
		assert.Nil(t, provider)
	})
}

func TestProvidePublisherProvider(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		logger := logging.NewNoopLogger()
		cfg := &Config{
			Publishers: MessageQueueConfig{
				Provider: ProviderRedis,
			},
		}

		provider, err := ProvidePublisherProvider(ctx, logger, tracing.NewNoopTracerProvider(), cfg)
		assert.NoError(t, err)
		assert.NotNil(t, provider)
	})

	T.Run("with invalid provider", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		logger := logging.NewNoopLogger()
		cfg := &Config{}

		provider, err := ProvidePublisherProvider(ctx, logger, tracing.NewNoopTracerProvider(), cfg)
		assert.Error(t, err)
		assert.Nil(t, provider)
	})
}
