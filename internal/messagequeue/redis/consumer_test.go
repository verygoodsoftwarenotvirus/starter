package redis

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/verygoodsoftwarenotvirus/starter/internal/messagequeue"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func buildRedisBackedConsumer(t *testing.T, ctx context.Context, cfg *Config, topic string, hf func(context.Context, []byte) error) messagequeue.Consumer {
	t.Helper()

	provider := ProvideRedisConsumerProvider(
		logging.NewNoopLogger(),
		tracing.NewNoopTracerProvider(),
		*cfg,
	)

	consumer, err := provider.ProvideConsumer(ctx, topic, hf)
	require.NoError(t, err)

	return consumer
}

func Test_redisConsumer_Consume(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()

		cfg, containerShutdown := buildContainerBackedRedisConfig(t, ctx)
		defer func() {
			assert.NoError(t, containerShutdown(ctx))
		}()

		hf := func(context.Context, []byte) error {
			return nil
		}

		consumer := buildRedisBackedConsumer(t, ctx, cfg, t.Name(), hf)
		require.NotNil(t, consumer)

		stopChan := make(chan bool)
		errorsChan := make(chan error)
		go consumer.Consume(stopChan, errorsChan)

		publisher := buildRedisBackedPublisher(t, cfg, t.Name())
		require.NoError(t, publisher.Publish(ctx, []byte("blah")))

		<-time.After(time.Second)
		stopChan <- true
	})

	T.Run("with error handling message", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()

		cfg, containerShutdown := buildContainerBackedRedisConfig(t, ctx)
		defer func() {
			assert.NoError(t, containerShutdown(ctx))
		}()

		anticipatedError := errors.New("blah")
		hf := func(context.Context, []byte) error {
			return anticipatedError
		}

		consumer := buildRedisBackedConsumer(t, ctx, cfg, t.Name(), hf)
		require.NotNil(t, consumer)

		stopChan := make(chan bool)
		errorsChan := make(chan error)
		go consumer.Consume(stopChan, errorsChan)

		publisher := buildRedisBackedPublisher(t, cfg, t.Name())
		require.NoError(t, publisher.Publish(ctx, []byte("blah")))

		err := <-errorsChan
		assert.Error(t, err)
		assert.Equal(t, anticipatedError, err)

		stopChan <- true
	})
}

func Test_consumerProvider_ProvideConsumer(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		logger := logging.NewNoopLogger()
		cfg := Config{
			QueueAddresses: []string{t.Name()},
		}

		conPro := ProvideRedisConsumerProvider(logger, tracing.NewNoopTracerProvider(), cfg)
		require.NotNil(t, conPro)

		ctx := context.Background()

		actual, err := conPro.ProvideConsumer(ctx, t.Name(), nil)
		assert.NoError(t, err)
		assert.NotNil(t, actual)
	})

	T.Run("hitting cache", func(t *testing.T) {
		t.Parallel()

		logger := logging.NewNoopLogger()
		cfg := Config{
			QueueAddresses: []string{t.Name()},
		}

		conPro := ProvideRedisConsumerProvider(logger, tracing.NewNoopTracerProvider(), cfg)
		require.NotNil(t, conPro)

		ctx := context.Background()

		actual, err := conPro.ProvideConsumer(ctx, t.Name(), nil)
		assert.NoError(t, err)
		assert.NotNil(t, actual)

		actual, err = conPro.ProvideConsumer(ctx, t.Name(), nil)
		assert.NoError(t, err)
		assert.NotNil(t, actual)
	})
}
