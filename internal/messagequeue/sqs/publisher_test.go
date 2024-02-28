package sqs

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	testutils "github.com/verygoodsoftwarenotvirus/starter/tests/utils"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type mockMessagePublisher struct {
	mock.Mock
}

// SendMessageWithContext is a mock function.
func (m *mockMessagePublisher) SendMessageWithContext(ctx aws.Context, input *sqs.SendMessageInput, opts ...request.Option) (*sqs.SendMessageOutput, error) {
	retVals := m.Called(ctx, input, opts)

	return retVals.Get(0).(*sqs.SendMessageOutput), retVals.Error(1)
}

func Test_sqsPublisher_Publish(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		logger := logging.NewNoopLogger()

		provider := ProvideSQSPublisherProvider(logger, tracing.NewNoopTracerProvider())
		require.NotNil(t, provider)

		a, err := provider.ProvidePublisher(t.Name())
		assert.NotNil(t, a)
		assert.NoError(t, err)

		actual, ok := a.(*sqsPublisher)
		require.True(t, ok)

		ctx := context.Background()
		inputData := &struct {
			Name string `json:"name"`
		}{
			Name: t.Name(),
		}

		mmp := &mockMessagePublisher{}
		mmp.On(
			"SendMessageWithContext",
			testutils.ContextMatcher,
			mock.MatchedBy(func(*sqs.SendMessageInput) bool { return true }),
			[]request.Option(nil),
		).Return(&sqs.SendMessageOutput{}, nil)

		actual.publisher = mmp

		err = actual.Publish(ctx, inputData)
		assert.NoError(t, err)

		mock.AssertExpectationsForObjects(t, mmp)
	})

	T.Run("with error encoding value", func(t *testing.T) {
		t.Parallel()

		logger := logging.NewNoopLogger()

		provider := ProvideSQSPublisherProvider(logger, tracing.NewNoopTracerProvider())
		require.NotNil(t, provider)

		a, err := provider.ProvidePublisher(t.Name())
		assert.NotNil(t, a)
		assert.NoError(t, err)

		actual, ok := a.(*sqsPublisher)
		require.True(t, ok)

		ctx := context.Background()
		inputData := &struct {
			Name json.Number `json:"name"`
		}{
			Name: json.Number(t.Name()),
		}

		err = actual.Publish(ctx, inputData)
		assert.Error(t, err)
	})
}

func TestProvideSQSPublisherProvider(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		logger := logging.NewNoopLogger()

		actual := ProvideSQSPublisherProvider(logger, tracing.NewNoopTracerProvider())
		assert.NotNil(t, actual)
	})
}

func Test_publisherProvider_ProvidePublisher(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		logger := logging.NewNoopLogger()

		provider := ProvideSQSPublisherProvider(logger, tracing.NewNoopTracerProvider())
		require.NotNil(t, provider)

		actual, err := provider.ProvidePublisher(t.Name())
		assert.NotNil(t, actual)
		assert.NoError(t, err)
	})

	T.Run("with cache hit", func(t *testing.T) {
		t.Parallel()

		logger := logging.NewNoopLogger()

		provider := ProvideSQSPublisherProvider(logger, tracing.NewNoopTracerProvider())
		require.NotNil(t, provider)

		actual, err := provider.ProvidePublisher(t.Name())
		assert.NotNil(t, actual)
		assert.NoError(t, err)

		actual, err = provider.ProvidePublisher(t.Name())
		assert.NotNil(t, actual)
		assert.NoError(t, err)
	})
}
