package oteltracehttp

import (
	"context"
	"errors"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"

	"github.com/stretchr/testify/assert"
)

func Test_tracingErrorHandler_Handle(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		errorHandler{logger: logging.NewNoopLogger()}.Handle(errors.New("blah"))
	})
}

func TestConfig_SetupOtelHTTP(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		cfg := &Config{
			CollectorEndpoint:         "blah blah blah",
			ServiceName:               t.Name(),
			SpanCollectionProbability: 0,
		}

		actual, err := SetupOtelHTTP(ctx, cfg)
		assert.NoError(t, err)
		assert.NotNil(t, actual)
	})
}
