package tracing

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewTracer(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		assert.NotNil(t, NewTracerForTest(t.Name()))
	})
}

func Test_otelSpanManager_StartSpan(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		NewTracerForTest(t.Name()).StartSpan(context.Background())
	})
}

func Test_otelSpanManager_StartCustomSpan(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		NewTracerForTest(t.Name()).StartCustomSpan(ctx, t.Name())
	})
}
