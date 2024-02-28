package rudderstack

import (
	"context"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"

	"github.com/stretchr/testify/require"
)

func TestNewRudderstackEventReporter(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		logger := logging.NewNoopLogger()
		cfg := &Config{
			APIKey:       t.Name(),
			DataPlaneURL: t.Name(),
		}

		collector, err := NewRudderstackEventReporter(logger, tracing.NewNoopTracerProvider(), cfg)
		require.NoError(t, err)
		require.NotNil(t, collector)
	})

	T.Run("with nil config", func(t *testing.T) {
		t.Parallel()

		logger := logging.NewNoopLogger()

		collector, err := NewRudderstackEventReporter(logger, tracing.NewNoopTracerProvider(), nil)
		require.Error(t, err)
		require.Nil(t, collector)
	})

	T.Run("with empty API key", func(t *testing.T) {
		t.Parallel()

		logger := logging.NewNoopLogger()
		cfg := &Config{
			APIKey:       "",
			DataPlaneURL: t.Name(),
		}

		collector, err := NewRudderstackEventReporter(logger, tracing.NewNoopTracerProvider(), cfg)
		require.Error(t, err)
		require.Nil(t, collector)
	})

	T.Run("with empty DataPlane URL", func(t *testing.T) {
		t.Parallel()

		logger := logging.NewNoopLogger()
		cfg := &Config{
			APIKey:       t.Name(),
			DataPlaneURL: "",
		}

		collector, err := NewRudderstackEventReporter(logger, tracing.NewNoopTracerProvider(), cfg)
		require.Error(t, err)
		require.Nil(t, collector)
	})
}

func TestRudderstackEventReporter_Close(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		logger := logging.NewNoopLogger()
		cfg := &Config{
			APIKey:       t.Name(),
			DataPlaneURL: t.Name(),
		}

		collector, err := NewRudderstackEventReporter(logger, tracing.NewNoopTracerProvider(), cfg)
		require.NoError(t, err)
		require.NotNil(t, collector)

		collector.Close()
	})
}

func TestRudderstackEventReporter_AddUser(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		logger := logging.NewNoopLogger()
		exampleUserID := fakes.BuildFakeID()
		properties := map[string]any{
			"test.name": t.Name(),
		}

		cfg := &Config{
			APIKey:       t.Name(),
			DataPlaneURL: t.Name(),
		}

		collector, err := NewRudderstackEventReporter(logger, tracing.NewNoopTracerProvider(), cfg)
		require.NoError(t, err)
		require.NotNil(t, collector)

		require.NoError(t, collector.AddUser(ctx, exampleUserID, properties))
	})
}

func TestRudderstackEventReporter_EventOccurred(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		logger := logging.NewNoopLogger()
		exampleUserID := fakes.BuildFakeID()
		properties := map[string]any{
			"test.name": t.Name(),
		}

		cfg := &Config{
			APIKey:       t.Name(),
			DataPlaneURL: t.Name(),
		}

		collector, err := NewRudderstackEventReporter(logger, tracing.NewNoopTracerProvider(), cfg)
		require.NoError(t, err)
		require.NotNil(t, collector)

		require.NoError(t, collector.EventOccurred(ctx, types.ServiceEventType(t.Name()), exampleUserID, properties))
	})
}
