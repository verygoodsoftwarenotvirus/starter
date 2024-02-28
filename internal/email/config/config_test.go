package config

import (
	"context"
	"net/http"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/internal/email/sendgrid"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_ValidateWithContext(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		cfg := &Config{
			Sendgrid: &sendgrid.Config{APIToken: t.Name()},
		}

		require.NoError(t, cfg.ValidateWithContext(ctx))
	})

	T.Run("with invalid token", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		cfg := &Config{
			Provider: "sendgrid",
		}

		require.Error(t, cfg.ValidateWithContext(ctx))
	})
}

func TestConfig_ProvideEmailer(T *testing.T) {
	T.Parallel()

	T.Run("with SendGrid", func(t *testing.T) {
		t.Parallel()

		logger := logging.NewNoopLogger()
		cfg := &Config{
			Provider: ProviderSendgrid,
			Sendgrid: &sendgrid.Config{APIToken: t.Name()},
		}

		actual, err := cfg.ProvideEmailer(logger, tracing.NewNoopTracerProvider(), &http.Client{})
		assert.NotNil(t, actual)
		assert.NoError(t, err)
	})

	T.Run("with invalid provider", func(t *testing.T) {
		t.Parallel()

		logger := logging.NewNoopLogger()
		cfg := &Config{
			Provider: "",
		}

		actual, err := cfg.ProvideEmailer(logger, tracing.NewNoopTracerProvider(), &http.Client{})
		assert.NotNil(t, actual)
		assert.NoError(t, err)
	})
}
