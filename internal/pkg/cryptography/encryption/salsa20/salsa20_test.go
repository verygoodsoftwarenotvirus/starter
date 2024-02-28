package salsa20

import (
	"context"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/internal/pkg/random"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStandardEncryptor(T *testing.T) {
	T.Parallel()

	T.Run("basic operation", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		expected := t.Name()
		secret, err := random.GenerateHexEncodedString(ctx, 16)
		require.NoError(t, err)

		encryptor, err := NewEncryptorDecryptor(tracing.NewNoopTracerProvider(), logging.NewNoopLogger(), []byte(secret))
		require.NotNil(t, encryptor)
		require.NoError(t, err)

		encrypted, err := encryptor.Encrypt(ctx, expected)
		assert.NoError(t, err)
		assert.NotEmpty(t, encrypted)

		encrypted2, err := encryptor.Encrypt(ctx, expected)
		assert.NoError(t, err)
		assert.NotEmpty(t, encrypted2)

		assert.Equal(t, encrypted, encrypted2)

		actual, err := encryptor.Decrypt(ctx, encrypted)
		assert.NoError(t, err)
		assert.Equal(t, expected, actual)
	})
}
