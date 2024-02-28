package authentication_test

import (
	"context"
	"testing"
	"time"

	"github.com/verygoodsoftwarenotvirus/starter/internal/authentication"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
)

const (
	argon2HashedExamplePassword = `$argon2id$v=19$m=65536,t=1,p=2$C+YWiNi21e94acF3ip8UGA$Ru6oL96HZSP7cVcfAbRwOuK9+vwBo/BLhCzOrGrMH0M`
)

func TestArgon2_HashPassword(T *testing.T) {
	T.Parallel()

	x := authentication.ProvideArgon2Authenticator(logging.NewNoopLogger(), tracing.NewNoopTracerProvider())

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()

		actual, err := x.HashPassword(ctx, examplePassword)
		assert.NoError(t, err)
		assert.NotEmpty(t, actual)
	})
}

func TestArgon2_ValidateLogin(T *testing.T) {
	T.Parallel()

	x := authentication.ProvideArgon2Authenticator(logging.NewNoopLogger(), tracing.NewNoopTracerProvider())

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()

		code, err := totp.GenerateCode(exampleTwoFactorSecret, time.Now().UTC())
		assert.NoError(t, err, "error generating code to validate login")

		valid, err := x.CredentialsAreValid(
			ctx,
			argon2HashedExamplePassword,
			examplePassword,
			exampleTwoFactorSecret,
			code,
		)
		assert.NoError(t, err, "unexpected error encountered validating login: %v", err)
		assert.True(t, valid)
	})

	T.Run("without two factor secret", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		valid, err := x.CredentialsAreValid(
			ctx,
			argon2HashedExamplePassword,
			examplePassword,
			"",
			"",
		)
		assert.NoError(t, err, "unexpected error encountered validating login: %v", err)
		assert.True(t, valid)
	})

	T.Run("with error determining if password matches", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()

		valid, err := x.CredentialsAreValid(
			ctx,
			"       blah blah blah not a valid hash lol           ",
			examplePassword,
			"",
			"",
		)
		assert.Error(t, err, "unexpected error encountered validating login: %v", err)
		assert.False(t, valid)
	})

	T.Run("with non-matching password", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()

		code, err := totp.GenerateCode(exampleTwoFactorSecret, time.Now().UTC())
		assert.NoError(t, err, "error generating code to validate login")

		valid, err := x.CredentialsAreValid(
			ctx,
			argon2HashedExamplePassword,
			"examplePassword",
			exampleTwoFactorSecret,
			code,
		)
		assert.Error(t, err, "unexpected error encountered validating login: %v", err)
		assert.False(t, valid)
	})

	T.Run("with invalid code", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()

		valid, err := x.CredentialsAreValid(
			ctx,
			argon2HashedExamplePassword,
			examplePassword,
			exampleTwoFactorSecret,
			"CODE",
		)
		assert.Error(t, err, "unexpected error encountered validating login: %v", err)
		assert.True(t, valid)
	})
}

func TestProvideArgon2Authenticator(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		authentication.ProvideArgon2Authenticator(logging.NewNoopLogger(), tracing.NewNoopTracerProvider())
	})
}
