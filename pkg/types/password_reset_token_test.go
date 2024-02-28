package types

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPasswordResetTokenCreationRequestInput_ValidateWithContext(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		x := &PasswordResetTokenCreationRequestInput{
			EmailAddress: t.Name(),
		}

		assert.NoError(t, x.ValidateWithContext(ctx))
	})
}

func TestPasswordResetTokenDatabaseCreationInput_ValidateWithContext(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		x := &PasswordResetTokenDatabaseCreationInput{
			ID:            t.Name(),
			Token:         t.Name(),
			ExpiresAt:     time.Now(),
			BelongsToUser: t.Name(),
		}

		assert.NoError(t, x.ValidateWithContext(ctx))
	})
}

func TestPasswordResetTokenRedemptionRequestInput_ValidateWithContext(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		x := &PasswordResetTokenRedemptionRequestInput{
			Token:       t.Name(),
			NewPassword: t.Name(),
		}

		assert.NoError(t, x.ValidateWithContext(ctx))
	})
}

func TestUsernameReminderRequestInput_ValidateWithContext(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		x := &UsernameReminderRequestInput{
			EmailAddress: t.Name(),
		}

		assert.NoError(t, x.ValidateWithContext(ctx))
	})
}
