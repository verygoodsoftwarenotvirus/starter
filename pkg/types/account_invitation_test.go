package types

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAccountInvitationCreationInput_ValidateWithContext(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		x := &AccountInvitationCreationRequestInput{
			ToEmail: t.Name(),
		}

		assert.NoError(t, x.ValidateWithContext(ctx))
	})
}

func TestAccountInvitationUpdateRequestInput_ValidateWithContext(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		x := &AccountInvitationUpdateRequestInput{
			Token: t.Name(),
		}

		assert.NoError(t, x.ValidateWithContext(ctx))
	})
}
