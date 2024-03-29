package types

import (
	"context"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/internal/authorization"

	"github.com/stretchr/testify/assert"
)

func TestAddUserToAccountInput_ValidateWithContext(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		x := &AccountUserMembershipCreationRequestInput{
			UserID: "123",
		}

		assert.NoError(t, x.ValidateWithContext(ctx))
	})
}

func TestTransferAccountOwnershipInput_ValidateWithContext(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		x := &AccountOwnershipTransferInput{
			CurrentOwner: "123",
			NewOwner:     "321",
			Reason:       t.Name(),
		}

		assert.NoError(t, x.ValidateWithContext(ctx))
	})
}

func TestModifyUserPermissionsInput_ValidateWithContext(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		x := &ModifyUserPermissionsInput{
			NewRole: authorization.AccountMemberRole.String(),
			Reason:  t.Name(),
		}

		assert.NoError(t, x.ValidateWithContext(ctx))
	})
}
