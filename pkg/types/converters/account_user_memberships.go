package converters

import (
	"github.com/verygoodsoftwarenotvirus/starter/internal/identifiers"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

// ConvertAccountUserMembershipToAccountUserMembershipDatabaseCreationInput builds a faked AccountUserMembershipCreationRequestInput.
func ConvertAccountUserMembershipToAccountUserMembershipDatabaseCreationInput(account *types.AccountUserMembership) *types.AccountUserMembershipDatabaseCreationInput {
	return &types.AccountUserMembershipDatabaseCreationInput{
		ID:          identifiers.New(),
		Reason:      "",
		UserID:      account.BelongsToUser,
		AccountID:   account.ID,
		AccountRole: account.AccountRole,
	}
}
