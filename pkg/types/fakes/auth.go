package fakes

import (
	"github.com/verygoodsoftwarenotvirus/starter/internal/authorization"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/converters"

	fake "github.com/brianvoe/gofakeit/v7"
)

// BuildFakeSessionContextData builds a faked AccountUserMembershipCreationRequestInput.
func BuildFakeSessionContextData() *types.SessionContextData {
	return &types.SessionContextData{
		AccountPermissions: map[string]authorization.AccountRolePermissionsChecker{},
		Requester: types.RequesterInfo{
			ServicePermissions:       nil,
			AccountStatus:            string(types.GoodStandingUserAccountStatus),
			AccountStatusExplanation: "fake",
			UserID:                   BuildFakeID(),
			EmailAddress:             fake.Email(),
			Username:                 buildUniqueString(),
		},
		ActiveAccountID: BuildFakeID(),
	}
}

// BuildFakeAccountUserMembershipCreationRequestInput builds a faked AccountUserMembershipCreationRequestInput.
func BuildFakeAccountUserMembershipCreationRequestInput() *types.AccountUserMembershipCreationRequestInput {
	return &types.AccountUserMembershipCreationRequestInput{
		Reason: fake.Sentence(10),
		UserID: BuildFakeID(),
	}
}

// BuildFakeAccountUserMembershipDatabaseCreationInput builds a faked AccountUserMembershipCreationRequestInput.
func BuildFakeAccountUserMembershipDatabaseCreationInput() *types.AccountUserMembershipDatabaseCreationInput {
	input := BuildFakeAccountUserMembershipCreationRequestInput()

	return converters.ConvertAccountUserMembershipCreationRequestInputToAccountUserMembershipDatabaseCreationInput(input)
}

// BuildFakeUserPermissionModificationInput builds a faked ModifyUserPermissionsInput.
func BuildFakeUserPermissionModificationInput() *types.ModifyUserPermissionsInput {
	return &types.ModifyUserPermissionsInput{
		Reason:  fake.Sentence(10),
		NewRole: authorization.AccountMemberRole.String(),
	}
}

// BuildFakeTransferAccountOwnershipInput builds a faked AccountOwnershipTransferInput.
func BuildFakeTransferAccountOwnershipInput() *types.AccountOwnershipTransferInput {
	return &types.AccountOwnershipTransferInput{
		Reason:       fake.Sentence(10),
		CurrentOwner: fake.UUID(),
		NewOwner:     fake.UUID(),
	}
}

// BuildFakeChangeActiveAccountInput builds a faked ChangeActiveAccountInput.
func BuildFakeChangeActiveAccountInput() *types.ChangeActiveAccountInput {
	return &types.ChangeActiveAccountInput{
		AccountID: fake.UUID(),
	}
}
