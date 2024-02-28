package converters

import (
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

// ConvertAccountInvitationCreationInputToAccountInvitationDatabaseCreationInput creates a AccountInvitationDatabaseCreationInput from a AccountInvitationCreationRequestInput.
func ConvertAccountInvitationCreationInputToAccountInvitationDatabaseCreationInput(input *types.AccountInvitationCreationRequestInput) *types.AccountInvitationDatabaseCreationInput {
	x := &types.AccountInvitationDatabaseCreationInput{
		ToEmail: input.ToEmail,
		ToName:  input.ToName,
	}

	if input.ExpiresAt != nil {
		x.ExpiresAt = *input.ExpiresAt
	}

	return x
}

// ConvertAccountInvitationToAccountInvitationCreationInput builds a faked AccountInvitationCreationRequestInput.
func ConvertAccountInvitationToAccountInvitationCreationInput(accountInvitation *types.AccountInvitation) *types.AccountInvitationCreationRequestInput {
	return &types.AccountInvitationCreationRequestInput{
		Note:      accountInvitation.Note,
		ToName:    accountInvitation.ToName,
		ToEmail:   accountInvitation.ToEmail,
		ExpiresAt: &accountInvitation.ExpiresAt,
	}
}

// ConvertAccountInvitationToAccountInvitationUpdateInput builds a faked AccountInvitationUpdateRequestInput.
func ConvertAccountInvitationToAccountInvitationUpdateInput(accountInvitation *types.AccountInvitation) *types.AccountInvitationUpdateRequestInput {
	return &types.AccountInvitationUpdateRequestInput{
		Token: accountInvitation.Token,
		Note:  accountInvitation.Note,
	}
}

// ConvertAccountInvitationToAccountInvitationDatabaseCreationInput builds a faked AccountInvitationCreationRequestInput.
func ConvertAccountInvitationToAccountInvitationDatabaseCreationInput(accountInvitation *types.AccountInvitation) *types.AccountInvitationDatabaseCreationInput {
	return &types.AccountInvitationDatabaseCreationInput{
		ID:                   accountInvitation.ID,
		FromUser:             accountInvitation.FromUser.ID,
		ToUser:               accountInvitation.ToUser,
		ToName:               accountInvitation.ToName,
		Note:                 accountInvitation.Note,
		ToEmail:              accountInvitation.ToEmail,
		Token:                accountInvitation.Token,
		DestinationAccountID: accountInvitation.DestinationAccount.ID,
		ExpiresAt:            accountInvitation.ExpiresAt,
	}
}
