package converters

import (
	"github.com/verygoodsoftwarenotvirus/starter/internal/identifiers"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

// ConvertAccountCreationInputToAccountDatabaseCreationInput creates a AccountDatabaseCreationInput from a AccountCreationRequestInput.
func ConvertAccountCreationInputToAccountDatabaseCreationInput(input *types.AccountCreationRequestInput) *types.AccountDatabaseCreationInput {
	x := &types.AccountDatabaseCreationInput{
		ID:           identifiers.New(),
		Name:         input.Name,
		AddressLine1: input.AddressLine1,
		AddressLine2: input.AddressLine2,
		City:         input.City,
		State:        input.State,
		ZipCode:      input.ZipCode,
		Country:      input.Country,
		Latitude:     input.Latitude,
		Longitude:    input.Longitude,
		ContactPhone: input.ContactPhone,
	}

	return x
}

// ConvertAccountToAccountUpdateRequestInput creates a AccountUpdateRequestInput from a Account.
func ConvertAccountToAccountUpdateRequestInput(input *types.Account) *types.AccountUpdateRequestInput {
	x := &types.AccountUpdateRequestInput{
		Name:          &input.Name,
		AddressLine1:  &input.AddressLine1,
		AddressLine2:  &input.AddressLine2,
		City:          &input.City,
		State:         &input.State,
		ZipCode:       &input.ZipCode,
		Country:       &input.Country,
		Latitude:      input.Latitude,
		Longitude:     input.Longitude,
		ContactPhone:  &input.ContactPhone,
		BelongsToUser: input.BelongsToUser,
	}

	return x
}

// ConvertAccountToAccountCreationRequestInput builds a faked AccountCreationRequestInput from a account.
func ConvertAccountToAccountCreationRequestInput(account *types.Account) *types.AccountCreationRequestInput {
	return &types.AccountCreationRequestInput{
		Name:         account.Name,
		AddressLine1: account.AddressLine1,
		AddressLine2: account.AddressLine2,
		City:         account.City,
		State:        account.State,
		ZipCode:      account.ZipCode,
		Country:      account.Country,
		Latitude:     account.Latitude,
		Longitude:    account.Longitude,
		ContactPhone: account.ContactPhone,
	}
}

// ConvertAccountToAccountDatabaseCreationInput builds a faked AccountCreationRequestInput.
func ConvertAccountToAccountDatabaseCreationInput(account *types.Account) *types.AccountDatabaseCreationInput {
	return &types.AccountDatabaseCreationInput{
		ID:                   account.ID,
		Name:                 account.Name,
		AddressLine1:         account.AddressLine1,
		AddressLine2:         account.AddressLine2,
		City:                 account.City,
		State:                account.State,
		ZipCode:              account.ZipCode,
		Country:              account.Country,
		Latitude:             account.Latitude,
		Longitude:            account.Longitude,
		ContactPhone:         account.ContactPhone,
		BelongsToUser:        account.BelongsToUser,
		WebhookEncryptionKey: account.WebhookEncryptionKey,
	}
}

// ConvertAccountUserMembershipCreationRequestInputToAccountUserMembershipDatabaseCreationInput builds a AccountUserMembershipDatabaseCreationInput from a AccountUserMembershipCreationRequestInput.
func ConvertAccountUserMembershipCreationRequestInputToAccountUserMembershipDatabaseCreationInput(input *types.AccountUserMembershipCreationRequestInput) *types.AccountUserMembershipDatabaseCreationInput {
	return &types.AccountUserMembershipDatabaseCreationInput{
		Reason: input.Reason,
		UserID: input.UserID,
	}
}
