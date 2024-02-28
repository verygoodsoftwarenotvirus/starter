package fakes

import (
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/converters"

	fake "github.com/brianvoe/gofakeit/v7"
)

// BuildFakeAccount builds a faked account.
func BuildFakeAccount() *types.Account {
	accountID := BuildFakeID()

	var memberships []*types.AccountUserMembershipWithUser
	for i := 0; i < exampleQuantity; i++ {
		membership := BuildFakeAccountUserMembershipWithUser()
		membership.BelongsToAccount = accountID
		memberships = append(memberships, membership)
	}

	fakeAddress := fake.Address()
	key := fake.BitcoinPrivateKey()

	return &types.Account{
		ID:                         accountID,
		Name:                       fake.UUID(),
		BillingStatus:              types.UnpaidAccountBillingStatus,
		ContactPhone:               fake.PhoneFormatted(),
		PaymentProcessorCustomerID: fake.UUID(),
		CreatedAt:                  BuildFakeTime(),
		BelongsToUser:              fake.UUID(),
		Members:                    memberships,
		AddressLine1:               fakeAddress.Address,
		AddressLine2:               "",
		City:                       fakeAddress.City,
		State:                      fakeAddress.State,
		ZipCode:                    fakeAddress.Zip,
		Country:                    fakeAddress.Country,
		Latitude:                   &fakeAddress.Latitude,
		Longitude:                  &fakeAddress.Longitude,
		WebhookEncryptionKey:       key,
	}
}

// BuildFakeAccountList builds a faked AccountList.
func BuildFakeAccountList() *types.QueryFilteredResult[types.Account] {
	var examples []*types.Account
	for i := 0; i < exampleQuantity; i++ {
		examples = append(examples, BuildFakeAccount())
	}

	return &types.QueryFilteredResult[types.Account]{
		Pagination: types.Pagination{
			Page:          1,
			Limit:         50,
			FilteredCount: exampleQuantity / 2,
			TotalCount:    exampleQuantity,
		},
		Data: examples,
	}
}

// BuildFakeAccountUpdateInput builds a faked AccountUpdateRequestInput from a account.
func BuildFakeAccountUpdateInput() *types.AccountUpdateRequestInput {
	account := BuildFakeAccount()
	return &types.AccountUpdateRequestInput{
		Name:          &account.Name,
		ContactPhone:  &account.ContactPhone,
		AddressLine1:  &account.AddressLine1,
		AddressLine2:  &account.AddressLine2,
		City:          &account.City,
		State:         &account.State,
		ZipCode:       &account.ZipCode,
		Country:       &account.Country,
		Latitude:      account.Latitude,
		Longitude:     account.Longitude,
		BelongsToUser: account.BelongsToUser,
	}
}

// BuildFakeAccountCreationInput builds a faked AccountCreationRequestInput.
func BuildFakeAccountCreationInput() *types.AccountCreationRequestInput {
	account := BuildFakeAccount()
	return converters.ConvertAccountToAccountCreationRequestInput(account)
}
