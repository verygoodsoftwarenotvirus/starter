package fakes

import (
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/converters"

	fake "github.com/brianvoe/gofakeit/v7"
)

// BuildFakeAccountInvitation builds a faked AccountInvitation.
func BuildFakeAccountInvitation() *types.AccountInvitation {
	return &types.AccountInvitation{
		FromUser:           *BuildFakeUser(),
		ToEmail:            fake.Email(),
		ToName:             buildUniqueString(),
		ToUser:             func(s string) *string { return &s }(buildUniqueString()),
		Note:               buildUniqueString(),
		StatusNote:         buildUniqueString(),
		Token:              fake.UUID(),
		DestinationAccount: *BuildFakeAccount(),
		ID:                 BuildFakeID(),
		ExpiresAt:          BuildFakeTime(),
		Status:             string(types.PendingAccountInvitationStatus),
		CreatedAt:          BuildFakeTime(),
	}
}

// BuildFakeAccountInvitationList builds a faked AccountInvitationList.
func BuildFakeAccountInvitationList() *types.QueryFilteredResult[types.AccountInvitation] {
	var examples []*types.AccountInvitation
	for i := 0; i < exampleQuantity; i++ {
		examples = append(examples, BuildFakeAccountInvitation())
	}

	return &types.QueryFilteredResult[types.AccountInvitation]{
		Pagination: types.Pagination{
			Page:          1,
			Limit:         50,
			FilteredCount: exampleQuantity / 2,
			TotalCount:    exampleQuantity,
		},
		Data: examples,
	}
}

// BuildFakeAccountInvitationCreationRequestInput builds a faked AccountInvitationCreationRequestInput from a webhook.
func BuildFakeAccountInvitationCreationRequestInput() *types.AccountInvitationCreationRequestInput {
	invitation := BuildFakeAccountInvitation()
	return converters.ConvertAccountInvitationToAccountInvitationCreationInput(invitation)
}
