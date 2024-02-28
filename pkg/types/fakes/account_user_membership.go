package fakes

import (
	"github.com/verygoodsoftwarenotvirus/starter/internal/authorization"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"

	fake "github.com/brianvoe/gofakeit/v7"
)

// BuildFakeAccountUserMembership builds a faked AccountUserMembership.
func BuildFakeAccountUserMembership() *types.AccountUserMembership {
	return &types.AccountUserMembership{
		ID:               BuildFakeID(),
		BelongsToUser:    BuildFakeID(),
		BelongsToAccount: fake.UUID(),
		AccountRole:      authorization.AccountMemberRole.String(),
		CreatedAt:        BuildFakeTime(),
		ArchivedAt:       nil,
	}
}

// BuildFakeAccountUserMembershipWithUser builds a faked AccountUserMembershipWithUser.
func BuildFakeAccountUserMembershipWithUser() *types.AccountUserMembershipWithUser {
	u := BuildFakeUser()
	u.TwoFactorSecret = ""

	return &types.AccountUserMembershipWithUser{
		ID:               BuildFakeID(),
		BelongsToUser:    u,
		BelongsToAccount: fake.UUID(),
		AccountRole:      authorization.AccountMemberRole.String(),
		CreatedAt:        BuildFakeTime(),
		ArchivedAt:       nil,
	}
}
