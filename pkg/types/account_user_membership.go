package types

import (
	"context"
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

type (
	// AccountUserMembership defines a relationship between a user and a account.
	AccountUserMembership struct {
		_ struct{} `json:"-"`

		CreatedAt        time.Time  `json:"createdAt"`
		LastUpdatedAt    *time.Time `json:"lastUpdatedAt"`
		ArchivedAt       *time.Time `json:"archivedAt"`
		ID               string     `json:"id"`
		BelongsToUser    string     `json:"belongsToUser"`
		BelongsToAccount string     `json:"belongsToAccount"`
		AccountRole      string     `json:"accountRoles"`
		DefaultAccount   bool       `json:"defaultAccount"`
	}

	// AccountUserMembershipWithUser defines a relationship between a user and a account.
	AccountUserMembershipWithUser struct {
		_ struct{} `json:"-"`

		CreatedAt        time.Time  `json:"createdAt"`
		LastUpdatedAt    *time.Time `json:"lastUpdatedAt"`
		BelongsToUser    *User      `json:"belongsToUser"`
		ArchivedAt       *time.Time `json:"archivedAt"`
		ID               string     `json:"id"`
		BelongsToAccount string     `json:"belongsToAccount"`
		AccountRole      string     `json:"accountRoles"`
		DefaultAccount   bool       `json:"defaultAccount"`
	}

	// AccountUserMembershipCreationRequestInput represents what a User could set as input for updating account user memberships.
	AccountUserMembershipCreationRequestInput struct {
		_ struct{} `json:"-"`

		Reason string `json:"reason"`
		UserID string `json:"userID"`
	}

	// AccountUserMembershipDatabaseCreationInput represents what a User could set as input for updating account user memberships.
	AccountUserMembershipDatabaseCreationInput struct {
		_ struct{} `json:"-"`

		ID          string
		Reason      string
		UserID      string
		AccountID   string
		AccountRole string
	}

	// AccountOwnershipTransferInput represents what a User could set as input for updating account user memberships.
	AccountOwnershipTransferInput struct {
		_ struct{} `json:"-"`

		Reason       string `json:"reason"`
		CurrentOwner string `json:"currentOwner"`
		NewOwner     string `json:"newOwner"`
	}

	// ModifyUserPermissionsInput  represents what a User could set as input for updating account user memberships.
	ModifyUserPermissionsInput struct {
		_ struct{} `json:"-"`

		Reason  string `json:"reason"`
		NewRole string `json:"newRoles"`
	}

	// AccountUserMembershipDataManager describes a structure capable of storing accountUserMemberships permanently.
	AccountUserMembershipDataManager interface {
		BuildSessionContextDataForUser(ctx context.Context, userID string) (*SessionContextData, error)
		GetDefaultAccountIDForUser(ctx context.Context, userID string) (string, error)
		MarkAccountAsUserDefault(ctx context.Context, userID, accountID string) error
		UserIsMemberOfAccount(ctx context.Context, userID, accountID string) (bool, error)
		ModifyUserPermissions(ctx context.Context, accountID, userID string, input *ModifyUserPermissionsInput) error
		TransferAccountOwnership(ctx context.Context, accountID string, input *AccountOwnershipTransferInput) error
		RemoveUserFromAccount(ctx context.Context, userID, accountID string) error
	}
)

var _ validation.ValidatableWithContext = (*AccountUserMembershipCreationRequestInput)(nil)

// ValidateWithContext validates an AccountUserMembershipCreationRequestInput.
func (x *AccountUserMembershipCreationRequestInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(ctx, x,
		validation.Field(&x.UserID, validation.Required),
	)
}

var _ validation.ValidatableWithContext = (*AccountOwnershipTransferInput)(nil)

// ValidateWithContext validates a AccountOwnershipTransferInput.
func (x *AccountOwnershipTransferInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(ctx, x,
		validation.Field(&x.CurrentOwner, validation.Required),
		validation.Field(&x.NewOwner, validation.Required),
		validation.Field(&x.Reason, validation.Required),
	)
}

var _ validation.ValidatableWithContext = (*ModifyUserPermissionsInput)(nil)

// ValidateWithContext validates a ModifyUserPermissionsInput.
func (x *ModifyUserPermissionsInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(ctx, x,
		validation.Field(&x.NewRole, validation.Required),
		validation.Field(&x.Reason, validation.Required),
	)
}
