package types

import (
	"context"
	"fmt"
	"net/http"
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

const (
	// AccountCreatedCustomerEventType indicates a account was created.
	AccountCreatedCustomerEventType ServiceEventType = "account_created"
	// AccountUpdatedCustomerEventType indicates a account was updated.
	AccountUpdatedCustomerEventType ServiceEventType = "account_updated"
	// AccountArchivedCustomerEventType indicates a account was archived.
	AccountArchivedCustomerEventType ServiceEventType = "account_archived"
	// AccountMemberRemovedCustomerEventType indicates a account member was removed.
	AccountMemberRemovedCustomerEventType ServiceEventType = "account_member_removed"
	// AccountMembershipPermissionsUpdatedCustomerEventType indicates a account member's permissions were modified.
	AccountMembershipPermissionsUpdatedCustomerEventType ServiceEventType = "account_membership_permissions_updated"
	// AccountOwnershipTransferredCustomerEventType indicates a account was transferred to another owner.
	AccountOwnershipTransferredCustomerEventType ServiceEventType = "account_ownership_transferred"

	// UnpaidAccountBillingStatus indicates a account is not paid.
	UnpaidAccountBillingStatus = "unpaid"
)

type (
	// Account represents a account.
	Account struct {
		_ struct{} `json:"-"`

		CreatedAt                  time.Time                        `json:"createdAt"`
		SubscriptionPlanID         *string                          `json:"subscriptionPlanID"`
		LastUpdatedAt              *time.Time                       `json:"lastUpdatedAt"`
		ArchivedAt                 *time.Time                       `json:"archivedAt"`
		Longitude                  *float64                         `json:"longitude"`
		Latitude                   *float64                         `json:"latitude"`
		State                      string                           `json:"state"`
		ContactPhone               string                           `json:"contactPhone"`
		City                       string                           `json:"city"`
		AddressLine1               string                           `json:"addressLine1"`
		ZipCode                    string                           `json:"zipCode"`
		Country                    string                           `json:"country"`
		BillingStatus              string                           `json:"billingStatus"`
		AddressLine2               string                           `json:"addressLine2"`
		PaymentProcessorCustomerID string                           `json:"paymentProcessorCustomer"`
		BelongsToUser              string                           `json:"belongsToUser"`
		ID                         string                           `json:"id"`
		Name                       string                           `json:"name"`
		WebhookEncryptionKey       string                           `json:"-"`
		Members                    []*AccountUserMembershipWithUser `json:"members"`
	}

	// AccountCreationRequestInput represents what a User could set as input for creating accounts.
	AccountCreationRequestInput struct {
		_ struct{} `json:"-"`

		Latitude     *float64 `json:"latitude"`
		Longitude    *float64 `json:"longitude"`
		Name         string   `json:"name"`
		ContactPhone string   `json:"contactPhone"`
		AddressLine1 string   `json:"addressLine1"`
		AddressLine2 string   `json:"addressLine2"`
		City         string   `json:"city"`
		State        string   `json:"state"`
		ZipCode      string   `json:"zipCode"`
		Country      string   `json:"country"`
	}

	// AccountDatabaseCreationInput represents what a User could set as input for creating accounts.
	AccountDatabaseCreationInput struct {
		_ struct{} `json:"-"`

		ID                   string
		Name                 string
		AddressLine1         string
		AddressLine2         string
		City                 string
		State                string
		ZipCode              string
		Country              string
		Latitude             *float64
		Longitude            *float64
		ContactPhone         string
		BelongsToUser        string
		WebhookEncryptionKey string
	}

	// AccountUpdateRequestInput represents what a User could set as input for updating accounts.
	AccountUpdateRequestInput struct {
		_ struct{} `json:"-"`

		Name          *string  `json:"name,omitempty"`
		ContactPhone  *string  `json:"contactPhone,omitempty"`
		AddressLine1  *string  `json:"addressLine1"`
		AddressLine2  *string  `json:"addressLine2"`
		City          *string  `json:"city"`
		State         *string  `json:"state"`
		ZipCode       *string  `json:"zipCode"`
		Country       *string  `json:"country"`
		Latitude      *float64 `json:"latitude"`
		Longitude     *float64 `json:"longitude"`
		BelongsToUser string   `json:"-"`
	}

	// AccountDataManager describes a structure capable of storing accounts permanently.
	AccountDataManager interface {
		GetAccount(ctx context.Context, accountID string) (*Account, error)
		GetAccounts(ctx context.Context, userID string, filter *QueryFilter) (*QueryFilteredResult[Account], error)
		CreateAccount(ctx context.Context, input *AccountDatabaseCreationInput) (*Account, error)
		UpdateAccount(ctx context.Context, updated *Account) error
		ArchiveAccount(ctx context.Context, accountID string, userID string) error
	}

	// AccountDataService describes a structure capable of serving traffic related to accounts.
	AccountDataService interface {
		ListHandler(http.ResponseWriter, *http.Request)
		CreateHandler(http.ResponseWriter, *http.Request)
		CurrentInfoHandler(http.ResponseWriter, *http.Request)
		ReadHandler(http.ResponseWriter, *http.Request)
		UpdateHandler(http.ResponseWriter, *http.Request)
		ArchiveHandler(http.ResponseWriter, *http.Request)
		RemoveMemberHandler(http.ResponseWriter, *http.Request)
		MarkAsDefaultAccountHandler(http.ResponseWriter, *http.Request)
		ModifyMemberPermissionsHandler(http.ResponseWriter, *http.Request)
		TransferAccountOwnershipHandler(http.ResponseWriter, *http.Request)
	}
)

// Update merges a AccountUpdateRequestInput with a account.
func (x *Account) Update(input *AccountUpdateRequestInput) {
	if input.Name != nil && *input.Name != x.Name {
		x.Name = *input.Name
	}

	if input.ContactPhone != nil && *input.ContactPhone != x.ContactPhone {
		x.ContactPhone = *input.ContactPhone
	}

	if input.AddressLine1 != nil && *input.AddressLine1 != x.AddressLine1 {
		x.AddressLine1 = *input.AddressLine1
	}

	if input.AddressLine2 != nil && *input.AddressLine2 != x.AddressLine2 {
		x.AddressLine2 = *input.AddressLine2
	}

	if input.City != nil && *input.City != x.City {
		x.City = *input.City
	}

	if input.State != nil && *input.State != x.State {
		x.State = *input.State
	}

	if input.ZipCode != nil && *input.ZipCode != x.ZipCode {
		x.ZipCode = *input.ZipCode
	}

	if input.Country != nil && *input.Country != x.Country {
		x.Country = *input.Country
	}

	if input.Latitude != nil && input.Latitude != x.Latitude {
		x.Latitude = input.Latitude
	}

	if input.Longitude != nil && input.Longitude != x.Longitude {
		x.Longitude = input.Longitude
	}
}

var _ validation.ValidatableWithContext = (*AccountCreationRequestInput)(nil)

// ValidateWithContext validates a AccountCreationRequestInput.
func (x *AccountCreationRequestInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(ctx, x,
		validation.Field(&x.Name, validation.Required),
		validation.Field(&x.Latitude, validation.NilOrNotEmpty),
		validation.Field(&x.Longitude, validation.NilOrNotEmpty),
	)
}

var _ validation.ValidatableWithContext = (*AccountUpdateRequestInput)(nil)

// ValidateWithContext validates a AccountUpdateRequestInput.
func (x *AccountUpdateRequestInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(ctx, x,
		validation.Field(&x.Name, validation.Required),
		validation.Field(&x.Latitude, validation.NilOrNotEmpty),
		validation.Field(&x.Longitude, validation.NilOrNotEmpty),
	)
}

// AccountCreationInputForNewUser creates a new AccountInputCreation struct for a given user.
func AccountCreationInputForNewUser(u *User) *AccountDatabaseCreationInput {
	return &AccountDatabaseCreationInput{
		Name:          fmt.Sprintf("%s's cool account", u.Username),
		BelongsToUser: u.ID,
	}
}
