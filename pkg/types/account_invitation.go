package types

import (
	"context"
	"net/http"
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

const (
	// AccountInvitationCreatedCustomerEventType indicates a account invitation was created.
	AccountInvitationCreatedCustomerEventType ServiceEventType = "account_invitation_created"
	// AccountInvitationCanceledCustomerEventType indicates a account invitation was created.
	AccountInvitationCanceledCustomerEventType ServiceEventType = "account_invitation_canceled"
	// AccountInvitationAcceptedCustomerEventType indicates a account invitation was created.
	AccountInvitationAcceptedCustomerEventType ServiceEventType = "account_invitation_accepted"
	// AccountInvitationRejectedCustomerEventType indicates a account invitation was created.
	AccountInvitationRejectedCustomerEventType ServiceEventType = "account_invitation_rejected"

	// PendingAccountInvitationStatus indicates a account invitation is pending.
	PendingAccountInvitationStatus AccountInvitationStatus = "pending"
	// CancelledAccountInvitationStatus indicates a account invitation was accepted.
	CancelledAccountInvitationStatus AccountInvitationStatus = "cancelled"
	// AcceptedAccountInvitationStatus indicates a account invitation was accepted.
	AcceptedAccountInvitationStatus AccountInvitationStatus = "accepted"
	// RejectedAccountInvitationStatus indicates a account invitation was rejected.
	RejectedAccountInvitationStatus AccountInvitationStatus = "rejected"
)

type (
	// AccountInvitationStatus is the type to use/compare against when checking invitation status.
	AccountInvitationStatus string

	// AccountInvitationCreationRequestInput represents what a User could set as input for creating account invitations.
	AccountInvitationCreationRequestInput struct {
		_ struct{} `json:"-"`

		ExpiresAt *time.Time `json:"expiresAt"`
		Note      string     `json:"note"`
		ToEmail   string     `json:"toEmail"`
		ToName    string     `json:"toName"`
	}

	// AccountInvitationDatabaseCreationInput represents what a User could set as input for creating account invitations.
	AccountInvitationDatabaseCreationInput struct {
		_ struct{} `json:"-"`

		ID                   string
		FromUser             string
		ToUser               *string
		Note                 string
		ToEmail              string
		Token                string
		ToName               string
		ExpiresAt            time.Time
		DestinationAccountID string
	}

	// AccountInvitation represents a account invitation.
	AccountInvitation struct {
		_ struct{} `json:"-"`

		CreatedAt          time.Time  `json:"createdAt"`
		LastUpdatedAt      *time.Time `json:"lastUpdatedAt"`
		ArchivedAt         *time.Time `json:"archivedAt"`
		ToUser             *string    `json:"toUser"`
		Status             string     `json:"status"`
		ToEmail            string     `json:"toEmail"`
		StatusNote         string     `json:"statusNote"`
		Token              string     `json:"token"`
		ID                 string     `json:"id"`
		Note               string     `json:"note"`
		ToName             string     `json:"toName"`
		ExpiresAt          time.Time  `json:"expiresAt"`
		DestinationAccount Account    `json:"destinationAccount"`
		FromUser           User       `json:"fromUser"`
	}

	// AccountInvitationUpdateRequestInput is used by users to update the status of a given account invitation.
	AccountInvitationUpdateRequestInput struct {
		Token string `json:"token"`
		Note  string `json:"note"`
	}

	// AccountInvitationDataManager describes a structure capable of storing account invitations permanently.
	AccountInvitationDataManager interface {
		AccountInvitationExists(ctx context.Context, accountInvitationID string) (bool, error)
		GetAccountInvitationByAccountAndID(ctx context.Context, accountID, accountInvitationID string) (*AccountInvitation, error)
		GetAccountInvitationByTokenAndID(ctx context.Context, token, invitationID string) (*AccountInvitation, error)
		GetAccountInvitationByEmailAndToken(ctx context.Context, emailAddress, token string) (*AccountInvitation, error)
		GetPendingAccountInvitationsFromUser(ctx context.Context, userID string, filter *QueryFilter) (*QueryFilteredResult[AccountInvitation], error)
		GetPendingAccountInvitationsForUser(ctx context.Context, userID string, filter *QueryFilter) (*QueryFilteredResult[AccountInvitation], error)
		CreateAccountInvitation(ctx context.Context, input *AccountInvitationDatabaseCreationInput) (*AccountInvitation, error)
		CancelAccountInvitation(ctx context.Context, accountInvitationID, note string) error
		AcceptAccountInvitation(ctx context.Context, accountInvitationID, token, note string) error
		RejectAccountInvitation(ctx context.Context, accountInvitationID, note string) error
	}

	// AccountInvitationDataService describes a structure capable of serving traffic related to account invitations.
	AccountInvitationDataService interface {
		ReadHandler(http.ResponseWriter, *http.Request)
		InboundInvitesHandler(http.ResponseWriter, *http.Request)
		OutboundInvitesHandler(http.ResponseWriter, *http.Request)
		InviteMemberHandler(http.ResponseWriter, *http.Request)
		CancelInviteHandler(http.ResponseWriter, *http.Request)
		AcceptInviteHandler(http.ResponseWriter, *http.Request)
		RejectInviteHandler(http.ResponseWriter, *http.Request)
	}
)

var _ validation.ValidatableWithContext = (*AccountInvitationCreationRequestInput)(nil)

// ValidateWithContext validates a AccountCreationRequestInput.
func (x *AccountInvitationCreationRequestInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(ctx, x,
		validation.Field(&x.ToEmail, validation.Required),
	)
}

var _ validation.ValidatableWithContext = (*AccountInvitationUpdateRequestInput)(nil)

// ValidateWithContext validates a AccountInvitationUpdateRequestInput.
func (x *AccountInvitationUpdateRequestInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(
		ctx,
		x,
		validation.Field(&x.Token, validation.Required),
	)
}
