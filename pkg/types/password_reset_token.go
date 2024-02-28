package types

import (
	"context"
	"encoding/gob"
	"net/http"
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

func init() {
	gob.Register(new(PasswordResetToken))
	gob.Register(new(PasswordResetTokenCreationRequestInput))
}

type (
	// PasswordResetToken represents a password reset token.
	PasswordResetToken struct {
		_ struct{} `json:"-"`

		CreatedAt     time.Time  `json:"createdAt"`
		ExpiresAt     time.Time  `json:"expiresAt"`
		RedeemedAt    *time.Time `json:"archivedAt"`
		LastUpdatedAt *time.Time `json:"lastUpdatedAt"`
		ID            string     `json:"id"`
		Token         string     `json:"token"`
		BelongsToUser string     `json:"belongsToUser"`
	}

	// UsernameReminderRequestInput represents what a user could set as input for creating password reset tokens.
	UsernameReminderRequestInput struct {
		_ struct{} `json:"-"`

		EmailAddress string `json:"emailAddress"`
	}

	// PasswordResetTokenCreationRequestInput represents what a user could set as input for creating password reset tokens.
	PasswordResetTokenCreationRequestInput struct {
		_ struct{} `json:"-"`

		EmailAddress string `json:"emailAddress"`
	}

	// PasswordResetTokenDatabaseCreationInput represents what a user could set as input for creating password reset tokens.
	PasswordResetTokenDatabaseCreationInput struct {
		_ struct{} `json:"-"`

		ExpiresAt     time.Time
		ID            string
		Token         string
		BelongsToUser string
	}

	// PasswordResetTokenRedemptionRequestInput represents what a user could set as input for creating password reset tokens.
	PasswordResetTokenRedemptionRequestInput struct {
		_ struct{} `json:"-"`

		Token       string `json:"token"`
		NewPassword string `json:"newPassword"`
	}

	// PasswordResetTokenDataManager describes a structure capable of storing password reset tokens permanently.
	PasswordResetTokenDataManager interface {
		GetPasswordResetTokenByToken(ctx context.Context, passwordResetTokenID string) (*PasswordResetToken, error)
		CreatePasswordResetToken(ctx context.Context, input *PasswordResetTokenDatabaseCreationInput) (*PasswordResetToken, error)
		RedeemPasswordResetToken(ctx context.Context, passwordResetTokenID string) error
	}

	// PasswordResetTokenDataService describes a structure capable of serving traffic related to password reset tokens.
	PasswordResetTokenDataService interface {
		CreateHandler(http.ResponseWriter, *http.Request)
		ReadHandler(http.ResponseWriter, *http.Request)
		ArchiveHandler(http.ResponseWriter, *http.Request)
	}
)

var _ validation.ValidatableWithContext = (*UsernameReminderRequestInput)(nil)

// ValidateWithContext validates a UsernameReminderRequestInput.
func (x *UsernameReminderRequestInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(
		ctx,
		x,
		validation.Field(&x.EmailAddress, validation.Required),
	)
}

var _ validation.ValidatableWithContext = (*PasswordResetTokenCreationRequestInput)(nil)

// ValidateWithContext validates a PasswordResetTokenCreationRequestInput.
func (x *PasswordResetTokenCreationRequestInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(
		ctx,
		x,
		validation.Field(&x.EmailAddress, validation.Required),
	)
}

var _ validation.ValidatableWithContext = (*PasswordResetTokenRedemptionRequestInput)(nil)

// ValidateWithContext validates a PasswordResetTokenRedemptionRequestInput.
func (x *PasswordResetTokenRedemptionRequestInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(
		ctx,
		x,
		validation.Field(&x.Token, validation.Required),
		validation.Field(&x.NewPassword, validation.Required),
	)
}

var _ validation.ValidatableWithContext = (*PasswordResetTokenDatabaseCreationInput)(nil)

// ValidateWithContext validates a PasswordResetTokenDatabaseCreationInput.
func (x *PasswordResetTokenDatabaseCreationInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(
		ctx,
		x,
		validation.Field(&x.ID, validation.Required),
		validation.Field(&x.Token, validation.Required),
		validation.Field(&x.ExpiresAt, validation.Required),
		validation.Field(&x.BelongsToUser, validation.Required),
	)
}
