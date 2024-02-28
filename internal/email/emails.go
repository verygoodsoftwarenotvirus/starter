package email

import (
	"errors"
	"fmt"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"

	"github.com/matcornic/hermes/v2"
)

var (
	ErrUnverifiedEmailRecipient = errors.New("missing email address verification for user")
)

const (
	companyName = "Replace Me, Inc."

	defaultEnv = "testing"

	// SentEventType indicates an email was sent.
	SentEventType types.ServiceEventType = "email_sent"

	// TemplateTypeInvite is used to indicate the invite template.
	TemplateTypeInvite = "invite"
	// TemplateTypeUsernameReminder is used to indicate the username_reminder template.
	TemplateTypeUsernameReminder = "username_reminder"
	// TemplateTypePasswordResetTokenCreated is used to indicate the password_reset template.
	TemplateTypePasswordResetTokenCreated = "password_reset_token_created"
	// TemplateTypePasswordReset is used to indicate the password_reset template.
	TemplateTypePasswordReset = "password_reset"
	// TemplateTypePasswordResetTokenRedeemed is used to indicate the password_reset_token_redeemed template.
	TemplateTypePasswordResetTokenRedeemed = "password_reset_token_redeemed"
	// TemplateTypeVerifyEmailAddress is used to indicate the verify_email_address template.
	TemplateTypeVerifyEmailAddress = "verify_email_address"

	logoURL = "data:image/png;base64,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"
)

type (
	// DeliveryRequest is the type to use when requesting emails within the service.
	DeliveryRequest struct {
		_ struct{} `json:"-"`

		TemplateParams         map[string]any            `json:"templateParams"`
		Invitation             *types.AccountInvitation  `json:"invitation,omitempty"`
		PasswordResetToken     *types.PasswordResetToken `json:"passwordResetToken,omitempty"`
		UserID                 string                    `json:"forUserId"`
		EmailVerificationToken string                    `json:"emailVerificationToken,omitempty"`
		Template               string                    `json:"template"`
	}
)

// BuildInviteMemberEmail builds an email notifying a user that they've been invited to join a account.
func BuildInviteMemberEmail(accountInvitation *types.AccountInvitation, envCfg *EnvironmentConfig) (*OutboundEmailMessage, error) {
	if envCfg == nil {
		return nil, ErrMissingEnvCfg
	}

	e := hermes.Email{
		Body: hermes.Body{
			Name: accountInvitation.ToEmail,
			Intros: []string{
				fmt.Sprintf("You've been invited to join a account on %s!", companyName),
			},
			Actions: []hermes.Action{
				{
					Instructions: "Click the button below to reset your password:",
					Button: hermes.Button{
						Text: "Join the fun",
						Link: fmt.Sprintf("%s/accept_invitation?i=%s&t=%s", envCfg.BaseURL(), accountInvitation.ID, accountInvitation.Token),
					},
				},
			},
		},
	}

	htmlContent, err := envCfg.buildHermes().GenerateHTML(e)
	if err != nil {
		return nil, fmt.Errorf("error rendering email template: %w", err)
	}

	msg := &OutboundEmailMessage{
		ToAddress:   accountInvitation.ToEmail,
		ToName:      "",
		FromAddress: envCfg.outboundInvitesEmailAddress,
		FromName:    companyName,
		Subject:     "You've been invited!",
		HTMLContent: htmlContent,
	}

	return msg, nil
}

// BuildGeneratedPasswordResetTokenEmail builds an email notifying a user that they've been invited to join a account.
func BuildGeneratedPasswordResetTokenEmail(recipient *types.User, passwordResetToken *types.PasswordResetToken, envCfg *EnvironmentConfig) (*OutboundEmailMessage, error) {
	if envCfg == nil {
		return nil, ErrMissingEnvCfg
	}

	if recipient.EmailAddressVerifiedAt == nil {
		return nil, ErrUnverifiedEmailRecipient
	}

	e := hermes.Email{
		Body: hermes.Body{
			Name: recipient.Username,
			Intros: []string{
				"You have received this email because a password reset was requested.",
			},
			Actions: []hermes.Action{
				{
					Instructions: "Click the button below to reset your password:",
					Button: hermes.Button{
						Text: "Reset your password",
						Link: fmt.Sprintf("%s/reset_password?t=%s", envCfg.BaseURL(), passwordResetToken.Token),
					},
				},
			},
			Outros: []string{
				"If you did not request a password reset, no further action is required on your part.",
			},
		},
	}

	htmlContent, err := envCfg.buildHermes().GenerateHTML(e)
	if err != nil {
		return nil, fmt.Errorf("error rendering email template: %w", err)
	}

	msg := &OutboundEmailMessage{
		ToAddress:   recipient.EmailAddress,
		ToName:      "",
		FromAddress: envCfg.passwordResetCreationEmailAddress,
		FromName:    companyName,
		Subject:     fmt.Sprintf("A password reset link was requested for your %s account", companyName),
		HTMLContent: htmlContent,
	}

	return msg, nil
}

// BuildUsernameReminderEmail builds an email notifying a user that they've been invited to join a account.
func BuildUsernameReminderEmail(recipient *types.User, envCfg *EnvironmentConfig) (*OutboundEmailMessage, error) {
	if envCfg == nil {
		return nil, ErrMissingEnvCfg
	}

	if recipient.EmailAddressVerifiedAt == nil {
		return nil, ErrUnverifiedEmailRecipient
	}

	e := hermes.Email{
		Body: hermes.Body{
			Name: recipient.Username,
			Intros: []string{
				fmt.Sprintf("A username reminder for your %s account was requested. Your username is <b>%s</b>.", companyName, recipient.Username),
			},
			Outros: []string{
				"If you did not request a username reminder, no further action is required on your part.",
			},
		},
	}

	htmlContent, err := envCfg.buildHermes().GenerateHTML(e)
	if err != nil {
		return nil, fmt.Errorf("error rendering email template: %w", err)
	}

	msg := &OutboundEmailMessage{
		ToAddress:   recipient.EmailAddress,
		FromAddress: envCfg.passwordResetCreationEmailAddress,
		FromName:    companyName,
		Subject:     fmt.Sprintf("A password reset link was requested for your %s account", companyName),
		HTMLContent: htmlContent,
	}

	return msg, nil
}

// BuildPasswordResetTokenRedeemedEmail builds an email notifying a user that they've been invited to join a account.
func BuildPasswordResetTokenRedeemedEmail(recipient *types.User, envCfg *EnvironmentConfig) (*OutboundEmailMessage, error) {
	if envCfg == nil {
		return nil, ErrMissingEnvCfg
	}

	if recipient.EmailAddressVerifiedAt == nil {
		return nil, ErrUnverifiedEmailRecipient
	}

	e := hermes.Email{
		Body: hermes.Body{
			Name: recipient.Username,
			Intros: []string{
				"This is to inform you that your password has been changed upon successful redemption of a reset token.",
			},
			Outros: []string{
				"If you did not request a password reset, please contact support.",
			},
		},
	}

	htmlContent, err := envCfg.buildHermes().GenerateHTML(e)
	if err != nil {
		return nil, fmt.Errorf("error rendering email template: %w", err)
	}

	msg := &OutboundEmailMessage{
		ToAddress:   recipient.EmailAddress,
		FromAddress: envCfg.passwordResetRedemptionEmailAddress,
		FromName:    companyName,
		Subject:     fmt.Sprintf("Your %s account password has been changed.", companyName),
		HTMLContent: htmlContent,
	}

	return msg, nil
}

// BuildPasswordChangedEmail builds an email notifying a user that they've been invited to join a account.
func BuildPasswordChangedEmail(recipient *types.User, envCfg *EnvironmentConfig) (*OutboundEmailMessage, error) {
	if envCfg == nil {
		return nil, ErrMissingEnvCfg
	}

	if recipient.EmailAddressVerifiedAt == nil {
		return nil, ErrUnverifiedEmailRecipient
	}

	e := hermes.Email{
		Body: hermes.Body{
			Name: recipient.Username,
			Intros: []string{
				"This is to inform you that your password has been changed.",
			},
			Outros: []string{
				"If you did not perform this action, please contact support.",
			},
		},
	}

	htmlContent, err := envCfg.buildHermes().GenerateHTML(e)
	if err != nil {
		return nil, fmt.Errorf("error rendering email template: %w", err)
	}

	msg := &OutboundEmailMessage{
		ToAddress:   recipient.EmailAddress,
		FromAddress: envCfg.passwordResetRedemptionEmailAddress,
		FromName:    companyName,
		Subject:     fmt.Sprintf("Your %s account password has been changed.", companyName),
		HTMLContent: htmlContent,
	}

	return msg, nil
}

var errEmailVerificationTokenRequired = errors.New("email verification token required")

// BuildVerifyEmailAddressEmail builds an email notifying a user that they've been invited to join a account.
func BuildVerifyEmailAddressEmail(recipient *types.User, emailVerificationToken string, envCfg *EnvironmentConfig) (*OutboundEmailMessage, error) {
	if envCfg == nil {
		return nil, ErrMissingEnvCfg
	}

	if emailVerificationToken == "" {
		return nil, errEmailVerificationTokenRequired
	}

	if recipient.EmailAddressVerifiedAt != nil {
		return nil, fmt.Errorf("user %s has already verified their email address", recipient.ID)
	}

	e := hermes.Email{
		Body: hermes.Body{
			Name: recipient.Username,
			Intros: []string{
				fmt.Sprintf("You recently signed up for an account on %s. Please verify your email address.", companyName),
			},
			Actions: []hermes.Action{
				{
					Instructions: "Click the button below to verify your email address:",
					Button: hermes.Button{
						Text: "Verify my email",
						Link: fmt.Sprintf("%s/verify_email_address?t=%s", envCfg.BaseURL(), emailVerificationToken),
					},
				},
			},
			Outros: []string{
				"If you did not sign up for an account, please contact support.",
			},
		},
	}

	htmlContent, err := envCfg.buildHermes().GenerateHTML(e)
	if err != nil {
		return nil, fmt.Errorf("error rendering email template: %w", err)
	}

	msg := &OutboundEmailMessage{
		ToAddress:   recipient.EmailAddress,
		ToName:      "",
		FromAddress: envCfg.passwordResetCreationEmailAddress,
		FromName:    companyName,
		Subject:     fmt.Sprintf("Verify your email with %s", companyName),
		HTMLContent: htmlContent,
	}

	return msg, nil
}
