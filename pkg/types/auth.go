package types

import (
	"context"
	"encoding/gob"
	"net/http"

	"github.com/verygoodsoftwarenotvirus/starter/internal/authorization"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

const (
	// SessionContextDataKey is the non-string type we use for referencing SessionContextData structs.
	SessionContextDataKey ContextKey = "session_context_data"
	// UserIDContextKey is the non-string type we use for referencing SessionContextData structs.
	UserIDContextKey ContextKey = "user_id"
	// AccountIDContextKey is the non-string type we use for referencing SessionContextData structs.
	AccountIDContextKey ContextKey = "account_id"
	// UserRegistrationInputContextKey is the non-string type we use for referencing SessionContextData structs.
	UserRegistrationInputContextKey ContextKey = "user_registration_input"

	// TwoFactorSecretVerifiedCustomerEventType indicates a user's two factor secret was verified.
	/* #nosec G101 */
	TwoFactorSecretVerifiedCustomerEventType ServiceEventType = "two_factor_secret_verified"
	// TwoFactorDeactivatedCustomerEventType indicates a user's two factor secret was changed and verified_at timestamp was reset.
	/* #nosec G101 */
	TwoFactorDeactivatedCustomerEventType ServiceEventType = "two_factor_deactivated"
	// TwoFactorSecretChangedCustomerEventType indicates a user's two factor secret was changed and verified_at timestamp was reset.
	/* #nosec G101 */
	TwoFactorSecretChangedCustomerEventType ServiceEventType = "two_factor_secret_changed"
	// PasswordResetTokenCreatedEventType indicates a user created a password reset token.
	PasswordResetTokenCreatedEventType ServiceEventType = "password_reset_token_created"
	// PasswordResetTokenRedeemedEventType indicates a user created a password reset token.
	PasswordResetTokenRedeemedEventType ServiceEventType = "password_reset_token_redeemed"
	// PasswordChangedEventType indicates a user changed their password.
	PasswordChangedEventType ServiceEventType = "password_changed"
	// EmailAddressChangedEventType indicates a user changed their email address.
	EmailAddressChangedEventType ServiceEventType = "email_address_changed"
	// UsernameChangedEventType indicates a user changed their username.
	UsernameChangedEventType ServiceEventType = "username_changed"
	// UserDetailsChangedEventType indicates a user changed their information.
	UserDetailsChangedEventType ServiceEventType = "user_details_changed"
	// UsernameReminderRequestedEventType indicates a user requested a username reminder.
	UsernameReminderRequestedEventType ServiceEventType = "username_reminder_requested"
	// UserLoggedInCustomerEventType indicates a user has logged in.
	UserLoggedInCustomerEventType ServiceEventType = "user_logged_in"
	// UserLoggedOutCustomerEventType indicates a user has logged in.
	UserLoggedOutCustomerEventType ServiceEventType = "user_logged_out"
	// UserChangedActiveAccountCustomerEventType indicates a user has logged in.
	UserChangedActiveAccountCustomerEventType ServiceEventType = "changed_active_account"
	// UserEmailAddressVerifiedEventType indicates a user created a password reset token.
	UserEmailAddressVerifiedEventType ServiceEventType = "user_email_address_verified"
	// UserEmailAddressVerificationEmailRequestedEventType indicates a user created a password reset token.
	UserEmailAddressVerificationEmailRequestedEventType ServiceEventType = "user_email_address_verification_email_requested"
)

func init() {
	gob.Register(&SessionContextData{})
}

type (
	// UserAccountMembershipInfo represents key information about a account membership.
	UserAccountMembershipInfo struct {
		_ struct{} `json:"-"`

		AccountName string
		AccountID   string
		AccountRole string
	}

	// SessionContextData represents what we encode in our passwords cookies.
	SessionContextData struct {
		_ struct{} `json:"-"`

		AccountPermissions map[string]authorization.AccountRolePermissionsChecker `json:"-"`
		Requester          RequesterInfo                                          `json:"-"`
		ActiveAccountID    string                                                 `json:"-"`
	}

	// RequesterInfo contains data relevant to the user making a request.
	RequesterInfo struct {
		_ struct{} `json:"-"`

		ServicePermissions       authorization.ServiceRolePermissionChecker `json:"-"`
		AccountStatus            string                                     `json:"-"`
		AccountStatusExplanation string                                     `json:"-"`
		UserID                   string                                     `json:"-"`
		EmailAddress             string                                     `json:"-"`
		Username                 string                                     `json:"-"`
	}

	// UserStatusResponse is what we encode when the frontend wants to check auth status.
	UserStatusResponse struct {
		_ struct{} `json:"-"`

		UserID                   string `json:"userID"`
		AccountStatus            string `json:"accountStatus,omitempty"`
		AccountStatusExplanation string `json:"accountStatusExplanation"`
		ActiveAccount            string `json:"activeAccount,omitempty"`
		UserIsAuthenticated      bool   `json:"isAuthenticated"`
	}

	// UserPermissionsRequestInput is what we decode when the frontend wants to check permission status.
	UserPermissionsRequestInput struct {
		_ struct{} `json:"-"`

		Permissions []string `json:"permissions"`
	}

	// UserPermissionsResponse is what we encode when the frontend wants to check permission status.
	UserPermissionsResponse struct {
		_ struct{} `json:"-"`

		Permissions map[string]bool `json:"permissions"`
	}

	// ChangeActiveAccountInput represents what a User could set as input for switching accounts.
	ChangeActiveAccountInput struct {
		_ struct{} `json:"-"`

		AccountID string `json:"accountID"`
	}

	// AuthService describes a structure capable of handling passwords and authorization requests.
	AuthService interface {
		StatusHandler(http.ResponseWriter, *http.Request)
		BuildLoginHandler(bool) func(http.ResponseWriter, *http.Request)
		EndSessionHandler(http.ResponseWriter, *http.Request)
		CycleCookieSecretHandler(http.ResponseWriter, *http.Request)
		ChangeActiveAccountHandler(http.ResponseWriter, *http.Request)

		SSOLoginHandler(http.ResponseWriter, *http.Request)
		SSOLoginCallbackHandler(http.ResponseWriter, *http.Request)

		PermissionFilterMiddleware(permissions ...authorization.Permission) func(next http.Handler) http.Handler
		CookieRequirementMiddleware(next http.Handler) http.Handler
		UserAttributionMiddleware(next http.Handler) http.Handler
		AuthorizationMiddleware(next http.Handler) http.Handler
		ServiceAdminMiddleware(next http.Handler) http.Handler

		OAuth2Service
	}
)

var _ validation.ValidatableWithContext = (*ChangeActiveAccountInput)(nil)

// ValidateWithContext validates a ChangeActiveAccountInput.
func (x *ChangeActiveAccountInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(ctx, x,
		validation.Field(&x.AccountID, validation.Required),
	)
}

// AccountRolePermissionsChecker returns the relevant AccountRolePermissionsChecker.
func (x *SessionContextData) AccountRolePermissionsChecker() authorization.AccountRolePermissionsChecker {
	return x.AccountPermissions[x.ActiveAccountID]
}

// ServiceRolePermissionChecker returns the relevant ServiceRolePermissionChecker.
func (x *SessionContextData) ServiceRolePermissionChecker() authorization.ServiceRolePermissionChecker {
	return x.Requester.ServicePermissions
}

// AttachToLogger provides a consistent way to attach a SessionContextData object to a logger.
func (x *SessionContextData) AttachToLogger(logger logging.Logger) logging.Logger {
	if x != nil {
		logger = logger.WithValue(keys.RequesterIDKey, x.Requester.UserID).
			WithValue(keys.ActiveAccountIDKey, x.ActiveAccountID)
	}

	return logger
}
