package types

import (
	"context"
	"math"
	"net/http"
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
)

const (
	// UserSignedUpCustomerEventType indicates a user signed up.
	UserSignedUpCustomerEventType ServiceEventType = "user_signed_up"
	// UserArchivedCustomerEventType indicates a user deleted their account.
	UserArchivedCustomerEventType ServiceEventType = "user_archived"

	// GoodStandingUserAccountStatus indicates a User's account is in good standing.
	GoodStandingUserAccountStatus userAccountStatus = "good"
	// UnverifiedAccountStatus indicates a User's account requires two factor secret verification.
	UnverifiedAccountStatus userAccountStatus = "unverified"
	// BannedUserAccountStatus indicates a User's account is banned.
	BannedUserAccountStatus userAccountStatus = "banned"
	// TerminatedUserAccountStatus indicates a User's account is banned.
	TerminatedUserAccountStatus userAccountStatus = "terminated"

	validTOTPTokenLength = 6
)

var (
	totpTokenLengthRule = validation.Length(validTOTPTokenLength, validTOTPTokenLength)
)

type (
	userAccountStatus string

	// User represents a User.
	User struct {
		_ struct{} `json:"-"`

		CreatedAt                  time.Time  `json:"createdAt"`
		PasswordLastChangedAt      *time.Time `json:"passwordLastChangedAt"`
		LastUpdatedAt              *time.Time `json:"lastUpdatedAt"`
		LastAcceptedTermsOfService *time.Time `json:"lastAcceptedTOS"`
		LastAcceptedPrivacyPolicy  *time.Time `json:"lastAcceptedPrivacyPolicy"`
		TwoFactorSecretVerifiedAt  *time.Time `json:"twoFactorSecretVerifiedAt"`
		AvatarSrc                  *string    `json:"avatar"`
		Birthday                   *time.Time `json:"birthday"`
		ArchivedAt                 *time.Time `json:"archivedAt"`
		AccountStatusExplanation   string     `json:"accountStatusExplanation"`
		TwoFactorSecret            string     `json:"-"`
		HashedPassword             string     `json:"-"`
		ID                         string     `json:"id"`
		AccountStatus              string     `json:"accountStatus"`
		Username                   string     `json:"username"`
		FirstName                  string     `json:"firstName"`
		LastName                   string     `json:"lastName"`
		EmailAddress               string     `json:"emailAddress"`
		EmailAddressVerifiedAt     *time.Time `json:"emailAddressVerifiedAt"`
		ServiceRole                string     `json:"serviceRoles"`
		RequiresPasswordChange     bool       `json:"requiresPasswordChange"`
	}

	// UserSearchSubset represents the subset of values suitable to index for search.
	UserSearchSubset struct {
		_ struct{} `json:"-"`

		ID           string `json:"id,omitempty"`
		Username     string `json:"username,omitempty"`
		FirstName    string `json:"firstName,omitempty"`
		LastName     string `json:"lastName,omitempty"`
		EmailAddress string `json:"emailAddress,omitempty"`
	}

	// UserRegistrationInput represents the input required from users to register an account.
	UserRegistrationInput struct {
		_ struct{} `json:"-"`

		Birthday              *time.Time `json:"birthday,omitempty"`
		Password              string     `json:"password"`
		EmailAddress          string     `json:"emailAddress"`
		InvitationToken       string     `json:"invitationToken,omitempty"`
		InvitationID          string     `json:"invitationID,omitempty"`
		Username              string     `json:"username"`
		FirstName             string     `json:"firstName"`
		LastName              string     `json:"lastName"`
		AccountName           string     `json:"accountName"`
		AcceptedTOS           bool       `json:"acceptedTOS"`
		AcceptedPrivacyPolicy bool       `json:"acceptedPrivacyPolicy"`
	}

	// UserDatabaseCreationInput is used by the User creation route to communicate with the data store.
	UserDatabaseCreationInput struct {
		_ struct{} `json:"-"`

		Birthday              *time.Time
		ID                    string
		AvatarSrc             *string
		HashedPassword        string
		TwoFactorSecret       string
		InvitationToken       string
		DestinationAccountID  string
		Username              string
		EmailAddress          string
		AccountName           string
		FirstName             string
		LastName              string
		AcceptedTOS           bool
		AcceptedPrivacyPolicy bool
	}

	// UserCreationResponse is a response structure for Users that doesn't contain passwords fields, but does contain the two factor secret.
	UserCreationResponse struct {
		_ struct{} `json:"-"`

		CreatedAt       time.Time  `json:"createdAt"`
		Birthday        *time.Time `json:"birthday"`
		AvatarSrc       *string    `json:"avatar"`
		Username        string     `json:"username"`
		EmailAddress    string     `json:"emailAddress"`
		TwoFactorQRCode string     `json:"qrCode"`
		CreatedUserID   string     `json:"createdUserID"`
		AccountStatus   string     `json:"accountStatus"`
		TwoFactorSecret string     `json:"twoFactorSecret"`
		FirstName       string     `json:"firstName"`
		LastName        string     `json:"lastName"`
		IsAdmin         bool       `json:"isAdmin"`
	}

	// UserLoginInput represents the payload used to log in a User.
	UserLoginInput struct {
		_ struct{} `json:"-"`

		Username  string `json:"username"`
		Password  string `json:"password"`
		TOTPToken string `json:"totpToken"`
	}

	// PasswordUpdateInput represents input a User would provide when updating their passwords.
	PasswordUpdateInput struct {
		_ struct{} `json:"-"`

		NewPassword     string `json:"newPassword"`
		CurrentPassword string `json:"currentPassword"`
		TOTPToken       string `json:"totpToken"`
	}

	// UsernameUpdateInput represents input a User would provide when updating their username.
	UsernameUpdateInput struct {
		_ struct{} `json:"-"`

		NewUsername     string `json:"newUsername"`
		CurrentPassword string `json:"currentPassword"`
		TOTPToken       string `json:"totpToken"`
	}

	// UserEmailAddressUpdateInput represents input a User would provide when updating their email address.
	UserEmailAddressUpdateInput struct {
		_ struct{} `json:"-"`

		NewEmailAddress string `json:"newEmailAddress"`
		CurrentPassword string `json:"currentPassword"`
		TOTPToken       string `json:"totpToken"`
	}

	// UserDetailsUpdateRequestInput represents input a User would provide when updating their information.
	UserDetailsUpdateRequestInput struct {
		_ struct{} `json:"-"`

		FirstName       string    `json:"firstName"`
		LastName        string    `json:"lastName"`
		Birthday        time.Time `json:"birthday"`
		CurrentPassword string    `json:"currentPassword"`
		TOTPToken       string    `json:"totpToken"`
	}

	// UserDetailsDatabaseUpdateInput represents input a User would provide when updating their information.
	UserDetailsDatabaseUpdateInput struct {
		_ struct{} `json:"-"`

		Birthday  time.Time `json:"-"`
		FirstName string    `json:"-"`
		LastName  string    `json:"-"`
	}

	// AvatarUpdateInput represents input a User would provide when updating their passwords.
	AvatarUpdateInput struct {
		_ struct{} `json:"-"`

		Base64EncodedData string `json:"base64EncodedData"`
	}

	// TOTPSecretRefreshInput represents input a User would provide when updating their 2FA secret.
	TOTPSecretRefreshInput struct {
		_ struct{} `json:"-"`

		CurrentPassword string `json:"currentPassword"`
		TOTPToken       string `json:"totpToken"`
	}

	// TOTPSecretVerificationInput represents input a User would provide when validating their 2FA secret.
	TOTPSecretVerificationInput struct {
		_ struct{} `json:"-"`

		TOTPToken string `json:"totpToken"`
		UserID    string `json:"userID"`
	}

	// TOTPSecretRefreshResponse represents the response we provide to a User when updating their 2FA secret.
	TOTPSecretRefreshResponse struct {
		_ struct{} `json:"-"`

		TwoFactorQRCode string `json:"qrCode"`
		TwoFactorSecret string `json:"twoFactorSecret"`
	}

	// EmailAddressVerificationRequestInput represents the request a User provides when verifying their email address.
	EmailAddressVerificationRequestInput struct {
		_ struct{} `json:"-"`

		Token string `json:"emailVerificationToken"`
	}

	// AdminUserDataManager contains administrative User functions that we don't necessarily want to expose
	// to, say, the collection of handlers.
	AdminUserDataManager interface {
		UpdateUserAccountStatus(ctx context.Context, userID string, input *UserAccountStatusUpdateInput) error
	}

	// UserDataManager describes a structure which can manage users in persistent storage.
	UserDataManager interface {
		GetUser(ctx context.Context, userID string) (*User, error)
		GetUserByUsername(ctx context.Context, username string) (*User, error)
		GetAdminUserByUsername(ctx context.Context, username string) (*User, error)
		GetUsers(ctx context.Context, filter *QueryFilter) (*QueryFilteredResult[User], error)
		GetUserByEmail(ctx context.Context, email string) (*User, error)
		SearchForUsersByUsername(ctx context.Context, usernameQuery string) ([]*User, error)
		CreateUser(ctx context.Context, input *UserDatabaseCreationInput) (*User, error)
		UpdateUserAvatar(ctx context.Context, userID, newAvatarContent string) error
		UpdateUserUsername(ctx context.Context, userID, newUsername string) error
		UpdateUserEmailAddress(ctx context.Context, userID, newEmailAddress string) error
		UpdateUserDetails(ctx context.Context, userID string, input *UserDetailsDatabaseUpdateInput) error
		UpdateUserPassword(ctx context.Context, userID, newHash string) error
		ArchiveUser(ctx context.Context, userID string) error
		GetUserWithUnverifiedTwoFactorSecret(ctx context.Context, userID string) (*User, error)
		MarkUserTwoFactorSecretAsVerified(ctx context.Context, userID string) error
		MarkUserTwoFactorSecretAsUnverified(ctx context.Context, userID, newSecret string) error
		GetEmailAddressVerificationTokenForUser(ctx context.Context, userID string) (string, error)
		GetUserByEmailAddressVerificationToken(ctx context.Context, token string) (*User, error)
		MarkUserEmailAddressAsVerified(ctx context.Context, userID, token string) error
		MarkUserEmailAddressAsUnverified(ctx context.Context, userID string) error
		GetUserIDsThatNeedSearchIndexing(ctx context.Context) ([]string, error)
		MarkUserAsIndexed(ctx context.Context, userID string) error
	}

	// UserDataService describes a structure capable of serving traffic related to users.
	UserDataService interface {
		ListHandler(http.ResponseWriter, *http.Request)
		CreateHandler(http.ResponseWriter, *http.Request)
		ReadHandler(http.ResponseWriter, *http.Request)
		SelfHandler(http.ResponseWriter, *http.Request)
		PermissionsHandler(http.ResponseWriter, *http.Request)
		UsernameSearchHandler(http.ResponseWriter, *http.Request)
		NewTOTPSecretHandler(http.ResponseWriter, *http.Request)
		TOTPSecretVerificationHandler(http.ResponseWriter, *http.Request)
		UpdatePasswordHandler(http.ResponseWriter, *http.Request)
		UpdateUserEmailAddressHandler(http.ResponseWriter, *http.Request)
		UpdateUserUsernameHandler(http.ResponseWriter, *http.Request)
		UpdateUserDetailsHandler(http.ResponseWriter, *http.Request)
		AvatarUploadHandler(http.ResponseWriter, *http.Request)
		ArchiveHandler(http.ResponseWriter, *http.Request)
		CreatePasswordResetTokenHandler(http.ResponseWriter, *http.Request)
		PasswordResetTokenRedemptionHandler(http.ResponseWriter, *http.Request)
		RequestUsernameReminderHandler(http.ResponseWriter, *http.Request)
		VerifyUserEmailAddressHandler(http.ResponseWriter, *http.Request)
		RequestEmailVerificationEmailHandler(http.ResponseWriter, *http.Request)
	}
)

// Update accepts a User as input and merges those values if they're set.
func (u *User) Update(input *User) {
	if input.Username != "" && input.Username != u.Username {
		u.Username = input.Username
	}

	if input.FirstName != "" && input.FirstName != u.FirstName {
		u.FirstName = input.FirstName
	}

	if input.LastName != "" && input.LastName != u.LastName {
		u.LastName = input.LastName
	}

	if input.HashedPassword != "" && input.HashedPassword != u.HashedPassword {
		u.HashedPassword = input.HashedPassword
	}

	if input.TwoFactorSecret != "" && input.TwoFactorSecret != u.TwoFactorSecret {
		u.TwoFactorSecret = input.TwoFactorSecret
	}

	if input.Birthday != nil && input.Birthday != u.Birthday {
		u.Birthday = input.Birthday
	}
}

// IsBanned is a handy helper function.
func (u *User) IsBanned() bool {
	return u.AccountStatus == string(BannedUserAccountStatus)
}

// ValidateWithContext ensures our provided UserRegistrationInput meets expectations.
func (i *UserRegistrationInput) ValidateWithContext(ctx context.Context, minUsernameLength, minPasswordLength uint8) error {
	return validation.ValidateStructWithContext(ctx, i,
		validation.Field(&i.EmailAddress, validation.Required, is.EmailFormat),
		validation.Field(&i.Username, validation.Required, validation.Length(int(minUsernameLength), math.MaxInt8)),
		validation.Field(&i.Password, validation.Required, validation.Length(int(minPasswordLength), math.MaxInt8)),
	)
}

var _ validation.ValidatableWithContext = (*TOTPSecretVerificationInput)(nil)

// ValidateWithContext ensures our provided TOTPSecretVerificationInput meets expectations.
func (i *TOTPSecretVerificationInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(ctx, i,
		validation.Field(&i.UserID, validation.Required),
		validation.Field(&i.TOTPToken, validation.Required, totpTokenLengthRule),
	)
}

// ValidateWithContext ensures our provided UserLoginInput meets expectations.
func (i *UserLoginInput) ValidateWithContext(ctx context.Context, minUsernameLength, minPasswordLength uint8) error {
	return validation.ValidateStructWithContext(ctx, i,
		validation.Field(&i.Username, validation.Required, validation.Length(int(minUsernameLength), math.MaxInt8)),
		validation.Field(&i.Password, validation.Required, validation.Length(int(minPasswordLength), math.MaxInt8)),
	)
}

// ValidateWithContext ensures our provided PasswordUpdateInput meets expectations.
func (i *PasswordUpdateInput) ValidateWithContext(ctx context.Context, minPasswordLength uint8) error {
	if i.CurrentPassword == i.NewPassword {
		return errNewPasswordSameAsOld
	}

	return validation.ValidateStructWithContext(ctx, i,
		validation.Field(&i.CurrentPassword, validation.Required, validation.Length(int(minPasswordLength), math.MaxInt8)),
		validation.Field(&i.NewPassword, validation.Required, validation.Length(int(minPasswordLength), math.MaxInt8)),
	)
}

var _ validation.ValidatableWithContext = (*TOTPSecretRefreshInput)(nil)

// ValidateWithContext ensures our provided TOTPSecretRefreshInput meets expectations.
func (i *TOTPSecretRefreshInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(ctx, i,
		validation.Field(&i.CurrentPassword, validation.Required),
		validation.Field(&i.TOTPToken, validation.Required, totpTokenLengthRule),
	)
}

var _ validation.ValidatableWithContext = (*EmailAddressVerificationRequestInput)(nil)

// ValidateWithContext ensures our provided EmailAddressVerificationRequestInput meets expectations.
func (i *EmailAddressVerificationRequestInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(ctx, i,
		validation.Field(&i.Token, validation.Required),
	)
}

var _ validation.ValidatableWithContext = (*UsernameUpdateInput)(nil)

// ValidateWithContext ensures our provided UsernameUpdateInput meets expectations.
func (i *UsernameUpdateInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(ctx, i,
		validation.Field(&i.NewUsername, validation.Required),
		validation.Field(&i.CurrentPassword, validation.Required),
		validation.Field(&i.TOTPToken, validation.When(i.TOTPToken != "", totpTokenLengthRule)),
	)
}

var _ validation.ValidatableWithContext = (*UserEmailAddressUpdateInput)(nil)

// ValidateWithContext ensures our provided UserEmailAddressUpdateInput meets expectations.
func (i *UserEmailAddressUpdateInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(ctx, i,
		validation.Field(&i.NewEmailAddress, validation.Required),
		validation.Field(&i.CurrentPassword, validation.Required),
		validation.Field(&i.TOTPToken, validation.When(i.TOTPToken != "", totpTokenLengthRule)),
	)
}

var _ validation.ValidatableWithContext = (*UserDetailsUpdateRequestInput)(nil)

// ValidateWithContext ensures our provided UserDetailsUpdateRequestInput meets expectations.
func (i *UserDetailsUpdateRequestInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(ctx, i,
		validation.Field(&i.FirstName, validation.Required),
		validation.Field(&i.CurrentPassword, validation.Required),
		validation.Field(&i.TOTPToken, validation.When(i.TOTPToken != "", totpTokenLengthRule)),
	)
}
