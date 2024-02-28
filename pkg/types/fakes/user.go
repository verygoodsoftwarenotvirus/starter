package fakes

import (
	"encoding/base32"
	"fmt"
	"log"
	"time"

	"github.com/verygoodsoftwarenotvirus/starter/internal/authorization"
	"github.com/verygoodsoftwarenotvirus/starter/internal/pkg/pointer"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"

	fake "github.com/brianvoe/gofakeit/v7"
	"github.com/pquerna/otp/totp"
)

// BuildFakeUser builds a faked User.
func BuildFakeUser() *types.User {
	fakeDate := BuildFakeTime()

	return &types.User{
		ID:                        BuildFakeID(),
		FirstName:                 fake.FirstName(),
		LastName:                  fake.LastName(),
		EmailAddress:              fake.Email(),
		Username:                  fmt.Sprintf("%s_%d_%s", fake.Username(), fake.Uint8(), fake.Username()),
		Birthday:                  pointer.To(BuildFakeTime()),
		AccountStatus:             string(types.UnverifiedAccountStatus),
		TwoFactorSecret:           base32.StdEncoding.EncodeToString([]byte(fake.Password(false, true, true, false, false, 32))),
		TwoFactorSecretVerifiedAt: &fakeDate,
		ServiceRole:               authorization.ServiceUserRole.String(),
		CreatedAt:                 BuildFakeTime(),
	}
}

// BuildFakeUserList builds a faked UserList.
func BuildFakeUserList() *types.QueryFilteredResult[types.User] {
	var examples []*types.User
	for i := 0; i < exampleQuantity; i++ {
		examples = append(examples, BuildFakeUser())
	}

	return &types.QueryFilteredResult[types.User]{
		Pagination: types.Pagination{
			Page:          1,
			Limit:         50,
			FilteredCount: exampleQuantity / 2,
			TotalCount:    exampleQuantity,
		},
		Data: examples,
	}
}

// BuildFakeUserCreationInput builds a faked UserRegistrationInput.
func BuildFakeUserCreationInput() *types.UserRegistrationInput {
	exampleUser := BuildFakeUser()

	return &types.UserRegistrationInput{
		Username:     exampleUser.Username,
		EmailAddress: fake.Email(),
		FirstName:    exampleUser.FirstName,
		LastName:     exampleUser.LastName,
		Password:     buildFakePassword(),
		Birthday:     exampleUser.Birthday,
	}
}

// BuildFakeUserRegistrationInputFromUser builds a faked UserRegistrationInput.
func BuildFakeUserRegistrationInputFromUser(user *types.User) *types.UserRegistrationInput {
	return &types.UserRegistrationInput{
		Username:     user.Username,
		FirstName:    user.FirstName,
		LastName:     user.LastName,
		EmailAddress: user.EmailAddress,
		Password:     buildFakePassword(),
		Birthday:     user.Birthday,
	}
}

// BuildFakeUserRegistrationInputWithInviteFromUser builds a faked UserRegistrationInput.
func BuildFakeUserRegistrationInputWithInviteFromUser(user *types.User) *types.UserRegistrationInput {
	return &types.UserRegistrationInput{
		Username:        user.Username,
		FirstName:       user.FirstName,
		LastName:        user.LastName,
		EmailAddress:    user.EmailAddress,
		Password:        buildFakePassword(),
		Birthday:        user.Birthday,
		InvitationToken: fake.UUID(),
		InvitationID:    BuildFakeID(),
	}
}

// BuildFakeUserAccountStatusUpdateInputFromUser builds a faked UserAccountStatusUpdateInput.
func BuildFakeUserAccountStatusUpdateInputFromUser(user *types.User) *types.UserAccountStatusUpdateInput {
	return &types.UserAccountStatusUpdateInput{
		TargetUserID: BuildFakeID(),
		NewStatus:    user.AccountStatus,
		Reason:       fake.Sentence(10),
	}
}

// BuildFakeUserLoginInputFromUser builds a faked UserLoginInput.
func BuildFakeUserLoginInputFromUser(user *types.User) *types.UserLoginInput {
	return &types.UserLoginInput{
		Username:  user.Username,
		Password:  buildFakePassword(),
		TOTPToken: fmt.Sprintf("0%s", fake.Zip()),
	}
}

// BuildFakePasswordUpdateInput builds a faked PasswordUpdateInput.
func BuildFakePasswordUpdateInput() *types.PasswordUpdateInput {
	return &types.PasswordUpdateInput{
		NewPassword:     buildFakePassword(),
		CurrentPassword: buildFakePassword(),
		TOTPToken:       fmt.Sprintf("0%s", fake.Zip()),
	}
}

// BuildFakeAvatarUpdateInput builds a faked AvatarUpdateInput.
func BuildFakeAvatarUpdateInput() *types.AvatarUpdateInput {
	return &types.AvatarUpdateInput{
		Base64EncodedData: buildUniqueString(),
	}
}

// BuildFakeTOTPSecretRefreshInput builds a faked TOTPSecretRefreshInput.
func BuildFakeTOTPSecretRefreshInput() *types.TOTPSecretRefreshInput {
	return &types.TOTPSecretRefreshInput{
		CurrentPassword: buildFakePassword(),
		TOTPToken:       fmt.Sprintf("0%s", fake.Zip()),
	}
}

// BuildFakeUserPermissionsRequestInput builds a faked UserPermissionsRequestInput.
func BuildFakeUserPermissionsRequestInput() *types.UserPermissionsRequestInput {
	return &types.UserPermissionsRequestInput{
		Permissions: []string{
			buildUniqueString(),
			buildUniqueString(),
			buildUniqueString(),
		},
	}
}

// BuildFakeTOTPSecretVerificationInputForUser builds a faked TOTPSecretVerificationInput for a given user.
func BuildFakeTOTPSecretVerificationInputForUser(user *types.User) *types.TOTPSecretVerificationInput {
	token, err := totp.GenerateCode(user.TwoFactorSecret, time.Now().UTC())
	if err != nil {
		log.Panicf("error generating TOTP token for fakes user: %v", err)
	}

	return &types.TOTPSecretVerificationInput{
		UserID:    user.ID,
		TOTPToken: token,
	}
}

// BuildFakePasswordResetToken builds a faked PasswordResetToken.
func BuildFakePasswordResetToken() *types.PasswordResetToken {
	fakeDate := BuildFakeTime()

	return &types.PasswordResetToken{
		ID:            BuildFakeID(),
		Token:         fake.UUID(),
		BelongsToUser: BuildFakeID(),
		ExpiresAt:     fakeDate.Add(30 * time.Minute),
		CreatedAt:     fakeDate,
	}
}

// BuildFakeUsernameReminderRequestInput builds a faked UsernameReminderRequestInput.
func BuildFakeUsernameReminderRequestInput() *types.UsernameReminderRequestInput {
	return &types.UsernameReminderRequestInput{
		EmailAddress: fake.Email(),
	}
}

// BuildFakePasswordResetTokenCreationRequestInput builds a faked PasswordResetTokenCreationRequestInput.
func BuildFakePasswordResetTokenCreationRequestInput() *types.PasswordResetTokenCreationRequestInput {
	return &types.PasswordResetTokenCreationRequestInput{EmailAddress: fake.Email()}
}

// BuildFakePasswordResetTokenRedemptionRequestInput builds a faked PasswordResetTokenRedemptionRequestInput.
func BuildFakePasswordResetTokenRedemptionRequestInput() *types.PasswordResetTokenRedemptionRequestInput {
	return &types.PasswordResetTokenRedemptionRequestInput{
		Token:       buildUniqueString(),
		NewPassword: buildFakePassword(),
	}
}

// BuildFakeEmailAddressVerificationRequestInput builds a faked EmailAddressVerificationRequestInput.
func BuildFakeEmailAddressVerificationRequestInput() *types.EmailAddressVerificationRequestInput {
	return &types.EmailAddressVerificationRequestInput{
		Token: buildUniqueString(),
	}
}

func BuildFakeUsernameUpdateInput() *types.UsernameUpdateInput {
	return &types.UsernameUpdateInput{
		NewUsername:     buildUniqueString(),
		CurrentPassword: fake.Password(true, true, true, false, false, 32),
		TOTPToken:       "123456",
	}
}

func BuildFakeUserEmailAddressUpdateInput() *types.UserEmailAddressUpdateInput {
	return &types.UserEmailAddressUpdateInput{
		NewEmailAddress: fake.Email(),
		CurrentPassword: fake.Password(true, true, true, false, false, 32),
		TOTPToken:       "123456",
	}
}

func BuildFakeUserDetailsUpdateInput() *types.UserDetailsUpdateRequestInput {
	return &types.UserDetailsUpdateRequestInput{
		FirstName:       buildUniqueString(),
		LastName:        buildUniqueString(),
		Birthday:        BuildFakeTime(),
		CurrentPassword: fake.Password(true, true, true, false, false, 32),
		TOTPToken:       "123456",
	}
}

func BuildFakeUserDetailsDatabaseUpdateInput() *types.UserDetailsDatabaseUpdateInput {
	return &types.UserDetailsDatabaseUpdateInput{
		FirstName: buildUniqueString(),
		LastName:  buildUniqueString(),
		Birthday:  BuildFakeTime(),
	}
}
