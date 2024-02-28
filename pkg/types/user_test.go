package types

import (
	"context"
	"testing"
	"time"

	"github.com/verygoodsoftwarenotvirus/starter/internal/pkg/pointer"

	"github.com/stretchr/testify/assert"
)

func TestUser_Update(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()
		actual := User{
			Username:        "old_username",
			HashedPassword:  "hashed_pass",
			TwoFactorSecret: "two factor secret",
			Birthday:        pointer.To[time.Time](time.Now()),
		}

		exampleInput := User{
			Username:        "new_username",
			HashedPassword:  "updated_hashed_pass",
			TwoFactorSecret: "new fancy secret",
			FirstName:       "first",
			LastName:        "last",
			Birthday:        pointer.To[time.Time](time.Now()),
		}

		actual.Update(&exampleInput)
		assert.Equal(t, exampleInput, actual)
	})
}

func TestUser_IsBanned(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		x := &User{AccountStatus: string(BannedUserAccountStatus)}

		assert.True(t, x.IsBanned())
	})
}

func TestUserRegistrationInput_ValidateWithContext(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		x := &UserRegistrationInput{
			Username:     t.Name(),
			Password:     t.Name(),
			EmailAddress: "things@stuff.com",
		}

		assert.NoError(t, x.ValidateWithContext(ctx, 1, 1))
	})

	T.Run("invalid", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		x := &UserRegistrationInput{
			Username:     "",
			EmailAddress: "",
			Password:     "",
		}

		err := x.ValidateWithContext(ctx, 1, 1)
		assert.Error(t, err)
	})
}

func TestTOTPSecretVerificationInput_ValidateWithContext(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		x := &TOTPSecretVerificationInput{
			UserID:    "123",
			TOTPToken: "123456",
		}

		assert.NoError(t, x.ValidateWithContext(ctx))
	})
}

func TestUserLoginInput_ValidateWithContext(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		x := &UserLoginInput{
			Username:  t.Name(),
			Password:  t.Name(),
			TOTPToken: "123456",
		}

		assert.NoError(t, x.ValidateWithContext(ctx, 1, 1))
	})
}

func TestPasswordUpdateInput_ValidateWithContext(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		x := &PasswordUpdateInput{
			NewPassword:     "new_password",
			CurrentPassword: t.Name(),
			TOTPToken:       "123456",
		}

		assert.NoError(t, x.ValidateWithContext(ctx, 1))
	})

	T.Run("with identical passwords", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		x := &PasswordUpdateInput{
			NewPassword:     t.Name(),
			CurrentPassword: t.Name(),
			TOTPToken:       "123456",
		}

		assert.Error(t, x.ValidateWithContext(ctx, 1))
	})
}

func TestTOTPSecretRefreshInput_ValidateWithContext(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		x := &TOTPSecretRefreshInput{
			CurrentPassword: t.Name(),
			TOTPToken:       "123456",
		}

		assert.NoError(t, x.ValidateWithContext(ctx))
	})
}

func TestEmailAddressVerificationRequestInput_ValidateWithContext(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		x := &EmailAddressVerificationRequestInput{
			Token: "123456",
		}

		assert.NoError(t, x.ValidateWithContext(ctx))
	})
}

func TestUsernameUpdateInput_ValidateWithContext(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		x := &UsernameUpdateInput{
			NewUsername:     t.Name(),
			CurrentPassword: t.Name(),
			TOTPToken:       "123456",
		}

		assert.NoError(t, x.ValidateWithContext(ctx))
	})
}

func TestUserEmailAddressUpdateInput_ValidateWithContext(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		x := &UserEmailAddressUpdateInput{
			NewEmailAddress: t.Name(),
			CurrentPassword: t.Name(),
			TOTPToken:       "123456",
		}

		assert.NoError(t, x.ValidateWithContext(ctx))
	})
}

func TestUserDetailsUpdateRequestInput_ValidateWithContext(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		x := &UserDetailsUpdateRequestInput{
			FirstName:       t.Name(),
			CurrentPassword: t.Name(),
			TOTPToken:       "123456",
		}

		assert.NoError(t, x.ValidateWithContext(ctx))
	})
}
