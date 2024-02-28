package email

import (
	"testing"
	"time"

	"github.com/verygoodsoftwarenotvirus/starter/internal/pkg/pointer"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"

	"github.com/stretchr/testify/assert"
)

func TestBuildGeneratedPasswordResetTokenEmail(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		user := fakes.BuildFakeUser()
		user.EmailAddressVerifiedAt = pointer.To(time.Now())
		token := fakes.BuildFakePasswordResetToken()

		actual, err := BuildGeneratedPasswordResetTokenEmail(user, token, envConfigsMap[defaultEnv])
		assert.NoError(t, err)
		assert.NotNil(t, actual)
		assert.Contains(t, actual.HTMLContent, logoURL)
	})
}

func TestBuildInviteMemberEmail(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		invitation := fakes.BuildFakeAccountInvitation()

		actual, err := BuildInviteMemberEmail(invitation, envConfigsMap[defaultEnv])
		assert.NoError(t, err)
		assert.NotNil(t, actual)
	})
}

func TestBuildPasswordResetTokenRedeemedEmail(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		user := fakes.BuildFakeUser()
		user.EmailAddressVerifiedAt = pointer.To(time.Now())

		actual, err := BuildPasswordResetTokenRedeemedEmail(user, envConfigsMap[defaultEnv])
		assert.NoError(t, err)
		assert.NotNil(t, actual)
	})
}

func TestBuildUsernameReminderEmail(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		user := fakes.BuildFakeUser()
		user.EmailAddressVerifiedAt = pointer.To(time.Now())

		actual, err := BuildUsernameReminderEmail(user, envConfigsMap[defaultEnv])
		assert.NoError(t, err)
		assert.NotNil(t, actual)
	})
}
