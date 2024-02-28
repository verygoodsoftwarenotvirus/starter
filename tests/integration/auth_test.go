package integration

import (
	"context"
	"database/sql"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	authservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/authentication"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func (s *TestSuite) TestLogin() {
	s.Run("logging in and out works", func() {
		t := s.T()

		ctx, span := tracing.StartCustomSpan(context.Background(), t.Name())
		defer span.End()

		testUser, _, testClient, _ := createUserAndClientForTest(ctx, t, nil)
		cookie, err := testClient.BeginSession(ctx, &types.UserLoginInput{
			Username:  testUser.Username,
			Password:  testUser.HashedPassword,
			TOTPToken: generateTOTPTokenForUser(t, testUser),
		})

		assert.NotNil(t, cookie)
		assert.NoError(t, err)

		assert.Equal(t, authservice.DefaultCookieName, cookie.Name)
		assert.NotEmpty(t, cookie.Value)
		assert.NotZero(t, cookie.MaxAge)
		assert.True(t, cookie.HttpOnly)
		assert.Equal(t, "/", cookie.Path)
		assert.Equal(t, http.SameSiteNoneMode, cookie.SameSite)

		assert.NoError(t, testClient.EndSession(ctx))
	})
}

func (s *TestSuite) TestLogin_WithoutBodyReturnsError() {
	s.Run("login request without body returns error", func() {
		t := s.T()

		ctx, span := tracing.StartSpan(context.Background())
		defer span.End()

		_, _, testClient, _ := createUserAndClientForTest(ctx, t, nil)

		u, err := url.Parse(testClient.BuildURL(ctx, nil))
		require.NoError(t, err)
		u.Path = "/users/login"

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), http.NoBody)
		requireNotNilAndNoProblems(t, req, err)

		// execute login request.
		res, err := testClient.PlainClient().Do(req)
		requireNotNilAndNoProblems(t, res, err)
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
	})
}

func (s *TestSuite) TestLogin_ShouldNotBeAbleToLoginWithInvalidPassword() {
	s.Run("should not be able to log in with the wrong password", func() {
		t := s.T()

		ctx, span := tracing.StartCustomSpan(context.Background(), t.Name())
		defer span.End()

		testUser, _, testClient, _ := createUserAndClientForTest(ctx, t, nil)

		// create login request.
		var badPassword string
		for _, v := range testUser.HashedPassword {
			badPassword = string(v) + badPassword
		}

		r := &types.UserLoginInput{
			Username:  testUser.Username,
			Password:  badPassword,
			TOTPToken: generateTOTPTokenForUser(t, testUser),
		}

		cookie, err := testClient.BeginSession(ctx, r)
		assert.Nil(t, cookie)
		assert.Error(t, err)
	})
}

func (s *TestSuite) TestLogin_ShouldNotBeAbleToLoginAsANonexistentUser() {
	s.Run("should not be able to login as someone that does not exist", func() {
		t := s.T()

		ctx, span := tracing.StartCustomSpan(context.Background(), t.Name())
		defer span.End()

		testUser, _, testClient, _ := createUserAndClientForTest(ctx, t, nil)

		exampleUserCreationInput := fakes.BuildFakeUserCreationInput()
		r := &types.UserLoginInput{
			Username:  exampleUserCreationInput.Username,
			Password:  testUser.HashedPassword,
			TOTPToken: "123456",
		}

		cookie, err := testClient.BeginSession(ctx, r)
		assert.Nil(t, cookie)
		assert.Error(t, err)
	})
}

func (s *TestSuite) TestLogin_ShouldNotBeAbleToLoginWithoutValidating2FASecret() {
	s.Run("should be able to login without validating 2FA secret", func() {
		t := s.T()

		ctx, span := tracing.StartSpan(context.Background())
		defer span.End()

		testClient := buildSimpleClient(t)

		// create a user.
		exampleUser := fakes.BuildFakeUser()
		exampleUserCreationInput := fakes.BuildFakeUserRegistrationInputFromUser(exampleUser)
		ucr, err := testClient.CreateUser(ctx, exampleUserCreationInput)
		requireNotNilAndNoProblems(t, ucr, err)

		// create login request.
		r := &types.UserLoginInput{
			Username: exampleUserCreationInput.Username,
			Password: exampleUserCreationInput.Password,
		}

		cookie, err := testClient.BeginSession(ctx, r)
		assert.NotNil(t, cookie)
		assert.NoError(t, err)
	})
}

func (s *TestSuite) TestCheckingAuthStatus() {
	s.Run("checking auth status", func() {
		t := s.T()

		ctx, span := tracing.StartCustomSpan(context.Background(), t.Name())
		defer span.End()

		testUser, _, testClient, _ := createUserAndClientForTest(ctx, t, nil)
		cookie, err := testClient.BeginSession(ctx, &types.UserLoginInput{
			Username:  testUser.Username,
			Password:  testUser.HashedPassword,
			TOTPToken: generateTOTPTokenForUser(t, testUser),
		})

		require.NotNil(t, cookie)
		assert.NoError(t, err)

		actual, err := testClient.UserStatus(ctx)
		assert.NoError(t, err)

		assert.Equal(t, true, actual.UserIsAuthenticated, "expected UserIsAuthenticated to equal %v, but got %v", true, actual.UserIsAuthenticated)
		assert.Equal(t, string(types.UnverifiedAccountStatus), actual.AccountStatus, "expected AccountStatus to equal %v, but got %v", types.GoodStandingUserAccountStatus, actual.AccountStatus)
		assert.Equal(t, "", actual.AccountStatusExplanation, "expected AccountStatusExplanation to equal %v, but got %v", "", actual.AccountStatusExplanation)
		assert.NotZero(t, actual.ActiveAccount)

		assert.NoError(t, testClient.EndSession(ctx))
	})
}

func (s *TestSuite) TestPasswordChanging() {
	s.Run("should be possible to change your password", func() {
		t := s.T()

		ctx, span := tracing.StartSpan(context.Background())
		defer span.End()

		testUser, _, testClient, _ := createUserAndClientForTest(ctx, t, nil)

		// login.
		cookie, err := testClient.BeginSession(ctx, &types.UserLoginInput{
			Username:  testUser.Username,
			Password:  testUser.HashedPassword,
			TOTPToken: generateTOTPTokenForUser(t, testUser),
		})
		require.NotNil(t, cookie)
		assert.NoError(t, err)

		// create new passwords.
		var backwardsPass string
		for _, v := range testUser.HashedPassword {
			backwardsPass = string(v) + backwardsPass
		}

		// update passwords.
		assert.NoError(t, testClient.ChangePassword(ctx, cookie, &types.PasswordUpdateInput{
			CurrentPassword: testUser.HashedPassword,
			TOTPToken:       generateTOTPTokenForUser(t, testUser),
			NewPassword:     backwardsPass,
		}))

		// logout.
		assert.NoError(t, testClient.EndSession(ctx))

		// login again with new passwords.
		cookie, err = testClient.BeginSession(ctx, &types.UserLoginInput{
			Username:  testUser.Username,
			Password:  backwardsPass,
			TOTPToken: generateTOTPTokenForUser(t, testUser),
		})

		assert.NotNil(t, cookie)
		assert.NoError(t, err)
	})
}

func (s *TestSuite) TestTOTPSecretChanging() {
	s.Run("should be possible to change your TOTP secret", func() {
		t := s.T()

		ctx, span := tracing.StartCustomSpan(context.Background(), t.Name())
		defer span.End()

		testUser, _, testClient, _ := createUserAndClientForTest(ctx, t, nil)

		cookie, err := testClient.BeginSession(ctx, &types.UserLoginInput{
			Username:  testUser.Username,
			Password:  testUser.HashedPassword,
			TOTPToken: generateTOTPTokenForUser(t, testUser),
		})
		require.NoError(t, err)

		r, err := testClient.CycleTwoFactorSecret(ctx, cookie, &types.TOTPSecretRefreshInput{
			CurrentPassword: testUser.HashedPassword,
			TOTPToken:       generateTOTPTokenForUser(t, testUser),
		})
		require.NoError(t, err)

		testUser.TwoFactorSecret = r.TwoFactorSecret
		require.NoError(t, testClient.VerifyTOTPSecret(ctx, testUser.ID, generateTOTPTokenForUser(t, testUser)))

		// logout.
		require.NoError(t, testClient.EndSession(ctx))

		// create login request.
		newToken, err := totp.GenerateCode(r.TwoFactorSecret, time.Now().UTC())
		requireNotNilAndNoProblems(t, newToken, err)

		secondCookie, err := testClient.BeginSession(ctx, &types.UserLoginInput{
			Username:  testUser.Username,
			Password:  testUser.HashedPassword,
			TOTPToken: newToken,
		})
		assert.NoError(t, err)
		assert.NotNil(t, secondCookie)
	})
}

func (s *TestSuite) TestTOTPTokenValidation() {
	s.Run("should be possible to validate TOTP", func() {
		t := s.T()

		ctx, span := tracing.StartSpan(context.Background())
		defer span.End()

		testClient := buildSimpleClient(t)

		// create user.
		userInput := fakes.BuildFakeUserCreationInput()
		user, err := testClient.CreateUser(ctx, userInput)
		assert.NotNil(t, user)
		require.NoError(t, err)

		token, err := totp.GenerateCode(user.TwoFactorSecret, time.Now().UTC())
		requireNotNilAndNoProblems(t, token, err)

		assert.NoError(t, testClient.VerifyTOTPSecret(ctx, user.CreatedUserID, token))
	})

	s.Run("should not be possible to validate an invalid TOTP", func() {
		t := s.T()

		ctx, span := tracing.StartCustomSpan(context.Background(), t.Name())
		defer span.End()

		testClient := buildSimpleClient(t)

		// create user.
		userInput := fakes.BuildFakeUserCreationInput()
		user, err := testClient.CreateUser(ctx, userInput)
		assert.NotNil(t, user)
		require.NoError(t, err)

		assert.Error(t, testClient.VerifyTOTPSecret(ctx, user.CreatedUserID, "NOTREAL"))
	})
}

func (s *TestSuite) TestLogin_RequestingPasswordReset() {
	s.Run("able to reset one's password and then redeem it", func() {
		t := s.T()

		ctx, span := tracing.StartSpan(context.Background())
		defer span.End()

		u, _, testClient, _ := createUserAndClientForTest(ctx, t, nil)

		require.NoError(t, testClient.RequestPasswordResetToken(ctx, u.EmailAddress))

		dbAddr := os.Getenv("TARGET_DATABASE")
		if dbAddr == "" {
			panic("empty database address provided")
		}

		db, err := sql.Open("pgx", dbAddr)
		if err != nil {
			panic(err)
		}

		var token string
		queryErr := db.QueryRow(`SELECT token FROM password_reset_tokens WHERE belongs_to_user = $1`, u.ID).Scan(&token)
		require.NoError(t, queryErr)

		resetToken, err := dbmanager.GetPasswordResetTokenByToken(ctx, token)
		requireNotNilAndNoProblems(t, resetToken, err)

		fakeInput := fakes.BuildFakeUserCreationInput()

		require.NoError(t, testClient.RedeemPasswordResetToken(ctx, &types.PasswordResetTokenRedemptionRequestInput{
			Token:       resetToken.Token,
			NewPassword: fakeInput.Password,
		}))

		cookie, err := testClient.BeginSession(ctx, &types.UserLoginInput{
			Username:  u.Username,
			Password:  fakeInput.Password,
			TOTPToken: generateTOTPTokenForUser(t, u),
		})
		requireNotNilAndNoProblems(t, cookie, err)

		require.Error(t, testClient.RedeemPasswordResetToken(ctx, &types.PasswordResetTokenRedemptionRequestInput{
			Token:       resetToken.Token,
			NewPassword: fakeInput.Password,
		}))
	})
}
