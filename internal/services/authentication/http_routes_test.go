package authentication

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/verygoodsoftwarenotvirus/starter/internal/authentication"
	mockauthn "github.com/verygoodsoftwarenotvirus/starter/internal/authentication/mock"
	"github.com/verygoodsoftwarenotvirus/starter/internal/authorization"
	"github.com/verygoodsoftwarenotvirus/starter/internal/encoding"
	mockpublishers "github.com/verygoodsoftwarenotvirus/starter/internal/messagequeue/mock"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/internal/pkg/random"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"
	mocktypes "github.com/verygoodsoftwarenotvirus/starter/pkg/types/mock"
	testutils "github.com/verygoodsoftwarenotvirus/starter/tests/utils"

	"github.com/gorilla/securecookie"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func Test_service_determineCookieDomain(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		helper := buildTestHelper(t)

		req := httptest.NewRequest(http.MethodPost, "/users/login", http.NoBody)

		actual := helper.service.determineCookieDomain(ctx, req)
		assert.Equal(t, helper.service.config.Cookies.Domain, actual)
	})

	T.Run("with requested domain", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		helper := buildTestHelper(t)

		expected := ".whocares.gov"

		req := httptest.NewRequest(http.MethodPost, "/users/login", http.NoBody)
		req.Header.Set(customCookieDomainHeader, expected)

		actual := helper.service.determineCookieDomain(ctx, req)
		assert.Equal(t, expected, actual)
	})
}

func TestAuthenticationService_issueSessionManagedCookie(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		expectedToken, err := random.GenerateBase64EncodedString(helper.ctx, 32)
		require.NoError(t, err)

		sm := &mockSessionManager{}
		sm.On("Load", testutils.ContextMatcher, "").Return(helper.ctx, nil)
		sm.On("RenewToken", testutils.ContextMatcher).Return(nil)
		sm.On("Put", testutils.ContextMatcher, userIDContextKey, helper.exampleUser.ID)
		sm.On("Put", testutils.ContextMatcher, accountIDContextKey, helper.exampleAccount.ID)
		sm.On("Commit", testutils.ContextMatcher).Return(expectedToken, time.Now().Add(24*time.Hour), nil)
		helper.service.sessionManager = sm

		cookie, err := helper.service.issueSessionManagedCookie(helper.ctx, helper.exampleAccount.ID, helper.exampleUser.ID, helper.service.config.Cookies.Domain)
		require.NotNil(t, cookie)
		assert.NoError(t, err)

		var actualToken string
		assert.NoError(t, helper.service.cookieManager.Decode(helper.service.config.Cookies.Name, cookie.Value, &actualToken))

		assert.Equal(t, expectedToken, actualToken)

		mock.AssertExpectationsForObjects(t, sm)
	})

	T.Run("with error loading from session manager", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		sm := &mockSessionManager{}
		sm.On("Load", testutils.ContextMatcher, "").Return(helper.ctx, errors.New("blah"))
		helper.service.sessionManager = sm

		cookie, err := helper.service.issueSessionManagedCookie(helper.ctx, helper.exampleAccount.ID, helper.exampleUser.ID, helper.service.config.Cookies.Domain)
		require.Nil(t, cookie)
		assert.Error(t, err)

		mock.AssertExpectationsForObjects(t, sm)
	})

	T.Run("with error renewing token", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		sm := &mockSessionManager{}
		sm.On("Load", testutils.ContextMatcher, "").Return(helper.ctx, nil)
		sm.On("RenewToken", testutils.ContextMatcher).Return(errors.New("blah"))
		helper.service.sessionManager = sm

		cookie, err := helper.service.issueSessionManagedCookie(helper.ctx, helper.exampleAccount.ID, helper.exampleUser.ID, helper.service.config.Cookies.Domain)
		require.Nil(t, cookie)
		assert.Error(t, err)

		mock.AssertExpectationsForObjects(t, sm)
	})

	T.Run("with error committing", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		expectedToken, err := random.GenerateBase64EncodedString(helper.ctx, 32)
		require.NoError(t, err)

		sm := &mockSessionManager{}
		sm.On("Load", testutils.ContextMatcher, "").Return(helper.ctx, nil)
		sm.On("RenewToken", testutils.ContextMatcher).Return(nil)
		sm.On("Put", testutils.ContextMatcher, userIDContextKey, helper.exampleUser.ID)
		sm.On("Put", testutils.ContextMatcher, accountIDContextKey, helper.exampleAccount.ID)
		sm.On("Commit", testutils.ContextMatcher).Return(expectedToken, time.Now(), errors.New("blah"))
		helper.service.sessionManager = sm

		cookie, err := helper.service.issueSessionManagedCookie(helper.ctx, helper.exampleAccount.ID, helper.exampleUser.ID, helper.service.config.Cookies.Domain)
		require.Nil(t, cookie)
		assert.Error(t, err)

		mock.AssertExpectationsForObjects(t, sm)
	})

	T.Run("with error building cookie", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		expectedToken, err := random.GenerateBase64EncodedString(helper.ctx, 32)
		require.NoError(t, err)

		sm := &mockSessionManager{}
		sm.On("Load", testutils.ContextMatcher, "").Return(helper.ctx, nil)
		sm.On("RenewToken", testutils.ContextMatcher).Return(nil)
		sm.On("Put", testutils.ContextMatcher, userIDContextKey, helper.exampleUser.ID)
		sm.On("Put", testutils.ContextMatcher, accountIDContextKey, helper.exampleAccount.ID)
		sm.On("Commit", testutils.ContextMatcher).Return(expectedToken, time.Now().Add(24*time.Hour), nil)
		helper.service.sessionManager = sm

		helper.service.cookieManager = securecookie.New(
			securecookie.GenerateRandomKey(0),
			[]byte(""),
		)

		cookie, err := helper.service.issueSessionManagedCookie(helper.ctx, helper.exampleAccount.ID, helper.exampleUser.ID, helper.service.config.Cookies.Domain)
		require.Nil(t, cookie)
		assert.Error(t, err)
	})
}

func TestAuthenticationService_BuildLoginHandler_WithoutAdminRestriction(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, helper.exampleLoginInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		userDataManager := &mocktypes.UserDataManagerMock{}
		userDataManager.On(
			"GetUserByUsername",
			testutils.ContextMatcher,
			helper.exampleUser.Username,
		).Return(helper.exampleUser, nil)
		helper.service.userDataManager = userDataManager

		authenticator := &mockauthn.Authenticator{}
		authenticator.On(
			"CredentialsAreValid",
			testutils.ContextMatcher,
			helper.exampleUser.HashedPassword,
			helper.exampleLoginInput.Password,
			helper.exampleUser.TwoFactorSecret,
			helper.exampleLoginInput.TOTPToken,
		).Return(true, nil)
		helper.service.authenticator = authenticator

		membershipDB := &mocktypes.AccountUserMembershipDataManagerMock{}
		membershipDB.On(
			"GetDefaultAccountIDForUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleAccount.ID, nil)
		helper.service.accountMembershipManager = membershipDB

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(nil)
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.BuildLoginHandler(false)(helper.res, helper.req)

		assert.Equal(t, http.StatusAccepted, helper.res.Code)
		assert.NotEmpty(t, helper.res.Header().Get("Set-Cookie"))
		var actual *types.APIResponse[*types.UserStatusResponse]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NotEmpty(t, actual.Data)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, userDataManager, authenticator, membershipDB, dataChangesPublisher)
	})

	T.Run("standard with admin", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, helper.exampleLoginInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		userDataManager := &mocktypes.UserDataManagerMock{}
		userDataManager.On(
			"GetAdminUserByUsername",
			testutils.ContextMatcher,
			helper.exampleUser.Username,
		).Return(helper.exampleUser, nil)
		helper.service.userDataManager = userDataManager

		authenticator := &mockauthn.Authenticator{}
		authenticator.On(
			"CredentialsAreValid",
			testutils.ContextMatcher,
			helper.exampleUser.HashedPassword,
			helper.exampleLoginInput.Password,
			helper.exampleUser.TwoFactorSecret,
			helper.exampleLoginInput.TOTPToken,
		).Return(true, nil)
		helper.service.authenticator = authenticator

		membershipDB := &mocktypes.AccountUserMembershipDataManagerMock{}
		membershipDB.On(
			"GetDefaultAccountIDForUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleAccount.ID, nil)
		helper.service.accountMembershipManager = membershipDB

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(nil)
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.BuildLoginHandler(true)(helper.res, helper.req)

		assert.Equal(t, http.StatusAccepted, helper.res.Code)
		assert.NotEmpty(t, helper.res.Header().Get("Set-Cookie"))
		var actual *types.APIResponse[*types.UserStatusResponse]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NotEmpty(t, actual.Data)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, userDataManager, authenticator, membershipDB, dataChangesPublisher)
	})

	T.Run("with requested cookie domain", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, helper.exampleLoginInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		expectedCookieDomain := ".whocares.gov"
		helper.req.Header.Set(customCookieDomainHeader, expectedCookieDomain)

		userDataManager := &mocktypes.UserDataManagerMock{}
		userDataManager.On(
			"GetUserByUsername",
			testutils.ContextMatcher,
			helper.exampleUser.Username,
		).Return(helper.exampleUser, nil)
		helper.service.userDataManager = userDataManager

		authenticator := &mockauthn.Authenticator{}
		authenticator.On(
			"CredentialsAreValid",
			testutils.ContextMatcher,
			helper.exampleUser.HashedPassword,
			helper.exampleLoginInput.Password,
			helper.exampleUser.TwoFactorSecret,
			helper.exampleLoginInput.TOTPToken,
		).Return(true, nil)
		helper.service.authenticator = authenticator

		membershipDB := &mocktypes.AccountUserMembershipDataManagerMock{}
		membershipDB.On(
			"GetDefaultAccountIDForUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleAccount.ID, nil)
		helper.service.accountMembershipManager = membershipDB

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(nil)
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.BuildLoginHandler(false)(helper.res, helper.req)

		assert.Equal(t, http.StatusAccepted, helper.res.Code)

		rawCookie := helper.res.Header().Get("Set-Cookie")
		assert.Contains(t, rawCookie, fmt.Sprintf("Domain=%s", strings.TrimPrefix(expectedCookieDomain, ".")))

		var actual *types.APIResponse[*types.UserStatusResponse]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NotEmpty(t, actual.Data)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, userDataManager, authenticator, membershipDB, dataChangesPublisher)
	})

	T.Run("with missing login data", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(nil))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.service.BuildLoginHandler(false)(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		assert.Empty(t, helper.res.Header().Get("Set-Cookie"))
	})

	T.Run("with invalid input", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, &types.UserLoginInput{})

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.service.BuildLoginHandler(false)(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		assert.Empty(t, helper.res.Header().Get("Set-Cookie"))
	})

	T.Run("with no results in the database", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, helper.exampleLoginInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		userDataManager := &mocktypes.UserDataManagerMock{}
		userDataManager.On(
			"GetUserByUsername",
			testutils.ContextMatcher,
			helper.exampleUser.Username,
		).Return((*types.User)(nil), sql.ErrNoRows)
		helper.service.userDataManager = userDataManager

		helper.service.BuildLoginHandler(false)(helper.res, helper.req)

		assert.Equal(t, http.StatusNotFound, helper.res.Code)
		assert.Empty(t, helper.res.Header().Get("Set-Cookie"))

		mock.AssertExpectationsForObjects(t, userDataManager)
	})

	T.Run("with error retrieving user from datastore", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, helper.exampleLoginInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		userDataManager := &mocktypes.UserDataManagerMock{}
		userDataManager.On(
			"GetUserByUsername",
			testutils.ContextMatcher,
			helper.exampleUser.Username,
		).Return((*types.User)(nil), errors.New("blah"))
		helper.service.userDataManager = userDataManager

		helper.service.BuildLoginHandler(false)(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		assert.Empty(t, helper.res.Header().Get("Set-Cookie"))

		mock.AssertExpectationsForObjects(t, userDataManager)
	})

	T.Run("with banned user", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		helper.exampleUser.AccountStatus = string(types.BannedUserAccountStatus)
		helper.exampleUser.AccountStatusExplanation = "bad behavior"
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, helper.exampleLoginInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		userDataManager := &mocktypes.UserDataManagerMock{}
		userDataManager.On(
			"GetUserByUsername",
			testutils.ContextMatcher,
			helper.exampleUser.Username,
		).Return(helper.exampleUser, nil)
		helper.service.userDataManager = userDataManager

		helper.service.BuildLoginHandler(false)(helper.res, helper.req)

		assert.Equal(t, http.StatusForbidden, helper.res.Code)
		assert.Empty(t, helper.res.Header().Get("Set-Cookie"))

		mock.AssertExpectationsForObjects(t, userDataManager)
	})

	T.Run("with invalid login", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, helper.exampleLoginInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		userDataManager := &mocktypes.UserDataManagerMock{}
		userDataManager.On(
			"GetUserByUsername",
			testutils.ContextMatcher,
			helper.exampleUser.Username,
		).Return(helper.exampleUser, nil)
		helper.service.userDataManager = userDataManager

		authenticator := &mockauthn.Authenticator{}
		authenticator.On(
			"CredentialsAreValid",
			testutils.ContextMatcher,
			helper.exampleUser.HashedPassword,
			helper.exampleLoginInput.Password,
			helper.exampleUser.TwoFactorSecret,
			helper.exampleLoginInput.TOTPToken,
		).Return(false, nil)
		helper.service.authenticator = authenticator

		helper.service.BuildLoginHandler(false)(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)
		assert.Empty(t, helper.res.Header().Get("Set-Cookie"))

		mock.AssertExpectationsForObjects(t, userDataManager, authenticator)
	})

	T.Run("with error validating login", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, helper.exampleLoginInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		userDataManager := &mocktypes.UserDataManagerMock{}
		userDataManager.On(
			"GetUserByUsername",
			testutils.ContextMatcher,
			helper.exampleUser.Username,
		).Return(helper.exampleUser, nil)
		helper.service.userDataManager = userDataManager

		authenticator := &mockauthn.Authenticator{}
		authenticator.On(
			"CredentialsAreValid",
			testutils.ContextMatcher,
			helper.exampleUser.HashedPassword,
			helper.exampleLoginInput.Password,
			helper.exampleUser.TwoFactorSecret,
			helper.exampleLoginInput.TOTPToken,
		).Return(true, errors.New("blah"))
		helper.service.authenticator = authenticator

		helper.service.BuildLoginHandler(false)(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		assert.Empty(t, helper.res.Header().Get("Set-Cookie"))

		mock.AssertExpectationsForObjects(t, userDataManager, authenticator)
	})

	T.Run("with invalid two factor code error returned", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, helper.exampleLoginInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		userDataManager := &mocktypes.UserDataManagerMock{}
		userDataManager.On(
			"GetUserByUsername",
			testutils.ContextMatcher,
			helper.exampleUser.Username,
		).Return(helper.exampleUser, nil)
		helper.service.userDataManager = userDataManager

		authenticator := &mockauthn.Authenticator{}
		authenticator.On(
			"CredentialsAreValid",
			testutils.ContextMatcher,
			helper.exampleUser.HashedPassword,
			helper.exampleLoginInput.Password,
			helper.exampleUser.TwoFactorSecret,
			helper.exampleLoginInput.TOTPToken,
		).Return(false, authentication.ErrInvalidTOTPToken)
		helper.service.authenticator = authenticator

		helper.service.BuildLoginHandler(false)(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)
		assert.Empty(t, helper.res.Header().Get("Set-Cookie"))

		mock.AssertExpectationsForObjects(t, userDataManager, authenticator)
	})

	T.Run("with non-matching password error returned", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, helper.exampleLoginInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		userDataManager := &mocktypes.UserDataManagerMock{}
		userDataManager.On(
			"GetUserByUsername",
			testutils.ContextMatcher,
			helper.exampleUser.Username,
		).Return(helper.exampleUser, nil)
		helper.service.userDataManager = userDataManager

		authenticator := &mockauthn.Authenticator{}
		authenticator.On(
			"CredentialsAreValid",
			testutils.ContextMatcher,
			helper.exampleUser.HashedPassword,
			helper.exampleLoginInput.Password,
			helper.exampleUser.TwoFactorSecret,
			helper.exampleLoginInput.TOTPToken,
		).Return(false, authentication.ErrPasswordDoesNotMatch)
		helper.service.authenticator = authenticator

		helper.service.BuildLoginHandler(false)(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)
		assert.Empty(t, helper.res.Header().Get("Set-Cookie"))

		mock.AssertExpectationsForObjects(t, userDataManager, authenticator)
	})

	T.Run("with verified two factor secret but without TOTP", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		helper.exampleLoginInput.TOTPToken = ""
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, helper.exampleLoginInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		userDataManager := &mocktypes.UserDataManagerMock{}
		userDataManager.On(
			"GetUserByUsername",
			testutils.ContextMatcher,
			helper.exampleUser.Username,
		).Return(helper.exampleUser, nil)
		helper.service.userDataManager = userDataManager

		authenticator := &mockauthn.Authenticator{}
		authenticator.On(
			"CredentialsAreValid",
			testutils.ContextMatcher,
			helper.exampleUser.HashedPassword,
			helper.exampleLoginInput.Password,
			helper.exampleUser.TwoFactorSecret,
			helper.exampleLoginInput.TOTPToken,
		).Return(true, nil)
		helper.service.authenticator = authenticator

		helper.service.BuildLoginHandler(false)(helper.res, helper.req)

		assert.Equal(t, http.StatusResetContent, helper.res.Code)
		assert.Empty(t, helper.res.Header().Get("Set-Cookie"))

		mock.AssertExpectationsForObjects(t, userDataManager, authenticator)
	})

	T.Run("with error fetching default account", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, helper.exampleLoginInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		userDataManager := &mocktypes.UserDataManagerMock{}
		userDataManager.On(
			"GetUserByUsername",
			testutils.ContextMatcher,
			helper.exampleUser.Username,
		).Return(helper.exampleUser, nil)
		helper.service.userDataManager = userDataManager

		authenticator := &mockauthn.Authenticator{}
		authenticator.On(
			"CredentialsAreValid",
			testutils.ContextMatcher,
			helper.exampleUser.HashedPassword,
			helper.exampleLoginInput.Password,
			helper.exampleUser.TwoFactorSecret,
			helper.exampleLoginInput.TOTPToken,
		).Return(true, nil)
		helper.service.authenticator = authenticator

		membershipDB := &mocktypes.AccountUserMembershipDataManagerMock{}
		membershipDB.On(
			"GetDefaultAccountIDForUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return("", errors.New("blah"))
		helper.service.accountMembershipManager = membershipDB

		helper.service.BuildLoginHandler(false)(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		assert.Empty(t, helper.res.Header().Get("Set-Cookie"))

		mock.AssertExpectationsForObjects(t, userDataManager, authenticator, membershipDB)
	})

	T.Run("with error loading from session manager", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, helper.exampleLoginInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		userDataManager := &mocktypes.UserDataManagerMock{}
		userDataManager.On(
			"GetUserByUsername",
			testutils.ContextMatcher,
			helper.exampleUser.Username,
		).Return(helper.exampleUser, nil)
		helper.service.userDataManager = userDataManager

		authenticator := &mockauthn.Authenticator{}
		authenticator.On(
			"CredentialsAreValid",
			testutils.ContextMatcher,
			helper.exampleUser.HashedPassword,
			helper.exampleLoginInput.Password,
			helper.exampleUser.TwoFactorSecret,
			helper.exampleLoginInput.TOTPToken,
		).Return(true, nil)
		helper.service.authenticator = authenticator

		membershipDB := &mocktypes.AccountUserMembershipDataManagerMock{}
		membershipDB.On(
			"GetDefaultAccountIDForUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleAccount.ID, nil)
		helper.service.accountMembershipManager = membershipDB

		sm := &mockSessionManager{}
		sm.On("Load", testutils.ContextMatcher, "").Return(helper.ctx, errors.New("blah"))
		helper.service.sessionManager = sm

		helper.service.BuildLoginHandler(false)(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		assert.Empty(t, helper.res.Header().Get("Set-Cookie"))

		mock.AssertExpectationsForObjects(t, userDataManager, authenticator, membershipDB, sm)
	})

	T.Run("with error renewing token in session manager", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, helper.exampleLoginInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		userDataManager := &mocktypes.UserDataManagerMock{}
		userDataManager.On(
			"GetUserByUsername",
			testutils.ContextMatcher,
			helper.exampleUser.Username,
		).Return(helper.exampleUser, nil)
		helper.service.userDataManager = userDataManager

		authenticator := &mockauthn.Authenticator{}
		authenticator.On(
			"CredentialsAreValid",
			testutils.ContextMatcher,
			helper.exampleUser.HashedPassword,
			helper.exampleLoginInput.Password,
			helper.exampleUser.TwoFactorSecret,
			helper.exampleLoginInput.TOTPToken,
		).Return(true, nil)
		helper.service.authenticator = authenticator

		membershipDB := &mocktypes.AccountUserMembershipDataManagerMock{}
		membershipDB.On(
			"GetDefaultAccountIDForUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleAccount.ID, nil)
		helper.service.accountMembershipManager = membershipDB

		sm := &mockSessionManager{}
		sm.On("Load", testutils.ContextMatcher, "").Return(helper.ctx, nil)
		sm.On("RenewToken", testutils.ContextMatcher).Return(errors.New("blah"))
		helper.service.sessionManager = sm

		helper.service.BuildLoginHandler(false)(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		assert.Empty(t, helper.res.Header().Get("Set-Cookie"))

		mock.AssertExpectationsForObjects(t, userDataManager, authenticator, membershipDB, sm)
	})

	T.Run("with error committing to session manager", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, helper.exampleLoginInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		userDataManager := &mocktypes.UserDataManagerMock{}
		userDataManager.On(
			"GetUserByUsername",
			testutils.ContextMatcher,
			helper.exampleUser.Username,
		).Return(helper.exampleUser, nil)
		helper.service.userDataManager = userDataManager

		authenticator := &mockauthn.Authenticator{}
		authenticator.On(
			"CredentialsAreValid",
			testutils.ContextMatcher,
			helper.exampleUser.HashedPassword,
			helper.exampleLoginInput.Password,
			helper.exampleUser.TwoFactorSecret,
			helper.exampleLoginInput.TOTPToken,
		).Return(true, nil)
		helper.service.authenticator = authenticator

		membershipDB := &mocktypes.AccountUserMembershipDataManagerMock{}
		membershipDB.On(
			"GetDefaultAccountIDForUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleAccount.ID, nil)
		helper.service.accountMembershipManager = membershipDB

		sm := &mockSessionManager{}
		sm.On("Load", testutils.ContextMatcher, "").Return(helper.ctx, nil)
		sm.On("RenewToken", testutils.ContextMatcher).Return(nil)
		sm.On("Put", testutils.ContextMatcher, userIDContextKey, helper.exampleUser.ID)
		sm.On("Put", testutils.ContextMatcher, accountIDContextKey, helper.exampleAccount.ID)
		sm.On("Commit", testutils.ContextMatcher).Return("", time.Now(), errors.New("blah"))
		helper.service.sessionManager = sm

		helper.service.BuildLoginHandler(false)(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		assert.Empty(t, helper.res.Header().Get("Set-Cookie"))

		mock.AssertExpectationsForObjects(t, userDataManager, authenticator, membershipDB, sm)
	})

	T.Run("with error building cookie", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, helper.exampleLoginInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		cb := &mockCookieEncoderDecoder{}
		cb.On(
			"Encode",

			helper.service.config.Cookies.Name,
			mock.IsType("string"),
		).Return("", errors.New("blah"))
		helper.service.cookieManager = cb

		userDataManager := &mocktypes.UserDataManagerMock{}
		userDataManager.On(
			"GetUserByUsername",
			testutils.ContextMatcher,
			helper.exampleUser.Username,
		).Return(helper.exampleUser, nil)
		helper.service.userDataManager = userDataManager

		authenticator := &mockauthn.Authenticator{}
		authenticator.On(
			"CredentialsAreValid",
			testutils.ContextMatcher,
			helper.exampleUser.HashedPassword,
			helper.exampleLoginInput.Password,
			helper.exampleUser.TwoFactorSecret,
			helper.exampleLoginInput.TOTPToken,
		).Return(true, nil)
		helper.service.authenticator = authenticator

		membershipDB := &mocktypes.AccountUserMembershipDataManagerMock{}
		membershipDB.On(
			"GetDefaultAccountIDForUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleAccount.ID, nil)
		helper.service.accountMembershipManager = membershipDB

		helper.service.BuildLoginHandler(false)(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		assert.Empty(t, helper.res.Header().Get("Set-Cookie"))

		mock.AssertExpectationsForObjects(t, cb, userDataManager, authenticator, membershipDB)
	})

	T.Run("with error building cookie and error encoding cookie response", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, helper.exampleLoginInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		cb := &mockCookieEncoderDecoder{}
		cb.On(
			"Encode",
			helper.service.config.Cookies.Name,
			mock.IsType("string"),
		).Return("", errors.New("blah"))
		helper.service.cookieManager = cb

		userDataManager := &mocktypes.UserDataManagerMock{}
		userDataManager.On(
			"GetUserByUsername",
			testutils.ContextMatcher,
			helper.exampleUser.Username,
		).Return(helper.exampleUser, nil)
		helper.service.userDataManager = userDataManager

		authenticator := &mockauthn.Authenticator{}
		authenticator.On(
			"CredentialsAreValid",
			testutils.ContextMatcher,
			helper.exampleUser.HashedPassword,
			helper.exampleLoginInput.Password,
			helper.exampleUser.TwoFactorSecret,
			helper.exampleLoginInput.TOTPToken,
		).Return(true, nil)
		helper.service.authenticator = authenticator

		membershipDB := &mocktypes.AccountUserMembershipDataManagerMock{}
		membershipDB.On(
			"GetDefaultAccountIDForUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleAccount.ID, nil)
		helper.service.accountMembershipManager = membershipDB

		helper.service.BuildLoginHandler(false)(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		assert.Empty(t, helper.res.Header().Get("Set-Cookie"))

		mock.AssertExpectationsForObjects(t, cb, userDataManager, authenticator, membershipDB)
	})

	T.Run("with error publishing service event", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, helper.exampleLoginInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		userDataManager := &mocktypes.UserDataManagerMock{}
		userDataManager.On(
			"GetUserByUsername",
			testutils.ContextMatcher,
			helper.exampleUser.Username,
		).Return(helper.exampleUser, nil)
		helper.service.userDataManager = userDataManager

		authenticator := &mockauthn.Authenticator{}
		authenticator.On(
			"CredentialsAreValid",
			testutils.ContextMatcher,
			helper.exampleUser.HashedPassword,
			helper.exampleLoginInput.Password,
			helper.exampleUser.TwoFactorSecret,
			helper.exampleLoginInput.TOTPToken,
		).Return(true, nil)
		helper.service.authenticator = authenticator

		membershipDB := &mocktypes.AccountUserMembershipDataManagerMock{}
		membershipDB.On(
			"GetDefaultAccountIDForUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleAccount.ID, nil)
		helper.service.accountMembershipManager = membershipDB

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(errors.New("blah"))
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.BuildLoginHandler(false)(helper.res, helper.req)

		assert.Equal(t, http.StatusAccepted, helper.res.Code)
		assert.NotEmpty(t, helper.res.Header().Get("Set-Cookie"))
		var actual *types.APIResponse[*types.UserStatusResponse]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NotNil(t, actual.Data)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, userDataManager, authenticator, membershipDB, dataChangesPublisher)
	})
}

func TestAuthenticationService_ChangeActiveAccountHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeChangeActiveAccountInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		accountMembershipManager := &mocktypes.AccountUserMembershipDataManagerMock{}
		accountMembershipManager.On(
			"UserIsMemberOfAccount",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			exampleInput.AccountID,
		).Return(true, nil)
		helper.service.accountMembershipManager = accountMembershipManager

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(nil)
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.ChangeActiveAccountHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusAccepted, helper.res.Code)
		assert.NotEmpty(t, helper.res.Header().Get("Set-Cookie"))

		mock.AssertExpectationsForObjects(t, accountMembershipManager, dataChangesPublisher)
	})

	T.Run("with error fetching session context data", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.sessionContextDataFetcher = testutils.BrokenSessionContextDataFetcher

		helper.service.ChangeActiveAccountHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)
		assert.Empty(t, helper.res.Header().Get("Set-Cookie"))
	})

	T.Run("with missing input", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(nil))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.service.ChangeActiveAccountHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		assert.Empty(t, helper.res.Header().Get("Set-Cookie"))
	})

	T.Run("with invalid input", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := &types.ChangeActiveAccountInput{}
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.service.ChangeActiveAccountHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		assert.Empty(t, helper.res.Header().Get("Set-Cookie"))
	})

	T.Run("with error checking user account membership", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeChangeActiveAccountInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		accountMembershipManager := &mocktypes.AccountUserMembershipDataManagerMock{}
		accountMembershipManager.On(
			"UserIsMemberOfAccount",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			exampleInput.AccountID,
		).Return(false, errors.New("blah"))
		helper.service.accountMembershipManager = accountMembershipManager

		helper.service.ChangeActiveAccountHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		assert.Empty(t, helper.res.Header().Get("Set-Cookie"))

		mock.AssertExpectationsForObjects(t, accountMembershipManager)
	})

	T.Run("without account authorization", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeChangeActiveAccountInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		accountMembershipManager := &mocktypes.AccountUserMembershipDataManagerMock{}
		accountMembershipManager.On(
			"UserIsMemberOfAccount",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			exampleInput.AccountID,
		).Return(false, nil)
		helper.service.accountMembershipManager = accountMembershipManager

		helper.service.ChangeActiveAccountHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)
		assert.Empty(t, helper.res.Header().Get("Set-Cookie"))

		mock.AssertExpectationsForObjects(t, accountMembershipManager)
	})

	T.Run("with error loading from session manager", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeChangeActiveAccountInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		accountMembershipManager := &mocktypes.AccountUserMembershipDataManagerMock{}
		accountMembershipManager.On(
			"UserIsMemberOfAccount",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			exampleInput.AccountID,
		).Return(true, nil)
		helper.service.accountMembershipManager = accountMembershipManager

		sm := &mockSessionManager{}
		sm.On("Load", testutils.ContextMatcher, "").Return(helper.ctx, errors.New("blah"))
		helper.service.sessionManager = sm

		helper.service.ChangeActiveAccountHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		assert.Empty(t, helper.res.Header().Get("Set-Cookie"))

		mock.AssertExpectationsForObjects(t, accountMembershipManager, sm)
	})

	T.Run("with error renewing token in session manager", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeChangeActiveAccountInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		accountMembershipManager := &mocktypes.AccountUserMembershipDataManagerMock{}
		accountMembershipManager.On(
			"UserIsMemberOfAccount",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			exampleInput.AccountID,
		).Return(true, nil)
		helper.service.accountMembershipManager = accountMembershipManager

		sm := &mockSessionManager{}
		sm.On("Load", testutils.ContextMatcher, "").Return(helper.ctx, nil)
		sm.On("RenewToken", testutils.ContextMatcher).Return(errors.New("blah"))
		helper.service.sessionManager = sm

		helper.service.ChangeActiveAccountHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		assert.Empty(t, helper.res.Header().Get("Set-Cookie"))

		mock.AssertExpectationsForObjects(t, accountMembershipManager, sm)
	})

	T.Run("with error committing to session manager", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeChangeActiveAccountInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		accountMembershipManager := &mocktypes.AccountUserMembershipDataManagerMock{}
		accountMembershipManager.On(
			"UserIsMemberOfAccount",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			exampleInput.AccountID,
		).Return(true, nil)
		helper.service.accountMembershipManager = accountMembershipManager

		sm := &mockSessionManager{}
		sm.On("Load", testutils.ContextMatcher, "").Return(helper.ctx, nil)
		sm.On("RenewToken", testutils.ContextMatcher).Return(nil)
		sm.On("Put", testutils.ContextMatcher, userIDContextKey, helper.exampleUser.ID)
		sm.On("Put", testutils.ContextMatcher, accountIDContextKey, exampleInput.AccountID)
		sm.On("Commit", testutils.ContextMatcher).Return("", time.Now(), errors.New("blah"))
		helper.service.sessionManager = sm

		helper.service.ChangeActiveAccountHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		assert.Empty(t, helper.res.Header().Get("Set-Cookie"))

		mock.AssertExpectationsForObjects(t, accountMembershipManager, sm)
	})

	T.Run("with error renewing token in session manager", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeChangeActiveAccountInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		accountMembershipManager := &mocktypes.AccountUserMembershipDataManagerMock{}
		accountMembershipManager.On(
			"UserIsMemberOfAccount",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			exampleInput.AccountID,
		).Return(true, nil)
		helper.service.accountMembershipManager = accountMembershipManager

		sm := &mockSessionManager{}
		sm.On("Load", testutils.ContextMatcher, "").Return(helper.ctx, nil)
		sm.On("RenewToken", testutils.ContextMatcher).Return(errors.New("blah"))
		helper.service.sessionManager = sm

		helper.service.ChangeActiveAccountHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		assert.Empty(t, helper.res.Header().Get("Set-Cookie"))

		mock.AssertExpectationsForObjects(t, accountMembershipManager, sm)
	})

	T.Run("with error building cookie", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeChangeActiveAccountInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		accountMembershipManager := &mocktypes.AccountUserMembershipDataManagerMock{}
		accountMembershipManager.On(
			"UserIsMemberOfAccount",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			exampleInput.AccountID,
		).Return(true, nil)
		helper.service.accountMembershipManager = accountMembershipManager

		cookieManager := &mockCookieEncoderDecoder{}
		cookieManager.On(
			"Encode",
			helper.service.config.Cookies.Name,
			mock.IsType("string"),
		).Return("", errors.New("blah"))
		helper.service.cookieManager = cookieManager

		helper.service.ChangeActiveAccountHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		assert.Empty(t, helper.res.Header().Get("Set-Cookie"))

		mock.AssertExpectationsForObjects(t, accountMembershipManager)
	})

	T.Run("with error publishing service event", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeChangeActiveAccountInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		accountMembershipManager := &mocktypes.AccountUserMembershipDataManagerMock{}
		accountMembershipManager.On(
			"UserIsMemberOfAccount",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			exampleInput.AccountID,
		).Return(true, nil)
		helper.service.accountMembershipManager = accountMembershipManager

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(errors.New("blah"))
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.ChangeActiveAccountHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusAccepted, helper.res.Code)
		assert.NotEmpty(t, helper.res.Header().Get("Set-Cookie"))

		mock.AssertExpectationsForObjects(t, accountMembershipManager, dataChangesPublisher)
	})
}

func TestAuthenticationService_EndSessionHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.ctx, helper.req, _ = attachCookieToRequestForTest(t, helper.service, helper.req, helper.exampleUser)

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(nil)
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.EndSessionHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusAccepted, helper.res.Code)
		var actual *types.APIResponse[*types.UserStatusResponse]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NoError(t, actual.Error.AsError())
		actualCookie := helper.res.Header().Get("Set-Cookie")
		assert.Contains(t, actualCookie, "Max-Age=0")

		mock.AssertExpectationsForObjects(t, dataChangesPublisher)
	})

	T.Run("with error retrieving session context data", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.sessionContextDataFetcher = testutils.BrokenSessionContextDataFetcher

		helper.service.EndSessionHandler(helper.res, helper.req)

		assert.Empty(t, helper.res.Header().Get("Set-Cookie"))
		var actual *types.APIResponse[*types.UserStatusResponse]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Error(t, actual.Error.AsError())
	})

	T.Run("with error loading from session manager", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		helper.ctx, helper.req, _ = attachCookieToRequestForTest(t, helper.service, helper.req, helper.exampleUser)

		sm := &mockSessionManager{}
		sm.On("Load", testutils.ContextMatcher, "").Return(context.Background(), errors.New("blah"))
		helper.service.sessionManager = sm

		helper.service.EndSessionHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.UserStatusResponse]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Error(t, actual.Error.AsError())
		actualCookie := helper.res.Header().Get("Set-Cookie")
		assert.Empty(t, actualCookie)

		mock.AssertExpectationsForObjects(t, sm)
	})

	T.Run("with error deleting from session store", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		sm := &mockSessionManager{}
		sm.On("Load", testutils.ContextMatcher, "").Return(helper.ctx, nil)
		sm.On("Destroy", testutils.ContextMatcher).Return(errors.New("blah"))
		helper.service.sessionManager = sm

		helper.service.EndSessionHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.UserStatusResponse]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Error(t, actual.Error.AsError())
		actualCookie := helper.res.Header().Get("Set-Cookie")
		assert.Empty(t, actualCookie)

		mock.AssertExpectationsForObjects(t, sm)
	})

	T.Run("with error building cookie", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		helper.ctx, helper.req, _ = attachCookieToRequestForTest(t, helper.service, helper.req, helper.exampleUser)
		helper.service.cookieManager = securecookie.New(
			securecookie.GenerateRandomKey(0),
			[]byte(""),
		)

		helper.service.EndSessionHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.UserStatusResponse]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Error(t, actual.Error.AsError())
	})

	T.Run("with error publishing service event", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.ctx, helper.req, _ = attachCookieToRequestForTest(t, helper.service, helper.req, helper.exampleUser)

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(errors.New("blah"))
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.EndSessionHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusAccepted, helper.res.Code)
		var actual *types.APIResponse[*types.UserStatusResponse]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NoError(t, actual.Error.AsError())
		actualCookie := helper.res.Header().Get("Set-Cookie")
		assert.Contains(t, actualCookie, "Max-Age=0")

		mock.AssertExpectationsForObjects(t, dataChangesPublisher)
	})
}

func TestAuthenticationService_StatusHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		helper.service.StatusHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusOK, helper.res.Code)
		var actual *types.APIResponse[*types.UserStatusResponse]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NotEmpty(t, actual.Data)
		assert.NoError(t, actual.Error.AsError())
	})

	T.Run("with problem fetching session context data", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.sessionContextDataFetcher = testutils.BrokenSessionContextDataFetcher

		helper.service.StatusHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)
		var actual *types.APIResponse[*types.Webhook]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})
}

func TestAuthenticationService_CycleSecretHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		helper.exampleUser.ServiceRole = authorization.ServiceAdminRole.String()
		helper.setContextFetcher(t)

		helper.ctx, helper.req, _ = attachCookieToRequestForTest(t, helper.service, helper.req, helper.exampleUser)
		c := helper.req.Cookies()[0]

		var token string
		assert.NoError(t, helper.service.cookieManager.Decode(helper.service.config.Cookies.Name, c.Value, &token))

		helper.service.CycleCookieSecretHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusAccepted, helper.res.Code, "expected code to be %d, but was %d", http.StatusUnauthorized, helper.res.Code)
		assert.Error(t, helper.service.cookieManager.Decode(helper.service.config.Cookies.Name, c.Value, &token))
	})

	T.Run("with error getting session context data", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)
		helper.service.sessionContextDataFetcher = testutils.BrokenSessionContextDataFetcher

		helper.ctx, helper.req, _ = attachCookieToRequestForTest(t, helper.service, helper.req, helper.exampleUser)
		c := helper.req.Cookies()[0]

		var token string
		assert.NoError(t, helper.service.cookieManager.Decode(helper.service.config.Cookies.Name, c.Value, &token))

		helper.service.CycleCookieSecretHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code, "expected code to be %d, but was %d", http.StatusUnauthorized, helper.res.Code)
		assert.NoError(t, helper.service.cookieManager.Decode(helper.service.config.Cookies.Name, c.Value, &token))
	})

	T.Run("with invalid permissions", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper(t)

		helper.ctx, helper.req, _ = attachCookieToRequestForTest(t, helper.service, helper.req, helper.exampleUser)
		c := helper.req.Cookies()[0]

		var token string
		assert.NoError(t, helper.service.cookieManager.Decode(helper.service.config.Cookies.Name, c.Value, &token))

		helper.service.CycleCookieSecretHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusForbidden, helper.res.Code, "expected code to be %d, but was %d", http.StatusUnauthorized, helper.res.Code)
		assert.NoError(t, helper.service.cookieManager.Decode(helper.service.config.Cookies.Name, c.Value, &token))
	})
}

//nolint:paralleltest // pending race condition fix
func Test_service_SSOProviderHandler(T *testing.T) {
	// T.Parallel()

	T.Run("standard", func(t *testing.T) {
		// t.Parallel()

		helper := buildTestHelper(t)
		helper.service.authProviderFetcher = func(*http.Request) string {
			return "google"
		}

		helper.service.SSOLoginHandler(helper.res, helper.req)

		assert.NotEmpty(t, helper.res.Header().Get("Location"))
		assert.Equal(t, http.StatusTemporaryRedirect, helper.res.Code)
	})

	T.Run("with invalid provider", func(t *testing.T) {
		// t.Parallel()

		helper := buildTestHelper(t)
		helper.service.authProviderFetcher = func(*http.Request) string {
			return "NOT REAL LOL"
		}

		helper.service.SSOLoginHandler(helper.res, helper.req)

		assert.Empty(t, helper.res.Header().Get("Location"))
		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
	})
}
