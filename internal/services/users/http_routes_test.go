package users

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"testing"

	mockauthn "github.com/verygoodsoftwarenotvirus/starter/internal/authentication/mock"
	"github.com/verygoodsoftwarenotvirus/starter/internal/database"
	"github.com/verygoodsoftwarenotvirus/starter/internal/encoding"
	mockpublishers "github.com/verygoodsoftwarenotvirus/starter/internal/messagequeue/mock"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	randommock "github.com/verygoodsoftwarenotvirus/starter/internal/pkg/random/mock"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/converters"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"
	testutils "github.com/verygoodsoftwarenotvirus/starter/tests/utils"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestService_validateCredentialChangeRequest(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)

		exampleTOTPToken := "123456"
		examplePassword := "password"

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)
		helper.service.userDataManager = mockDB

		auth := &mockauthn.Authenticator{}
		auth.On(
			"CredentialsAreValid",
			testutils.ContextMatcher,
			helper.exampleUser.HashedPassword,
			examplePassword,
			helper.exampleUser.TwoFactorSecret,
			exampleTOTPToken,
		).Return(true, nil)
		helper.service.authenticator = auth

		actual, sc := helper.service.validateCredentialsForUpdateRequest(
			helper.ctx,
			helper.exampleUser.ID,
			examplePassword,
			exampleTOTPToken,
		)

		assert.Equal(t, helper.exampleUser, actual)
		assert.Equal(t, http.StatusOK, sc)

		mock.AssertExpectationsForObjects(t, mockDB, auth)
	})

	T.Run("with no rows found in database", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)

		exampleTOTPToken := "123456"
		examplePassword := "password"

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return((*types.User)(nil), sql.ErrNoRows)
		helper.service.userDataManager = mockDB

		actual, sc := helper.service.validateCredentialsForUpdateRequest(
			helper.ctx,
			helper.exampleUser.ID,
			examplePassword,
			exampleTOTPToken,
		)

		assert.Nil(t, actual)
		assert.Equal(t, http.StatusNotFound, sc)

		mock.AssertExpectationsForObjects(t, mockDB)
	})

	T.Run("with error fetching from database", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)

		exampleTOTPToken := "123456"
		examplePassword := "password"

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return((*types.User)(nil), errors.New("blah"))
		helper.service.userDataManager = mockDB

		actual, sc := helper.service.validateCredentialsForUpdateRequest(
			helper.ctx,
			helper.exampleUser.ID,
			examplePassword,
			exampleTOTPToken,
		)

		assert.Nil(t, actual)
		assert.Equal(t, http.StatusInternalServerError, sc)

		mock.AssertExpectationsForObjects(t, mockDB)
	})

	T.Run("with error validating login", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)

		exampleTOTPToken := "123456"
		examplePassword := "password"

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)
		helper.service.userDataManager = mockDB

		auth := &mockauthn.Authenticator{}
		auth.On(
			"CredentialsAreValid",
			testutils.ContextMatcher,
			helper.exampleUser.HashedPassword,
			examplePassword,
			helper.exampleUser.TwoFactorSecret,
			exampleTOTPToken,
		).Return(false, errors.New("blah"))
		helper.service.authenticator = auth

		actual, sc := helper.service.validateCredentialsForUpdateRequest(
			helper.ctx,
			helper.exampleUser.ID,
			examplePassword,
			exampleTOTPToken,
		)

		assert.Nil(t, actual)
		assert.Equal(t, http.StatusBadRequest, sc)

		mock.AssertExpectationsForObjects(t, mockDB, auth)
	})

	T.Run("with invalid login", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)

		exampleTOTPToken := "123456"
		examplePassword := "password"

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)
		helper.service.userDataManager = mockDB

		auth := &mockauthn.Authenticator{}
		auth.On(
			"CredentialsAreValid",
			testutils.ContextMatcher,
			helper.exampleUser.HashedPassword,
			examplePassword,
			helper.exampleUser.TwoFactorSecret,
			exampleTOTPToken,
		).Return(false, nil)
		helper.service.authenticator = auth

		actual, sc := helper.service.validateCredentialsForUpdateRequest(
			helper.ctx,
			helper.exampleUser.ID,
			examplePassword,
			exampleTOTPToken,
		)

		assert.Nil(t, actual)
		assert.Equal(t, http.StatusUnauthorized, sc)

		mock.AssertExpectationsForObjects(t, mockDB, auth)
	})
}

func TestService_UsernameSearchHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)

		exampleUserList := fakes.BuildFakeUserList()

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"SearchForUsersByUsername",
			testutils.ContextMatcher,
			helper.exampleUser.Username,
		).Return(exampleUserList.Data, nil)
		helper.service.userDataManager = mockDB

		v := helper.req.URL.Query()
		v.Set(types.SearchQueryKey, helper.exampleUser.Username)
		helper.req.URL.RawQuery = v.Encode()

		helper.service.UsernameSearchHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusOK, helper.res.Code)
		var actual *types.APIResponse[[]*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		for i := range exampleUserList.Data {
			exampleUserList.Data[i].TwoFactorSecret = ""
		}
		assert.Equal(t, actual.Data, exampleUserList.Data)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, mockDB)
	})

	T.Run("with error reading from database", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"SearchForUsersByUsername",
			testutils.ContextMatcher,
			helper.exampleUser.Username,
		).Return([]*types.User{}, errors.New("blah"))
		helper.service.userDataManager = mockDB

		v := helper.req.URL.Query()
		v.Set(types.SearchQueryKey, helper.exampleUser.Username)
		helper.req.URL.RawQuery = v.Encode()

		helper.service.UsernameSearchHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockDB)
	})
}

func TestService_ListHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)

		exampleUserList := fakes.BuildFakeUserList()

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUsers",
			testutils.ContextMatcher,
			mock.IsType(&types.QueryFilter{}),
		).Return(exampleUserList, nil)
		helper.service.userDataManager = mockDB

		helper.service.ListHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusOK, helper.res.Code)
		var actual *types.APIResponse[[]*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		for i := range exampleUserList.Data {
			exampleUserList.Data[i].TwoFactorSecret = ""
		}
		assert.Equal(t, actual.Data, exampleUserList.Data)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, mockDB)
	})

	T.Run("with error reading from database", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUsers",
			testutils.ContextMatcher,
			mock.IsType(&types.QueryFilter{}),
		).Return((*types.QueryFilteredResult[types.User])(nil), errors.New("blah"))
		helper.service.userDataManager = mockDB

		helper.service.ListHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockDB)
	})
}

func TestService_CreateHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeUserRegistrationInputFromUser(helper.exampleUser)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		exampleAccount := fakes.BuildFakeAccount()
		exampleAccount.BelongsToUser = helper.exampleUser.ID

		auth := &mockauthn.Authenticator{}
		auth.On(
			"HashPassword",
			testutils.ContextMatcher,
			exampleInput.Password,
		).Return(helper.exampleUser.HashedPassword, nil)
		helper.service.authenticator = auth

		db := database.NewMockDatabase()
		db.UserDataManagerMock.On(
			"CreateUser",
			testutils.ContextMatcher,
			mock.IsType(&types.UserDatabaseCreationInput{}),
		).Return(helper.exampleUser, nil)

		db.UserDataManagerMock.On(
			"GetEmailAddressVerificationTokenForUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(t.Name(), nil)
		helper.service.userDataManager = db

		db.AccountUserMembershipDataManagerMock.On(
			"GetDefaultAccountIDForUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleAccount.ID, nil)
		helper.service.accountUserMembershipDataManager = db

		helper.req = helper.req.WithContext(
			context.WithValue(
				helper.req.Context(),
				types.UserRegistrationInputContextKey,
				exampleInput,
			),
		)

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(nil)
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.authSettings.EnableUserSignup = true
		helper.service.CreateHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusCreated, helper.res.Code)
		var actual *types.APIResponse[*types.UserCreationResponse]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NotNil(t, actual.Data)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, auth, db, dataChangesPublisher)
	})

	T.Run("with user creation disabled", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeUserRegistrationInputFromUser(helper.exampleUser)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.service.authSettings.EnableUserSignup = false
		helper.service.CreateHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusForbidden, helper.res.Code)
	})

	T.Run("with missing input", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(nil))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.service.authSettings.EnableUserSignup = true
		helper.service.CreateHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with invalid input", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := &types.UserRegistrationInput{}
		exampleInput.Password = "a"
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		exampleAccount := fakes.BuildFakeAccount()
		exampleAccount.BelongsToUser = helper.exampleUser.ID

		helper.service.authSettings.EnableUserSignup = true
		helper.service.CreateHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with error validating password", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeUserRegistrationInputFromUser(helper.exampleUser)
		exampleInput.Password = "a"
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		exampleAccount := fakes.BuildFakeAccount()
		exampleAccount.BelongsToUser = helper.exampleUser.ID

		helper.req = helper.req.WithContext(
			context.WithValue(
				helper.req.Context(),
				types.UserRegistrationInputContextKey,
				exampleInput,
			),
		)

		helper.service.authSettings.EnableUserSignup = true
		helper.service.CreateHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with invitation", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeUserRegistrationInputWithInviteFromUser(helper.exampleUser)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		exampleAccount := fakes.BuildFakeAccount()
		exampleAccount.BelongsToUser = helper.exampleUser.ID
		exampleAccountInvitation := fakes.BuildFakeAccountInvitation()
		exampleAccountInvitation.ID = exampleInput.InvitationID
		exampleAccountInvitation.Token = exampleInput.InvitationToken
		exampleAccountInvitation.DestinationAccount = *exampleAccount

		auth := &mockauthn.Authenticator{}
		auth.On(
			"HashPassword",
			testutils.ContextMatcher,
			exampleInput.Password,
		).Return(helper.exampleUser.HashedPassword, nil)
		helper.service.authenticator = auth

		db := database.NewMockDatabase()
		db.UserDataManagerMock.On(
			"CreateUser",
			testutils.ContextMatcher,
			mock.IsType(&types.UserDatabaseCreationInput{}),
		).Return(helper.exampleUser, nil)

		db.UserDataManagerMock.On(
			"GetEmailAddressVerificationTokenForUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(t.Name(), nil)

		db.AccountInvitationDataManagerMock.On(
			"GetAccountInvitationByTokenAndID",
			testutils.ContextMatcher,
			exampleInput.InvitationToken,
			exampleInput.InvitationID,
		).Return(exampleAccountInvitation, nil)
		helper.service.userDataManager = db
		helper.service.accountInvitationDataManager = db

		db.AccountUserMembershipDataManagerMock.On(
			"GetDefaultAccountIDForUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleAccount.ID, nil)
		helper.service.accountUserMembershipDataManager = db

		helper.req = helper.req.WithContext(
			context.WithValue(
				helper.req.Context(),
				types.UserRegistrationInputContextKey,
				exampleInput,
			),
		)

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(nil)
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.authSettings.EnableUserSignup = true
		helper.service.CreateHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusCreated, helper.res.Code)
		var actual *types.APIResponse[*types.UserCreationResponse]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NotNil(t, actual.Data)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, auth, db, dataChangesPublisher)
	})

	T.Run("with invitation and no invite found", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeUserRegistrationInputWithInviteFromUser(helper.exampleUser)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		exampleAccount := fakes.BuildFakeAccount()
		exampleAccount.BelongsToUser = helper.exampleUser.ID
		exampleAccountInvitation := fakes.BuildFakeAccountInvitation()
		exampleAccountInvitation.ID = exampleInput.InvitationID
		exampleAccountInvitation.Token = exampleInput.InvitationToken
		exampleAccountInvitation.DestinationAccount = *exampleAccount

		db := database.NewMockDatabase()
		db.UserDataManagerMock.On(
			"CreateUser",
			testutils.ContextMatcher,
			mock.IsType(&types.UserDatabaseCreationInput{}),
		).Return(helper.exampleUser, nil)

		db.UserDataManagerMock.On(
			"GetEmailAddressVerificationTokenForUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(t.Name(), nil)
		helper.service.userDataManager = db

		db.AccountInvitationDataManagerMock.On(
			"GetAccountInvitationByTokenAndID",
			testutils.ContextMatcher,
			exampleInput.InvitationToken,
			exampleInput.InvitationID,
		).Return((*types.AccountInvitation)(nil), sql.ErrNoRows)
		helper.service.userDataManager = db
		helper.service.accountInvitationDataManager = db

		helper.req = helper.req.WithContext(
			context.WithValue(
				helper.req.Context(),
				types.UserRegistrationInputContextKey,
				exampleInput,
			),
		)

		helper.service.authSettings.EnableUserSignup = true
		helper.service.CreateHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusNotFound, helper.res.Code)
		var actual *types.APIResponse[*types.UserCreationResponse]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, db)
	})

	T.Run("with invitation and error fetching invite from database", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeUserRegistrationInputWithInviteFromUser(helper.exampleUser)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		exampleAccount := fakes.BuildFakeAccount()
		exampleAccount.BelongsToUser = helper.exampleUser.ID
		exampleAccountInvitation := fakes.BuildFakeAccountInvitation()
		exampleAccountInvitation.ID = exampleInput.InvitationID
		exampleAccountInvitation.Token = exampleInput.InvitationToken
		exampleAccountInvitation.DestinationAccount = *exampleAccount

		db := database.NewMockDatabase()
		db.UserDataManagerMock.On(
			"CreateUser",
			testutils.ContextMatcher,
			mock.IsType(&types.UserDatabaseCreationInput{}),
		).Return(helper.exampleUser, nil)

		db.UserDataManagerMock.On(
			"GetEmailAddressVerificationTokenForUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(t.Name(), nil)

		db.AccountInvitationDataManagerMock.On(
			"GetAccountInvitationByTokenAndID",
			testutils.ContextMatcher,
			exampleInput.InvitationToken,
			exampleInput.InvitationID,
		).Return((*types.AccountInvitation)(nil), errors.New("blah"))
		helper.service.userDataManager = db
		helper.service.accountInvitationDataManager = db

		helper.req = helper.req.WithContext(
			context.WithValue(
				helper.req.Context(),
				types.UserRegistrationInputContextKey,
				exampleInput,
			),
		)

		helper.service.authSettings.EnableUserSignup = true
		helper.service.CreateHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.UserCreationResponse]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, db)
	})

	T.Run("with error hashing password", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeUserRegistrationInputFromUser(helper.exampleUser)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		auth := &mockauthn.Authenticator{}
		auth.On(
			"HashPassword",
			testutils.ContextMatcher,
			exampleInput.Password,
		).Return(helper.exampleUser.HashedPassword, errors.New("blah"))
		helper.service.authenticator = auth

		helper.req = helper.req.WithContext(
			context.WithValue(
				helper.req.Context(),
				types.UserRegistrationInputContextKey,
				exampleInput,
			),
		)

		helper.service.authSettings.EnableUserSignup = true
		helper.service.CreateHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.UserCreationResponse]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, auth)
	})

	T.Run("with error generating two factor secret", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeUserRegistrationInputFromUser(helper.exampleUser)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		auth := &mockauthn.Authenticator{}
		auth.On(
			"HashPassword",
			testutils.ContextMatcher,
			exampleInput.Password,
		).Return(helper.exampleUser.HashedPassword, nil)
		helper.service.authenticator = auth

		db := database.NewMockDatabase()
		db.UserDataManagerMock.On(
			"CreateUser",
			testutils.ContextMatcher,
			mock.IsType(&types.UserDatabaseCreationInput{}),
		).Return(helper.exampleUser, nil)

		db.UserDataManagerMock.On(
			"GetEmailAddressVerificationTokenForUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(t.Name(), nil)
		helper.service.userDataManager = db

		db.AccountUserMembershipDataManagerMock.On(
			"GetDefaultAccountIDForUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleAccount.ID, nil)
		helper.service.accountUserMembershipDataManager = db

		sg := &randommock.Generator{}
		sg.On(
			"GenerateBase32EncodedString",
			testutils.ContextMatcher,
			totpSecretSize,
		).Return("", errors.New("blah"))
		helper.service.secretGenerator = sg

		helper.req = helper.req.WithContext(
			context.WithValue(
				helper.req.Context(),
				types.UserRegistrationInputContextKey,
				exampleInput,
			),
		)

		helper.service.authSettings.EnableUserSignup = true
		helper.service.CreateHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.UserCreationResponse]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, auth, db, sg)
	})

	T.Run("with error writing to database", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeUserRegistrationInputFromUser(helper.exampleUser)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		auth := &mockauthn.Authenticator{}
		auth.On(
			"HashPassword",
			testutils.ContextMatcher,
			exampleInput.Password,
		).Return(helper.exampleUser.HashedPassword, nil)
		helper.service.authenticator = auth

		db := database.NewMockDatabase()
		db.UserDataManagerMock.On(
			"CreateUser",
			testutils.ContextMatcher,
			mock.IsType(&types.UserDatabaseCreationInput{}),
		).Return((*types.User)(nil), errors.New("blah"))
		helper.service.userDataManager = db

		helper.req = helper.req.WithContext(
			context.WithValue(
				helper.req.Context(),
				types.UserRegistrationInputContextKey,
				exampleInput,
			),
		)

		helper.service.authSettings.EnableUserSignup = true
		helper.service.CreateHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.UserCreationResponse]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, auth, db)
	})

	T.Run("with already existent user", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeUserRegistrationInputFromUser(helper.exampleUser)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		auth := &mockauthn.Authenticator{}
		auth.On(
			"HashPassword",
			testutils.ContextMatcher,
			exampleInput.Password,
		).Return(helper.exampleUser.HashedPassword, nil)
		helper.service.authenticator = auth

		db := database.NewMockDatabase()
		db.UserDataManagerMock.On(
			"CreateUser",
			testutils.ContextMatcher,
			mock.IsType(&types.UserDatabaseCreationInput{}),
		).Return((*types.User)(nil), database.ErrUserAlreadyExists)
		helper.service.userDataManager = db

		helper.req = helper.req.WithContext(
			context.WithValue(
				helper.req.Context(),
				types.UserRegistrationInputContextKey,
				exampleInput,
			),
		)

		helper.service.authSettings.EnableUserSignup = true
		helper.service.CreateHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		var actual *types.APIResponse[*types.UserCreationResponse]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, auth, db)
	})

	T.Run("with error publishing data change event", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeUserRegistrationInputFromUser(helper.exampleUser)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		exampleAccount := fakes.BuildFakeAccount()
		exampleAccount.BelongsToUser = helper.exampleUser.ID

		auth := &mockauthn.Authenticator{}
		auth.On(
			"HashPassword",
			testutils.ContextMatcher,
			exampleInput.Password,
		).Return(helper.exampleUser.HashedPassword, nil)
		helper.service.authenticator = auth

		db := database.NewMockDatabase()
		db.UserDataManagerMock.On(
			"CreateUser",
			testutils.ContextMatcher,
			mock.IsType(&types.UserDatabaseCreationInput{}),
		).Return(helper.exampleUser, nil)

		db.UserDataManagerMock.On(
			"GetEmailAddressVerificationTokenForUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(t.Name(), nil)
		helper.service.userDataManager = db

		db.AccountUserMembershipDataManagerMock.On(
			"GetDefaultAccountIDForUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleAccount.ID, nil)
		helper.service.accountUserMembershipDataManager = db

		helper.req = helper.req.WithContext(
			context.WithValue(
				helper.req.Context(),
				types.UserRegistrationInputContextKey,
				exampleInput,
			),
		)

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(errors.New("blah"))
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.authSettings.EnableUserSignup = true
		helper.service.CreateHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusCreated, helper.res.Code)
		var actual *types.APIResponse[*types.UserCreationResponse]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NotNil(t, actual.Data)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, auth, db, dataChangesPublisher)
	})

	T.Run("with error fetching email address verification token", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeUserRegistrationInputFromUser(helper.exampleUser)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		exampleAccount := fakes.BuildFakeAccount()
		exampleAccount.BelongsToUser = helper.exampleUser.ID

		auth := &mockauthn.Authenticator{}
		auth.On(
			"HashPassword",
			testutils.ContextMatcher,
			exampleInput.Password,
		).Return(helper.exampleUser.HashedPassword, nil)
		helper.service.authenticator = auth

		db := database.NewMockDatabase()
		db.UserDataManagerMock.On(
			"CreateUser",
			testutils.ContextMatcher,
			mock.IsType(&types.UserDatabaseCreationInput{}),
		).Return(helper.exampleUser, nil)

		db.UserDataManagerMock.On(
			"GetEmailAddressVerificationTokenForUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return("", errors.New("blah"))
		helper.service.userDataManager = db

		db.AccountUserMembershipDataManagerMock.On(
			"GetDefaultAccountIDForUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleAccount.ID, nil)
		helper.service.accountUserMembershipDataManager = db

		helper.req = helper.req.WithContext(
			context.WithValue(
				helper.req.Context(),
				types.UserRegistrationInputContextKey,
				exampleInput,
			),
		)

		helper.service.authSettings.EnableUserSignup = true
		helper.service.CreateHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.UserCreationResponse]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, auth, db)
	})
}

func TestService_buildQRCode(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)

		actual := helper.service.buildQRCode(helper.ctx, helper.exampleUser.Username, helper.exampleUser.TwoFactorSecret)

		assert.NotEmpty(t, actual)
		assert.True(t, strings.HasPrefix(actual, base64ImagePrefix))
	})
}

func TestService_SelfHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)
		helper.service.userDataManager = mockDB

		helper.service.SelfHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusOK, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		helper.exampleUser.TwoFactorSecret = ""
		assert.Equal(t, actual.Data, helper.exampleUser)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, mockDB)
	})

	T.Run("with error retrieving session context data", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.sessionContextDataFetcher = testutils.BrokenSessionContextDataFetcher

		helper.service.SelfHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with no rows found", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, sql.ErrNoRows)
		helper.service.userDataManager = mockDB

		helper.service.SelfHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusNotFound, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockDB)
	})

	T.Run("with error reading from database", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, errors.New("blah"))
		helper.service.userDataManager = mockDB

		helper.service.SelfHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockDB)
	})
}

func TestService_PermissionsHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)

		exampleInput := fakes.BuildFakeUserPermissionsRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.service.PermissionsHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusOK, helper.res.Code)
		var actual *types.APIResponse[*types.UserPermissionsResponse]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NotNil(t, actual.Data)
		assert.NoError(t, actual.Error.AsError())
	})

	T.Run("with error retrieving session context data", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.sessionContextDataFetcher = testutils.BrokenSessionContextDataFetcher

		helper.service.PermissionsHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})
}

func TestService_ReadHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)
		helper.service.userDataManager = mockDB

		helper.service.ReadHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusOK, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		helper.exampleUser.TwoFactorSecret = ""
		assert.Equal(t, actual.Data, helper.exampleUser)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, mockDB)
	})

	T.Run("with no rows found", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, sql.ErrNoRows)
		helper.service.userDataManager = mockDB

		helper.service.ReadHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusNotFound, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockDB)
	})

	T.Run("with error reading from database", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, errors.New("blah"))
		helper.service.userDataManager = mockDB

		helper.service.ReadHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockDB)
	})
}

func TestService_TOTPSecretVerificationHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeTOTPSecretVerificationInputForUser(helper.exampleUser)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.exampleUser.TwoFactorSecretVerifiedAt = nil

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUserWithUnverifiedTwoFactorSecret",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)
		mockDB.UserDataManagerMock.On(
			"MarkUserTwoFactorSecretAsVerified",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(nil)
		helper.service.userDataManager = mockDB

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(nil)
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.TOTPSecretVerificationHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusAccepted, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		helper.exampleUser.TwoFactorSecret = ""
		assert.Equal(t, actual.Data, helper.exampleUser)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, mockDB, dataChangesPublisher)
	})

	T.Run("without input attached to request", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(nil))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.exampleUser.TwoFactorSecretVerifiedAt = nil

		helper.service.TOTPSecretVerificationHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("without valid input attached", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := &types.TOTPSecretVerificationInput{}
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.exampleUser.TwoFactorSecretVerifiedAt = nil

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUserWithUnverifiedTwoFactorSecret",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)
		helper.service.userDataManager = mockDB

		helper.service.TOTPSecretVerificationHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockDB)
	})

	T.Run("with error fetching user", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeTOTPSecretVerificationInputForUser(helper.exampleUser)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.exampleUser.TwoFactorSecretVerifiedAt = nil

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUserWithUnverifiedTwoFactorSecret",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return((*types.User)(nil), errors.New("blah"))
		helper.service.userDataManager = mockDB

		helper.service.TOTPSecretVerificationHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockDB)
	})

	T.Run("with invalid TOTP token", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeTOTPSecretVerificationInputForUser(helper.exampleUser)
		exampleInput.TOTPToken = "000000"
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUserWithUnverifiedTwoFactorSecret",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)
		mockDB.UserDataManagerMock.On(
			"MarkUserTwoFactorSecretAsVerified",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(nil)
		helper.service.userDataManager = mockDB

		helper.exampleUser.TwoFactorSecretVerifiedAt = nil

		helper.service.TOTPSecretVerificationHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with secret already validated", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		og := helper.exampleUser.TwoFactorSecretVerifiedAt
		helper.exampleUser.TwoFactorSecretVerifiedAt = nil
		exampleInput := fakes.BuildFakeTOTPSecretVerificationInputForUser(helper.exampleUser)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		helper.exampleUser.TwoFactorSecretVerifiedAt = og

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUserWithUnverifiedTwoFactorSecret",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)
		helper.service.userDataManager = mockDB

		helper.service.TOTPSecretVerificationHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusAlreadyReported, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Error(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, mockDB)
	})

	T.Run("with invalid code", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeTOTPSecretVerificationInputForUser(helper.exampleUser)
		exampleInput.TOTPToken = "INVALID"
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.exampleUser.TwoFactorSecretVerifiedAt = nil

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUserWithUnverifiedTwoFactorSecret",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)
		helper.service.userDataManager = mockDB

		helper.service.TOTPSecretVerificationHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockDB)
	})

	T.Run("with error verifying two factor secret", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeTOTPSecretVerificationInputForUser(helper.exampleUser)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.exampleUser.TwoFactorSecretVerifiedAt = nil

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUserWithUnverifiedTwoFactorSecret",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)
		mockDB.UserDataManagerMock.On(
			"MarkUserTwoFactorSecretAsVerified",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(errors.New("blah"))
		helper.service.userDataManager = mockDB

		helper.service.TOTPSecretVerificationHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockDB)
	})

	T.Run("with error publishing data change event", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeTOTPSecretVerificationInputForUser(helper.exampleUser)
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.exampleUser.TwoFactorSecretVerifiedAt = nil

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUserWithUnverifiedTwoFactorSecret",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)
		mockDB.UserDataManagerMock.On(
			"MarkUserTwoFactorSecretAsVerified",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(nil)
		helper.service.userDataManager = mockDB

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(errors.New("blah"))
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.TOTPSecretVerificationHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusAccepted, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		helper.exampleUser.TwoFactorSecret = ""
		assert.Equal(t, actual.Data, helper.exampleUser)
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, mockDB, dataChangesPublisher)
	})
}

func TestService_NewTOTPSecretHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeTOTPSecretRefreshInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)

		fakeSecret := fakes.BuildFakeID()
		sg := &randommock.Generator{}
		sg.On(
			"GenerateBase32EncodedString",
			testutils.ContextMatcher,
			totpSecretSize,
		).Return(fakeSecret, nil)
		helper.service.secretGenerator = sg

		mockDB.UserDataManagerMock.On(
			"MarkUserTwoFactorSecretAsUnverified",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			fakeSecret,
		).Return(nil)
		helper.service.userDataManager = mockDB

		auth := &mockauthn.Authenticator{}
		auth.On(
			"CredentialsAreValid",
			testutils.ContextMatcher,
			helper.exampleUser.HashedPassword,
			exampleInput.CurrentPassword,
			helper.exampleUser.TwoFactorSecret,
			exampleInput.TOTPToken,
		).Return(true, nil)
		helper.service.authenticator = auth

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(nil)
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.NewTOTPSecretHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusAccepted, helper.res.Code)
		var actual *types.APIResponse[*types.TOTPSecretRefreshResponse]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, mockDB, auth, sg, dataChangesPublisher)
	})

	T.Run("with invalid credentials", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeTOTPSecretRefreshInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)
		helper.service.userDataManager = mockDB

		auth := &mockauthn.Authenticator{}
		auth.On(
			"CredentialsAreValid",
			testutils.ContextMatcher,
			helper.exampleUser.HashedPassword,
			exampleInput.CurrentPassword,
			helper.exampleUser.TwoFactorSecret,
			exampleInput.TOTPToken,
		).Return(false, nil)
		helper.service.authenticator = auth

		helper.service.NewTOTPSecretHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockDB, auth)
	})

	T.Run("with error retrieving user", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeTOTPSecretRefreshInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return((*types.User)(nil), errors.New("blah"))
		helper.service.userDataManager = mockDB

		helper.service.NewTOTPSecretHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockDB)
	})

	T.Run("with error generating new secret", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeTOTPSecretRefreshInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)
		helper.service.userDataManager = mockDB

		sg := &randommock.Generator{}
		sg.On(
			"GenerateBase32EncodedString",
			testutils.ContextMatcher,
			totpSecretSize,
		).Return("", errors.New("blah"))
		helper.service.secretGenerator = sg

		auth := &mockauthn.Authenticator{}
		auth.On(
			"CredentialsAreValid",
			testutils.ContextMatcher,
			helper.exampleUser.HashedPassword,
			exampleInput.CurrentPassword,
			helper.exampleUser.TwoFactorSecret,
			exampleInput.TOTPToken,
		).Return(true, nil)
		helper.service.authenticator = auth

		helper.service.NewTOTPSecretHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockDB, auth, sg)
	})

	T.Run("with error marking two factor secret as unverified", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeTOTPSecretRefreshInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)

		fakeSecret := fakes.BuildFakeID()
		sg := &randommock.Generator{}
		sg.On(
			"GenerateBase32EncodedString",
			testutils.ContextMatcher,
			totpSecretSize,
		).Return(fakeSecret, nil)
		helper.service.secretGenerator = sg

		mockDB.UserDataManagerMock.On(
			"MarkUserTwoFactorSecretAsUnverified",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			fakeSecret,
		).Return(errors.New("blah"))
		helper.service.userDataManager = mockDB

		auth := &mockauthn.Authenticator{}
		auth.On(
			"CredentialsAreValid",
			testutils.ContextMatcher,
			helper.exampleUser.HashedPassword,
			exampleInput.CurrentPassword,
			helper.exampleUser.TwoFactorSecret,
			exampleInput.TOTPToken,
		).Return(true, nil)
		helper.service.authenticator = auth

		helper.service.NewTOTPSecretHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockDB, auth, sg)
	})

	T.Run("with error publishing data change", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeTOTPSecretRefreshInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)

		fakeSecret := fakes.BuildFakeID()
		sg := &randommock.Generator{}
		sg.On(
			"GenerateBase32EncodedString",
			testutils.ContextMatcher,
			totpSecretSize,
		).Return(fakeSecret, nil)
		helper.service.secretGenerator = sg

		mockDB.UserDataManagerMock.On(
			"MarkUserTwoFactorSecretAsUnverified",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			fakeSecret,
		).Return(nil)
		helper.service.userDataManager = mockDB

		auth := &mockauthn.Authenticator{}
		auth.On(
			"CredentialsAreValid",
			testutils.ContextMatcher,
			helper.exampleUser.HashedPassword,
			exampleInput.CurrentPassword,
			helper.exampleUser.TwoFactorSecret,
			exampleInput.TOTPToken,
		).Return(true, nil)
		helper.service.authenticator = auth

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(errors.New("blah"))
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.NewTOTPSecretHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusAccepted, helper.res.Code)
		var actual *types.APIResponse[*types.TOTPSecretRefreshResponse]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, mockDB, auth, sg, dataChangesPublisher)
	})
}

func TestService_UpdatePasswordHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakePasswordUpdateInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)

		mockDB.UserDataManagerMock.On(
			"UpdateUserPassword",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			mock.IsType("string"),
		).Return(nil)
		helper.service.userDataManager = mockDB

		auth := &mockauthn.Authenticator{}
		auth.On(
			"CredentialsAreValid",
			testutils.ContextMatcher,
			helper.exampleUser.HashedPassword,
			exampleInput.CurrentPassword,
			helper.exampleUser.TwoFactorSecret,
			exampleInput.TOTPToken,
		).Return(true, nil)
		auth.On(
			"HashPassword",
			testutils.ContextMatcher,
			exampleInput.NewPassword,
		).Return("blah", nil)
		helper.service.authenticator = auth

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(nil)
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.UpdatePasswordHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusAccepted, helper.res.Code)
		var actual *types.APIResponse[any]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, mockDB, auth, dataChangesPublisher)
	})

	T.Run("without input attached to request", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(nil))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.service.UpdatePasswordHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with invalid input attached to request", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := &types.PasswordUpdateInput{}
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.service.UpdatePasswordHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with input but without user info", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.sessionContextDataFetcher = testutils.BrokenSessionContextDataFetcher
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakePasswordUpdateInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.service.UpdatePasswordHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with error validating login", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakePasswordUpdateInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)
		mockDB.UserDataManagerMock.On(
			"UpdateUserPassword",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			mock.IsType("string"),
		).Return(nil)
		helper.service.userDataManager = mockDB

		auth := &mockauthn.Authenticator{}
		auth.On(
			"CredentialsAreValid",
			testutils.ContextMatcher,
			helper.exampleUser.HashedPassword,
			exampleInput.CurrentPassword,
			helper.exampleUser.TwoFactorSecret,
			exampleInput.TOTPToken,
		).Return(false, errors.New("blah"))
		helper.service.authenticator = auth

		helper.service.UpdatePasswordHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockDB, auth)
	})

	T.Run("with invalid password", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakePasswordUpdateInput()
		exampleInput.NewPassword = "a"
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)
		helper.service.userDataManager = mockDB

		auth := &mockauthn.Authenticator{}
		auth.On(
			"CredentialsAreValid",
			testutils.ContextMatcher,
			helper.exampleUser.HashedPassword,
			exampleInput.CurrentPassword,
			helper.exampleUser.TwoFactorSecret,
			exampleInput.TOTPToken,
		).Return(true, nil)
		helper.service.authenticator = auth

		helper.service.UpdatePasswordHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockDB, auth)
	})

	T.Run("with error hashing password", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakePasswordUpdateInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)
		mockDB.UserDataManagerMock.On(
			"UpdateUserPassword",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			mock.IsType("string"),
		).Return(nil)
		helper.service.userDataManager = mockDB

		auth := &mockauthn.Authenticator{}
		auth.On(
			"CredentialsAreValid",
			testutils.ContextMatcher,
			helper.exampleUser.HashedPassword,
			exampleInput.CurrentPassword,
			helper.exampleUser.TwoFactorSecret,
			exampleInput.TOTPToken,
		).Return(true, nil)
		auth.On(
			"HashPassword",
			testutils.ContextMatcher,
			exampleInput.NewPassword,
		).Return("blah", errors.New("blah"))
		helper.service.authenticator = auth

		helper.service.UpdatePasswordHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockDB, auth)
	})

	T.Run("with error updating user", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakePasswordUpdateInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)
		mockDB.UserDataManagerMock.On(
			"UpdateUserPassword",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			mock.IsType("string"),
		).Return(errors.New("blah"))
		helper.service.userDataManager = mockDB

		auth := &mockauthn.Authenticator{}
		auth.On(
			"CredentialsAreValid",
			testutils.ContextMatcher,
			helper.exampleUser.HashedPassword,
			exampleInput.CurrentPassword,
			helper.exampleUser.TwoFactorSecret,
			exampleInput.TOTPToken,
		).Return(true, nil)
		auth.On(
			"HashPassword",
			testutils.ContextMatcher,
			exampleInput.NewPassword,
		).Return("blah", nil)
		helper.service.authenticator = auth

		helper.service.UpdatePasswordHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockDB, auth)
	})
}

func TestService_UpdateUserEmailAddressHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeUserEmailAddressUpdateInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)

		auth := &mockauthn.Authenticator{}
		auth.On(
			"CredentialsAreValid",
			testutils.ContextMatcher,
			helper.exampleUser.HashedPassword,
			exampleInput.CurrentPassword,
			helper.exampleUser.TwoFactorSecret,
			exampleInput.TOTPToken,
		).Return(true, nil)
		helper.service.authenticator = auth

		mockDB.UserDataManagerMock.On(
			"UpdateUserEmailAddress",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			exampleInput.NewEmailAddress,
		).Return(nil)
		helper.service.userDataManager = mockDB

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(nil)
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.UpdateUserEmailAddressHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusAccepted, helper.res.Code)
		var actual *types.APIResponse[any]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, mockDB, auth, dataChangesPublisher)
	})
}

func TestService_UpdateUserUsernameHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeUsernameUpdateInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)

		auth := &mockauthn.Authenticator{}
		auth.On(
			"CredentialsAreValid",
			testutils.ContextMatcher,
			helper.exampleUser.HashedPassword,
			exampleInput.CurrentPassword,
			helper.exampleUser.TwoFactorSecret,
			exampleInput.TOTPToken,
		).Return(true, nil)
		helper.service.authenticator = auth

		mockDB.UserDataManagerMock.On(
			"UpdateUserUsername",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			exampleInput.NewUsername,
		).Return(nil)
		helper.service.userDataManager = mockDB

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(nil)
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.UpdateUserUsernameHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusAccepted, helper.res.Code)
		var actual *types.APIResponse[any]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, mockDB, auth, dataChangesPublisher)
	})
}

func TestService_UpdateUserDetailsHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeUserDetailsUpdateInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)

		auth := &mockauthn.Authenticator{}
		auth.On(
			"CredentialsAreValid",
			testutils.ContextMatcher,
			helper.exampleUser.HashedPassword,
			exampleInput.CurrentPassword,
			helper.exampleUser.TwoFactorSecret,
			exampleInput.TOTPToken,
		).Return(true, nil)
		helper.service.authenticator = auth

		mockDB.UserDataManagerMock.On(
			"UpdateUserDetails",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			converters.ConvertUserDetailsUpdateRequestInputToUserDetailsUpdateInput(exampleInput),
		).Return(nil)
		helper.service.userDataManager = mockDB

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(nil)
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.UpdateUserDetailsHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusAccepted, helper.res.Code)
		var actual *types.APIResponse[any]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, mockDB, auth, dataChangesPublisher)
	})
}

func TestService_AvatarUploadHandler(T *testing.T) {
	T.Parallel()

	// these aren't very good tests, because the major request work is handled by interfaces.

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)

		exampleInput := fakes.BuildFakeAvatarUpdateInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)

		mockDB.UserDataManagerMock.On(
			"UpdateUserAvatar",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			exampleInput.Base64EncodedData,
		).Return(nil)
		helper.service.userDataManager = mockDB

		helper.service.AvatarUploadHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusAccepted, helper.res.Code)
		var actual *types.APIResponse[any]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, mockDB)
	})

	T.Run("without session context data", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)

		exampleInput := fakes.BuildFakeAvatarUpdateInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.service.sessionContextDataFetcher = testutils.BrokenSessionContextDataFetcher

		helper.service.AvatarUploadHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusUnauthorized, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with error fetching user", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)

		exampleInput := fakes.BuildFakeAvatarUpdateInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return((*types.User)(nil), errors.New("blah"))
		helper.service.userDataManager = mockDB

		helper.service.AvatarUploadHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockDB)
	})

	T.Run("with error updating user", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)

		exampleInput := fakes.BuildFakeAvatarUpdateInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)
		mockDB.UserDataManagerMock.On(
			"UpdateUserAvatar",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			exampleInput.Base64EncodedData,
		).Return(errors.New("blah"))
		helper.service.userDataManager = mockDB

		helper.service.AvatarUploadHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockDB)
	})
}

func TestService_ArchiveHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"ArchiveUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(nil)
		helper.service.userDataManager = mockDB

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(nil)
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.ArchiveHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusOK, helper.res.Code)
		var actual *types.APIResponse[any]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, mockDB, dataChangesPublisher)
	})

	T.Run("with no results in the database", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"ArchiveUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(sql.ErrNoRows)
		helper.service.userDataManager = mockDB

		helper.service.ArchiveHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusNotFound, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockDB)
	})

	T.Run("with error updating database", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"ArchiveUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(errors.New("blah"))
		helper.service.userDataManager = mockDB

		helper.service.ArchiveHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockDB)
	})
}

func TestService_RequestUsernameReminderHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeUsernameReminderRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUserByEmail",
			testutils.ContextMatcher,
			exampleInput.EmailAddress,
		).Return(helper.exampleUser, nil)

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(nil)
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.userDataManager = mockDB
		helper.service.passwordResetTokenDataManager = mockDB

		helper.service.RequestUsernameReminderHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusAccepted, helper.res.Code)
		var actual *types.APIResponse[any]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, mockDB, dataChangesPublisher)
	})

	T.Run("with missing input", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader([]byte("")))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.service.RequestUsernameReminderHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with invalid input", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := &types.UsernameReminderRequestInput{}
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.service.RequestUsernameReminderHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with no such user in the database", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeUsernameReminderRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUserByEmail",
			testutils.ContextMatcher,
			exampleInput.EmailAddress,
		).Return((*types.User)(nil), sql.ErrNoRows)

		helper.service.userDataManager = mockDB
		helper.service.passwordResetTokenDataManager = mockDB

		helper.service.RequestUsernameReminderHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusNotFound, helper.res.Code)
		var actual *types.APIResponse[any]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Error(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, mockDB)
	})

	T.Run("with error fetching user", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeUsernameReminderRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUserByEmail",
			testutils.ContextMatcher,
			exampleInput.EmailAddress,
		).Return((*types.User)(nil), errors.New("blah"))

		helper.service.userDataManager = mockDB
		helper.service.passwordResetTokenDataManager = mockDB

		helper.service.RequestUsernameReminderHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockDB)
	})

	T.Run("with error publishing email message", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeUsernameReminderRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUserByEmail",
			testutils.ContextMatcher,
			exampleInput.EmailAddress,
		).Return(helper.exampleUser, nil)

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(nil)
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.userDataManager = mockDB
		helper.service.passwordResetTokenDataManager = mockDB

		helper.service.RequestUsernameReminderHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusAccepted, helper.res.Code)
		var actual *types.APIResponse[any]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, mockDB, dataChangesPublisher)
	})
}

func TestService_CreatePasswordResetTokenHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakePasswordResetTokenCreationRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		exampleToken := fakes.BuildFakePasswordResetToken()

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		sg := &randommock.Generator{}
		sg.On(
			"GenerateBase32EncodedString",
			testutils.ContextMatcher,
			passwordResetTokenSize,
		).Return(exampleToken.Token, nil)
		helper.service.secretGenerator = sg

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUserByEmail",
			testutils.ContextMatcher,
			exampleInput.EmailAddress,
		).Return(helper.exampleUser, nil)

		mockDB.PasswordResetTokenDataManagerMock.On(
			"CreatePasswordResetToken",
			testutils.ContextMatcher,
			mock.MatchedBy(func(x *types.PasswordResetTokenDatabaseCreationInput) bool { return true }),
		).Return(exampleToken, nil)

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(nil)
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.userDataManager = mockDB
		helper.service.passwordResetTokenDataManager = mockDB

		helper.service.CreatePasswordResetTokenHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusAccepted, helper.res.Code)
		var actual *types.APIResponse[any]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, sg, mockDB, dataChangesPublisher)
	})

	T.Run("with missing input", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader([]byte("")))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.service.CreatePasswordResetTokenHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with invalid input", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := types.PasswordResetTokenCreationRequestInput{}
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.service.CreatePasswordResetTokenHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with error generating secret", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakePasswordResetTokenCreationRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		sg := &randommock.Generator{}
		sg.On(
			"GenerateBase32EncodedString",
			testutils.ContextMatcher,
			passwordResetTokenSize,
		).Return("", errors.New("blah"))
		helper.service.secretGenerator = sg

		helper.service.CreatePasswordResetTokenHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, sg)
	})

	T.Run("with no such user", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakePasswordResetTokenCreationRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		exampleToken := fakes.BuildFakePasswordResetToken()

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		sg := &randommock.Generator{}
		sg.On(
			"GenerateBase32EncodedString",
			testutils.ContextMatcher,
			passwordResetTokenSize,
		).Return(exampleToken.Token, nil)
		helper.service.secretGenerator = sg

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUserByEmail",
			testutils.ContextMatcher,
			exampleInput.EmailAddress,
		).Return((*types.User)(nil), sql.ErrNoRows)

		helper.service.userDataManager = mockDB
		helper.service.passwordResetTokenDataManager = mockDB

		helper.service.CreatePasswordResetTokenHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusNotFound, helper.res.Code)
		var actual *types.APIResponse[any]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Error(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, sg, mockDB)
	})

	T.Run("with error getting user by email", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakePasswordResetTokenCreationRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		exampleToken := fakes.BuildFakePasswordResetToken()

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		sg := &randommock.Generator{}
		sg.On(
			"GenerateBase32EncodedString",
			testutils.ContextMatcher,
			passwordResetTokenSize,
		).Return(exampleToken.Token, nil)
		helper.service.secretGenerator = sg

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUserByEmail",
			testutils.ContextMatcher,
			exampleInput.EmailAddress,
		).Return((*types.User)(nil), errors.New("blah"))

		helper.service.userDataManager = mockDB
		helper.service.passwordResetTokenDataManager = mockDB

		helper.service.CreatePasswordResetTokenHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, sg, mockDB)
	})

	T.Run("with error creating password reset token", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakePasswordResetTokenCreationRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		exampleToken := fakes.BuildFakePasswordResetToken()

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		sg := &randommock.Generator{}
		sg.On(
			"GenerateBase32EncodedString",
			testutils.ContextMatcher,
			passwordResetTokenSize,
		).Return(exampleToken.Token, nil)
		helper.service.secretGenerator = sg

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUserByEmail",
			testutils.ContextMatcher,
			exampleInput.EmailAddress,
		).Return(helper.exampleUser, nil)

		mockDB.PasswordResetTokenDataManagerMock.On(
			"CreatePasswordResetToken",
			testutils.ContextMatcher,
			mock.MatchedBy(func(x *types.PasswordResetTokenDatabaseCreationInput) bool { return true }),
		).Return((*types.PasswordResetToken)(nil), errors.New("blah"))

		helper.service.userDataManager = mockDB
		helper.service.passwordResetTokenDataManager = mockDB

		helper.service.CreatePasswordResetTokenHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, sg, mockDB)
	})

	T.Run("with error publishing outbound email request", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakePasswordResetTokenCreationRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		exampleToken := fakes.BuildFakePasswordResetToken()

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		sg := &randommock.Generator{}
		sg.On(
			"GenerateBase32EncodedString",
			testutils.ContextMatcher,
			passwordResetTokenSize,
		).Return(exampleToken.Token, nil)
		helper.service.secretGenerator = sg

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUserByEmail",
			testutils.ContextMatcher,
			exampleInput.EmailAddress,
		).Return(helper.exampleUser, nil)

		mockDB.PasswordResetTokenDataManagerMock.On(
			"CreatePasswordResetToken",
			testutils.ContextMatcher,
			mock.MatchedBy(func(x *types.PasswordResetTokenDatabaseCreationInput) bool { return true }),
		).Return(exampleToken, nil)

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(nil)
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.userDataManager = mockDB
		helper.service.passwordResetTokenDataManager = mockDB

		helper.service.CreatePasswordResetTokenHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusAccepted, helper.res.Code)
		var actual *types.APIResponse[any]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, sg, mockDB, dataChangesPublisher)
	})
}

func TestService_PasswordResetTokenRedemptionHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakePasswordResetTokenRedemptionRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		exampleToken := fakes.BuildFakePasswordResetToken()
		exampleToken.BelongsToUser = helper.exampleUser.ID

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.PasswordResetTokenDataManagerMock.On(
			"GetPasswordResetTokenByToken",
			testutils.ContextMatcher,
			exampleInput.Token,
		).Return(exampleToken, nil)

		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)

		auth := &mockauthn.Authenticator{}
		auth.On(
			"HashPassword",
			testutils.ContextMatcher,
			exampleInput.NewPassword,
		).Return(helper.exampleUser.HashedPassword, nil)
		helper.service.authenticator = auth

		mockDB.UserDataManagerMock.On(
			"UpdateUserPassword",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			mock.IsType("string"),
		).Return(nil)

		mockDB.PasswordResetTokenDataManagerMock.On(
			"RedeemPasswordResetToken",
			testutils.ContextMatcher,
			exampleToken.ID,
		).Return(nil)

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(nil)
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.userDataManager = mockDB
		helper.service.passwordResetTokenDataManager = mockDB

		helper.service.PasswordResetTokenRedemptionHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusAccepted, helper.res.Code)
		var actual *types.APIResponse[any]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, mockDB, dataChangesPublisher, auth)
	})

	T.Run("with missing input", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader([]byte("")))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.service.PasswordResetTokenRedemptionHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with invalid input", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := &types.PasswordResetTokenRedemptionRequestInput{}
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)
		helper.service.PasswordResetTokenRedemptionHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with missing password reset token", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakePasswordResetTokenRedemptionRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		exampleToken := fakes.BuildFakePasswordResetToken()
		exampleToken.BelongsToUser = helper.exampleUser.ID

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.PasswordResetTokenDataManagerMock.On(
			"GetPasswordResetTokenByToken",
			testutils.ContextMatcher,
			exampleInput.Token,
		).Return((*types.PasswordResetToken)(nil), sql.ErrNoRows)

		helper.service.userDataManager = mockDB
		helper.service.passwordResetTokenDataManager = mockDB

		helper.service.PasswordResetTokenRedemptionHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusNotFound, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockDB)
	})

	T.Run("with error finding password reset token", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakePasswordResetTokenRedemptionRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		exampleToken := fakes.BuildFakePasswordResetToken()
		exampleToken.BelongsToUser = helper.exampleUser.ID

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.PasswordResetTokenDataManagerMock.On(
			"GetPasswordResetTokenByToken",
			testutils.ContextMatcher,
			exampleInput.Token,
		).Return((*types.PasswordResetToken)(nil), errors.New("blah"))

		helper.service.userDataManager = mockDB
		helper.service.passwordResetTokenDataManager = mockDB

		helper.service.PasswordResetTokenRedemptionHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockDB)
	})

	T.Run("with error getting user", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakePasswordResetTokenRedemptionRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		exampleToken := fakes.BuildFakePasswordResetToken()
		exampleToken.BelongsToUser = helper.exampleUser.ID

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.PasswordResetTokenDataManagerMock.On(
			"GetPasswordResetTokenByToken",
			testutils.ContextMatcher,
			exampleInput.Token,
		).Return(exampleToken, nil)

		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return((*types.User)(nil), errors.New("blah"))

		helper.service.userDataManager = mockDB
		helper.service.passwordResetTokenDataManager = mockDB

		helper.service.PasswordResetTokenRedemptionHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockDB)
	})

	T.Run("with too weak a password", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakePasswordResetTokenRedemptionRequestInput()
		exampleInput.NewPassword = "123"
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		exampleToken := fakes.BuildFakePasswordResetToken()
		exampleToken.BelongsToUser = helper.exampleUser.ID

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.PasswordResetTokenDataManagerMock.On(
			"GetPasswordResetTokenByToken",
			testutils.ContextMatcher,
			exampleInput.Token,
		).Return(exampleToken, nil)

		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)

		helper.service.userDataManager = mockDB
		helper.service.passwordResetTokenDataManager = mockDB

		helper.service.PasswordResetTokenRedemptionHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockDB)
	})

	T.Run("with error hashing password", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakePasswordResetTokenRedemptionRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		exampleToken := fakes.BuildFakePasswordResetToken()
		exampleToken.BelongsToUser = helper.exampleUser.ID

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.PasswordResetTokenDataManagerMock.On(
			"GetPasswordResetTokenByToken",
			testutils.ContextMatcher,
			exampleInput.Token,
		).Return(exampleToken, nil)

		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)

		auth := &mockauthn.Authenticator{}
		auth.On(
			"HashPassword",
			testutils.ContextMatcher,
			exampleInput.NewPassword,
		).Return("", errors.New("blah"))
		helper.service.authenticator = auth

		helper.service.userDataManager = mockDB
		helper.service.passwordResetTokenDataManager = mockDB

		helper.service.PasswordResetTokenRedemptionHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockDB)
	})

	T.Run("with error updating new password", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakePasswordResetTokenRedemptionRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		exampleToken := fakes.BuildFakePasswordResetToken()
		exampleToken.BelongsToUser = helper.exampleUser.ID

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.PasswordResetTokenDataManagerMock.On(
			"GetPasswordResetTokenByToken",
			testutils.ContextMatcher,
			exampleInput.Token,
		).Return(exampleToken, nil)

		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)

		auth := &mockauthn.Authenticator{}
		auth.On(
			"HashPassword",
			testutils.ContextMatcher,
			exampleInput.NewPassword,
		).Return(helper.exampleUser.HashedPassword, nil)
		helper.service.authenticator = auth

		mockDB.UserDataManagerMock.On(
			"UpdateUserPassword",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			mock.IsType("string"),
		).Return(errors.New("blah"))

		helper.service.userDataManager = mockDB
		helper.service.passwordResetTokenDataManager = mockDB

		helper.service.PasswordResetTokenRedemptionHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockDB)
	})

	T.Run("with error redeeming token", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakePasswordResetTokenRedemptionRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		exampleToken := fakes.BuildFakePasswordResetToken()
		exampleToken.BelongsToUser = helper.exampleUser.ID

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.PasswordResetTokenDataManagerMock.On(
			"GetPasswordResetTokenByToken",
			testutils.ContextMatcher,
			exampleInput.Token,
		).Return(exampleToken, nil)

		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)

		auth := &mockauthn.Authenticator{}
		auth.On(
			"HashPassword",
			testutils.ContextMatcher,
			exampleInput.NewPassword,
		).Return(helper.exampleUser.HashedPassword, nil)
		helper.service.authenticator = auth

		mockDB.UserDataManagerMock.On(
			"UpdateUserPassword",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			mock.IsType("string"),
		).Return(nil)

		mockDB.PasswordResetTokenDataManagerMock.On(
			"RedeemPasswordResetToken",
			testutils.ContextMatcher,
			exampleToken.ID,
		).Return(errors.New("blah"))

		helper.service.userDataManager = mockDB
		helper.service.passwordResetTokenDataManager = mockDB

		helper.service.PasswordResetTokenRedemptionHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockDB)
	})

	T.Run("with error publishing outbound email request", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakePasswordResetTokenRedemptionRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		exampleToken := fakes.BuildFakePasswordResetToken()
		exampleToken.BelongsToUser = helper.exampleUser.ID

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.PasswordResetTokenDataManagerMock.On(
			"GetPasswordResetTokenByToken",
			testutils.ContextMatcher,
			exampleInput.Token,
		).Return(exampleToken, nil)

		mockDB.UserDataManagerMock.On(
			"GetUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(helper.exampleUser, nil)

		auth := &mockauthn.Authenticator{}
		auth.On(
			"HashPassword",
			testutils.ContextMatcher,
			exampleInput.NewPassword,
		).Return(helper.exampleUser.HashedPassword, nil)
		helper.service.authenticator = auth

		mockDB.UserDataManagerMock.On(
			"UpdateUserPassword",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			mock.IsType("string"),
		).Return(nil)

		mockDB.PasswordResetTokenDataManagerMock.On(
			"RedeemPasswordResetToken",
			testutils.ContextMatcher,
			exampleToken.ID,
		).Return(nil)

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(nil)
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.userDataManager = mockDB
		helper.service.passwordResetTokenDataManager = mockDB

		helper.service.PasswordResetTokenRedemptionHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusAccepted, helper.res.Code)
		var actual *types.APIResponse[any]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, mockDB, dataChangesPublisher, auth)
	})
}

func TestService_VerifyUserEmailAddressHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeEmailAddressVerificationRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUserByEmailAddressVerificationToken",
			testutils.ContextMatcher,
			exampleInput.Token,
		).Return(helper.exampleUser, nil)

		mockDB.UserDataManagerMock.On(
			"MarkUserEmailAddressAsVerified",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			exampleInput.Token,
		).Return(nil)

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(nil)
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.userDataManager = mockDB
		helper.service.passwordResetTokenDataManager = mockDB

		helper.service.VerifyUserEmailAddressHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusAccepted, helper.res.Code)
		var actual *types.APIResponse[any]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, mockDB, dataChangesPublisher)
	})

	T.Run("with error decoding request", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)

		helper.service.VerifyUserEmailAddressHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with invalid input", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := &types.EmailAddressVerificationRequestInput{}
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		helper.service.VerifyUserEmailAddressHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusBadRequest, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)
	})

	T.Run("with error fetching user by token", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeEmailAddressVerificationRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUserByEmailAddressVerificationToken",
			testutils.ContextMatcher,
			exampleInput.Token,
		).Return((*types.User)(nil), errors.New("blah"))

		helper.service.userDataManager = mockDB
		helper.service.passwordResetTokenDataManager = mockDB

		helper.service.VerifyUserEmailAddressHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockDB)
	})

	T.Run("with sql.ErrNoRows for verification token", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeEmailAddressVerificationRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUserByEmailAddressVerificationToken",
			testutils.ContextMatcher,
			exampleInput.Token,
		).Return((*types.User)(nil), sql.ErrNoRows)

		helper.service.userDataManager = mockDB
		helper.service.passwordResetTokenDataManager = mockDB

		helper.service.VerifyUserEmailAddressHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusNotFound, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockDB)
	})

	T.Run("with error marking user email address as verified", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeEmailAddressVerificationRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUserByEmailAddressVerificationToken",
			testutils.ContextMatcher,
			exampleInput.Token,
		).Return(helper.exampleUser, nil)

		mockDB.UserDataManagerMock.On(
			"MarkUserEmailAddressAsVerified",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			exampleInput.Token,
		).Return(errors.New("blah"))

		helper.service.userDataManager = mockDB
		helper.service.passwordResetTokenDataManager = mockDB

		helper.service.VerifyUserEmailAddressHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusInternalServerError, helper.res.Code)
		var actual *types.APIResponse[*types.User]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.Empty(t, actual.Data)
		assert.Error(t, actual.Error)

		mock.AssertExpectationsForObjects(t, mockDB)
	})

	T.Run("with error publishing data change message", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		exampleInput := fakes.BuildFakeEmailAddressVerificationRequestInput()
		jsonBytes := helper.service.encoderDecoder.MustEncode(helper.ctx, exampleInput)

		var err error
		helper.req, err = http.NewRequestWithContext(helper.ctx, http.MethodPost, "https://whatever.whocares.gov", bytes.NewReader(jsonBytes))
		require.NoError(t, err)
		require.NotNil(t, helper.req)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetUserByEmailAddressVerificationToken",
			testutils.ContextMatcher,
			exampleInput.Token,
		).Return(helper.exampleUser, nil)

		mockDB.UserDataManagerMock.On(
			"MarkUserEmailAddressAsVerified",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
			exampleInput.Token,
		).Return(nil)

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(errors.New("blah"))
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.userDataManager = mockDB
		helper.service.passwordResetTokenDataManager = mockDB

		helper.service.VerifyUserEmailAddressHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusAccepted, helper.res.Code)
		var actual *types.APIResponse[any]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, mockDB, dataChangesPublisher)
	})
}

func TestService_RequestEmailVerificationEmailHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := newTestHelper(t)
		helper.service.encoderDecoder = encoding.ProvideServerEncoderDecoder(logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), encoding.ContentTypeJSON)

		mockDB := database.NewMockDatabase()
		mockDB.UserDataManagerMock.On(
			"GetEmailAddressVerificationTokenForUser",
			testutils.ContextMatcher,
			helper.exampleUser.ID,
		).Return(t.Name(), nil)

		dataChangesPublisher := &mockpublishers.Publisher{}
		dataChangesPublisher.On(
			"Publish",
			testutils.ContextMatcher,
			testutils.DataChangeMessageMatcher,
		).Return(nil)
		helper.service.dataChangesPublisher = dataChangesPublisher

		helper.service.userDataManager = mockDB
		helper.service.passwordResetTokenDataManager = mockDB

		helper.service.RequestEmailVerificationEmailHandler(helper.res, helper.req)

		assert.Equal(t, http.StatusAccepted, helper.res.Code)
		var actual *types.APIResponse[any]
		require.NoError(t, helper.service.encoderDecoder.DecodeBytes(helper.ctx, helper.res.Body.Bytes(), &actual))
		assert.NoError(t, actual.Error.AsError())

		mock.AssertExpectationsForObjects(t, mockDB, dataChangesPublisher)
	})
}
