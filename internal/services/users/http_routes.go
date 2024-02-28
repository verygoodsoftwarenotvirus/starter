package users

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"image/png"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/verygoodsoftwarenotvirus/starter/internal/authorization"
	"github.com/verygoodsoftwarenotvirus/starter/internal/database"
	"github.com/verygoodsoftwarenotvirus/starter/internal/identifiers"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/converters"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	servertiming "github.com/mitchellh/go-server-timing"
	"github.com/pquerna/otp/totp"
	passwordvalidator "github.com/wagslane/go-password-validator"
)

var _ types.UserDataService = (*service)(nil)

const (
	// UserIDURIParamKey is used to refer to user IDs in router params.
	UserIDURIParamKey = "userID"

	totpIssuer             = "DinnerDoneBetter"
	base64ImagePrefix      = "data:image/jpeg;base64,"
	minimumPasswordEntropy = 60
	totpSecretSize         = 64
	passwordResetTokenSize = 32
)

// validateCredentialsForUpdateRequest takes a user's credentials and determines if they match what is on record.
func (s *service) validateCredentialsForUpdateRequest(ctx context.Context, userID, password, totpToken string) (user *types.User, httpStatus int) {
	ctx, span := s.tracer.StartSpan(ctx)
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithValue(keys.UserIDKey, userID)

	// fetch user data.
	readTimer := timing.NewMetric("database").WithDesc("fetch").Start()
	user, err := s.userDataManager.GetUser(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, http.StatusNotFound
		}

		logger.Error(err, "error encountered fetching user")
		return nil, http.StatusInternalServerError
	}
	readTimer.Stop()

	if user.TwoFactorSecretVerifiedAt != nil && totpToken == "" {
		return nil, http.StatusResetContent
	}

	tfs := user.TwoFactorSecret
	if user.TwoFactorSecretVerifiedAt == nil {
		tfs = ""
		totpToken = ""
	}

	// validate login.
	valid, err := s.authenticator.CredentialsAreValid(ctx, user.HashedPassword, password, tfs, totpToken)
	if err != nil {
		logger.WithValue("validation_error", err).Debug("error validating credentials")
		return nil, http.StatusBadRequest
	} else if !valid {
		logger.WithValue("valid", valid).Error(err, "invalid credentials")
		return nil, http.StatusUnauthorized
	}

	return user, http.StatusOK
}

// UsernameSearchHandler is a handler for responding to username queries.
func (s *service) UsernameSearchHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	query := req.URL.Query().Get(types.SearchQueryKey)

	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	// fetch user data.
	users, err := s.userDataManager.SearchForUsersByUsername(ctx, query)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			errRes := types.NewAPIErrorResponse("not found", types.ErrDataNotFound, responseDetails)
			s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusNotFound)
			return
		}

		observability.AcknowledgeError(err, logger, span, "searching for users")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}

	responseValue := &types.APIResponse[[]*types.User]{
		Details: responseDetails,
		Data:    users,
	}

	// encode response.
	s.encoderDecoder.RespondWithData(ctx, res, responseValue)
}

// ListHandler is a handler for responding with a list of users.
func (s *service) ListHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	// determine desired filter.
	qf := types.ExtractQueryFilterFromRequest(req)

	// fetch user data.
	readTimer := timing.NewMetric("database").WithDesc("fetch").Start()
	users, err := s.userDataManager.GetUsers(ctx, qf)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "fetching users")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	readTimer.Stop()

	responseValue := &types.APIResponse[[]*types.User]{
		Details:    responseDetails,
		Data:       users.Data,
		Pagination: &users.Pagination,
	}

	// encode response.
	s.encoderDecoder.RespondWithData(ctx, res, responseValue)
}

// CreateHandler is our user creation route.
func (s *service) CreateHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	// in the event that we don't want new users to be able to sign up (a config setting) just decline the request from the get-go
	if !s.authSettings.EnableUserSignup || os.Getenv("DISABLE_REGISTRATION") == "true" {
		errRes := types.NewAPIErrorResponse("user creation is disabled", types.ErrNothingSpecific, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusForbidden)
		return
	}

	// decode the request.
	decodeTimer := timing.NewMetric("decode").WithDesc("decode input").Start()
	registrationInput := new(types.UserRegistrationInput)
	if err := s.encoderDecoder.DecodeRequest(ctx, req, registrationInput); err != nil {
		observability.AcknowledgeError(err, logger, span, "decoding request body")
		errRes := types.NewAPIErrorResponse("invalid request content", types.ErrDecodingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}
	decodeTimer.Stop()

	registrationInput.Username = strings.TrimSpace(registrationInput.Username)
	tracing.AttachToSpan(span, keys.UsernameKey, registrationInput.Username)
	registrationInput.EmailAddress = strings.TrimSpace(strings.ToLower(registrationInput.EmailAddress))
	tracing.AttachToSpan(span, keys.UserEmailAddressKey, registrationInput.EmailAddress)
	registrationInput.Password = strings.TrimSpace(registrationInput.Password)

	logger = logger.WithValues(map[string]any{
		keys.UsernameKey:               registrationInput.Username,
		keys.UserEmailAddressKey:       registrationInput.EmailAddress,
		keys.AccountInvitationIDKey:    registrationInput.InvitationID,
		keys.AccountInvitationTokenKey: registrationInput.InvitationToken,
	})

	if err := registrationInput.ValidateWithContext(ctx, s.authSettings.MinimumUsernameLength, s.authSettings.MinimumPasswordLength); err != nil {
		logger.WithValue(keys.ValidationErrorKey, err).Debug("provided input was invalid")
		errRes := types.NewAPIErrorResponse(err.Error(), types.ErrValidatingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}

	// ensure the password is not garbage-tier
	if err := passwordvalidator.Validate(strings.TrimSpace(registrationInput.Password), minimumPasswordEntropy); err != nil {
		logger.WithValue("password_validation_error", err).Debug("weak password provided to user creation route")
		errRes := types.NewAPIErrorResponse("provided password is too weak", types.ErrValidatingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}

	var invitation *types.AccountInvitation
	if registrationInput.InvitationID != "" && registrationInput.InvitationToken != "" {
		readTimer := timing.NewMetric("database").WithDesc("fetch").Start()
		i, err := s.accountInvitationDataManager.GetAccountInvitationByTokenAndID(ctx, registrationInput.InvitationToken, registrationInput.InvitationID)
		if errors.Is(err, sql.ErrNoRows) {
			errRes := types.NewAPIErrorResponse("not found", types.ErrDataNotFound, responseDetails)
			s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusNotFound)
			return
		} else if err != nil {
			observability.AcknowledgeError(err, logger, span, "retrieving invitation")
			errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
			s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
			return
		}
		readTimer.Stop()

		invitation = i
		logger = logger.WithValue(keys.AccountInvitationIDKey, invitation.ID)
		logger.Debug("retrieved account invitation")
	}

	logger.Debug("completed invitation check")

	// hash the password
	hp, err := s.authenticator.HashPassword(ctx, strings.TrimSpace(registrationInput.Password))
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "creating user")
		errRes := types.NewAPIErrorResponse("hashing password", types.ErrSecretGeneration, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}

	// generate a two factor secret.
	tfs, err := s.secretGenerator.GenerateBase32EncodedString(ctx, totpSecretSize)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "generating two factor secret")
		errRes := types.NewAPIErrorResponse("internal error", types.ErrNothingSpecific, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}

	input := &types.UserDatabaseCreationInput{
		ID:              identifiers.New(),
		Username:        registrationInput.Username,
		FirstName:       registrationInput.FirstName,
		LastName:        registrationInput.LastName,
		EmailAddress:    registrationInput.EmailAddress,
		HashedPassword:  hp,
		TwoFactorSecret: tfs,
		InvitationToken: registrationInput.InvitationToken,
		Birthday:        registrationInput.Birthday,
		AccountName:     registrationInput.AccountName,
	}

	if invitation != nil {
		logger.Debug("supplementing user creation input with invitation data")
		input.DestinationAccountID = invitation.DestinationAccount.ID
		input.InvitationToken = invitation.Token
	}

	// create the user.
	createTimer := timing.NewMetric("database").WithDesc("create").Start()
	user, err := s.userDataManager.CreateUser(ctx, input)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "creating user")
		if errors.Is(err, database.ErrUserAlreadyExists) {
			errRes := types.NewAPIErrorResponse("username taken", types.ErrValidatingRequestInput, responseDetails)
			s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
			return
		}
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	createTimer.Stop()

	logger.Debug("user created")

	readTimer := timing.NewMetric("database").WithDesc("get default account").Start()
	defaultAccountID, err := s.accountUserMembershipDataManager.GetDefaultAccountIDForUser(ctx, user.ID)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "fetching default account ID for user")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	readTimer.Stop()

	readTimer = timing.NewMetric("database").WithDesc("get token").Start()
	emailVerificationToken, emailVerificationTokenErr := s.userDataManager.GetEmailAddressVerificationTokenForUser(ctx, user.ID)
	if emailVerificationTokenErr != nil {
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	readTimer.Stop()

	// notify the relevant parties.
	tracing.AttachToSpan(span, keys.UserIDKey, user.ID)

	dcm := &types.DataChangeMessage{
		AccountID:              defaultAccountID,
		EventType:              types.UserSignedUpCustomerEventType,
		UserID:                 user.ID,
		EmailVerificationToken: emailVerificationToken,
	}

	if err = s.dataChangesPublisher.Publish(ctx, dcm); err != nil {
		observability.AcknowledgeError(err, logger, span, "publishing data change message")
	}

	if err = s.analyticsReporter.AddUser(ctx, user.ID, map[string]any{
		"username":        user.Username,
		"default_account": defaultAccountID,
		"first_name":      user.FirstName,
		"last_name":       user.LastName,
	}); err != nil {
		observability.AcknowledgeError(err, logger, span, "identifying user for analytics")
	}

	if err = s.featureFlagManager.Identify(ctx, user); err != nil {
		observability.AcknowledgeError(err, logger, span, "identifying user in feature flag manager")
	}

	// UserCreationResponse is a struct we can use to notify the user of their two factor secret, but ideally just this once and then never again.
	ucr := &types.UserCreationResponse{
		CreatedUserID:   user.ID,
		Username:        user.Username,
		FirstName:       user.FirstName,
		LastName:        user.LastName,
		EmailAddress:    user.EmailAddress,
		CreatedAt:       user.CreatedAt,
		TwoFactorSecret: user.TwoFactorSecret,
		Birthday:        user.Birthday,
		TwoFactorQRCode: s.buildQRCode(ctx, user.Username, user.TwoFactorSecret),
	}

	responseValue := &types.APIResponse[*types.UserCreationResponse]{
		Details: responseDetails,
		Data:    ucr,
	}

	// encode and peace.
	s.encoderDecoder.EncodeResponseWithStatus(ctx, res, responseValue, http.StatusCreated)
}

// buildQRCode builds a QR code for a given username and secret.
func (s *service) buildQRCode(ctx context.Context, username, twoFactorSecret string) string {
	_, span := s.tracer.StartSpan(ctx)
	defer span.End()

	logger := s.logger.WithValue(keys.UsernameKey, username)

	// "otpauth://totp/{{ .Issuer }}:{{ .EnsureUsername }}?secret={{ .Secret }}&issuer={{ .Issuer }}",
	otpString := fmt.Sprintf(
		"otpauth://totp/%s:%s?secret=%s&issuer=%s",
		totpIssuer,
		username,
		twoFactorSecret,
		totpIssuer,
	)

	// encode two factor secret as authenticator-friendly QR code
	qrCode, err := qr.Encode(otpString, qr.L, qr.Auto)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "encoding OTP string")
		return ""
	}

	// scale the QR code so that it's not a PNG for ants.
	qrCode, err = barcode.Scale(qrCode, 256, 256)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "scaling QR code")
		return ""
	}

	// encode the QR code to PNG.
	var b bytes.Buffer
	if err = png.Encode(&b, qrCode); err != nil {
		observability.AcknowledgeError(err, logger, span, "encoding QR code to PNG")
		return ""
	}

	// base64 encode the image for easy HTML use.
	return fmt.Sprintf("%s%s", base64ImagePrefix, base64.StdEncoding.EncodeToString(b.Bytes()))
}

// SelfHandler returns information about the user making the request.
func (s *service) SelfHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	sessionContextTimer := timing.NewMetric("session").WithDesc("fetch session context").Start()
	sessionCtxData, err := s.sessionContextDataFetcher(req)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "retrieving session context data")
		errRes := types.NewAPIErrorResponse("unauthenticated", types.ErrFetchingSessionContextData, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusUnauthorized)
		return
	}
	sessionContextTimer.Stop()

	tracing.AttachSessionContextDataToSpan(span, sessionCtxData)
	logger = sessionCtxData.AttachToLogger(logger)
	responseDetails.CurrentAccountID = sessionCtxData.ActiveAccountID

	// figure out who this is all for.
	requester := sessionCtxData.Requester.UserID
	logger = logger.WithValue(keys.RequesterIDKey, requester)
	tracing.AttachToSpan(span, keys.RequesterIDKey, requester)

	// fetch user data.
	readTimer := timing.NewMetric("database").WithDesc("fetch").Start()
	user, err := s.userDataManager.GetUser(ctx, requester)
	if errors.Is(err, sql.ErrNoRows) {
		logger.Debug("no such user")
		errRes := types.NewAPIErrorResponse("not found", types.ErrDataNotFound, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusNotFound)
		return
	} else if err != nil {
		observability.AcknowledgeError(err, logger, span, "fetching user")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	readTimer.Stop()

	responseValue := &types.APIResponse[*types.User]{
		Details: responseDetails,
		Data:    user,
	}

	// encode response and peace.
	s.encoderDecoder.RespondWithData(ctx, res, responseValue)
}

// PermissionsHandler returns information about the user making the request.
func (s *service) PermissionsHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	sessionContextTimer := timing.NewMetric("session").WithDesc("fetch session context").Start()
	sessionCtxData, err := s.sessionContextDataFetcher(req)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "retrieving session context data")
		errRes := types.NewAPIErrorResponse("unauthenticated", types.ErrFetchingSessionContextData, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusUnauthorized)
		return
	}
	sessionContextTimer.Stop()

	tracing.AttachSessionContextDataToSpan(span, sessionCtxData)
	logger = sessionCtxData.AttachToLogger(logger)
	responseDetails.CurrentAccountID = sessionCtxData.ActiveAccountID

	// decode the request.
	permissionsInput := new(types.UserPermissionsRequestInput)
	if decodeErr := s.encoderDecoder.DecodeRequest(ctx, req, permissionsInput); decodeErr != nil {
		observability.AcknowledgeError(decodeErr, logger, span, "decoding request body")
		errRes := types.NewAPIErrorResponse("invalid request content", types.ErrDecodingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}

	body := &types.UserPermissionsResponse{
		Permissions: make(map[string]bool),
	}

	for _, perm := range permissionsInput.Permissions {
		p := authorization.Permission(perm)
		hasAccountPerm := sessionCtxData.AccountPermissions[sessionCtxData.ActiveAccountID].HasPermission(p)
		hasServicePerm := sessionCtxData.Requester.ServicePermissions.HasPermission(p)
		body.Permissions[perm] = hasAccountPerm || hasServicePerm
	}

	responseValue := &types.APIResponse[*types.UserPermissionsResponse]{
		Details: responseDetails,
		Data:    body,
	}

	// encode response and peace.
	s.encoderDecoder.RespondWithData(ctx, res, responseValue)
}

// ReadHandler is our read route.
func (s *service) ReadHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	// figure out who this is all for.
	userID := s.userIDFetcher(req)
	logger = logger.WithValue(keys.UserIDKey, userID)
	tracing.AttachToSpan(span, keys.UserIDKey, userID)

	// fetch user data.
	readTimer := timing.NewMetric("database").WithDesc("fetch").Start()
	x, err := s.userDataManager.GetUser(ctx, userID)
	if errors.Is(err, sql.ErrNoRows) {
		logger.Debug("no such user")
		errRes := types.NewAPIErrorResponse("not found", types.ErrDataNotFound, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusNotFound)
		return
	} else if err != nil {
		observability.AcknowledgeError(err, logger, span, "fetching user from database")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	readTimer.Stop()

	responseValue := &types.APIResponse[*types.User]{
		Details: responseDetails,
		Data:    x,
	}

	// encode response and peace.
	s.encoderDecoder.RespondWithData(ctx, res, responseValue)
}

// TOTPSecretVerificationHandler accepts a TOTP token as input and returns 200 if the TOTP token
// is validated by the user's TOTP secret.
func (s *service) TOTPSecretVerificationHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	// decode the request.
	decodeTimer := timing.NewMetric("decode").WithDesc("decode input").Start()
	input := new(types.TOTPSecretVerificationInput)
	if err := s.encoderDecoder.DecodeRequest(ctx, req, input); err != nil {
		observability.AcknowledgeError(err, logger, span, "decoding request body")
		errRes := types.NewAPIErrorResponse("invalid request content", types.ErrDecodingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}
	decodeTimer.Stop()

	if err := input.ValidateWithContext(ctx); err != nil {
		logger.WithValue(keys.ValidationErrorKey, err).Debug("provided input was invalid")
		errRes := types.NewAPIErrorResponse("invalid request content", types.ErrValidatingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}

	logger = logger.WithValue(keys.UserIDKey, input.UserID)

	readTimer := timing.NewMetric("database").WithDesc("fetch").Start()
	user, err := s.userDataManager.GetUserWithUnverifiedTwoFactorSecret(ctx, input.UserID)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "fetching user to verify two factor secret")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	readTimer.Stop()

	tracing.AttachToSpan(span, keys.UserIDKey, user.ID)
	tracing.AttachToSpan(span, keys.UsernameKey, user.Username)

	if user.TwoFactorSecretVerifiedAt != nil {
		// I suppose if this happens too many times, we might want to keep track of that
		logger.Debug("two factor secret already verified")
		errRes := types.NewAPIErrorResponse("TOTP secret already verified", types.ErrValidatingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusAlreadyReported)
		return
	}

	totpValid := totp.Validate(input.TOTPToken, user.TwoFactorSecret)
	if !totpValid {
		logger.WithValue(keys.ValidationErrorKey, err).Debug("provided input was invalid")
		errRes := types.NewAPIErrorResponse("invalid request content", types.ErrValidatingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}

	if err = s.userDataManager.MarkUserTwoFactorSecretAsVerified(ctx, user.ID); err != nil {
		observability.AcknowledgeError(err, logger, span, "verifying user two factor secret")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}

	dcm := &types.DataChangeMessage{
		EventType: types.TwoFactorSecretVerifiedCustomerEventType,
		UserID:    user.ID,
	}

	if err = s.dataChangesPublisher.Publish(ctx, dcm); err != nil {
		observability.AcknowledgeError(err, logger, span, "publishing data change message")
	}

	responseValue := &types.APIResponse[*types.User]{
		Details: responseDetails,
		Data:    user,
	}

	s.encoderDecoder.EncodeResponseWithStatus(ctx, res, responseValue, http.StatusAccepted)
}

// NewTOTPSecretHandler fetches a user, and issues them a new TOTP secret, after validating
// that information received from TOTPSecretRefreshInputContextMiddleware is valid.
func (s *service) NewTOTPSecretHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	// decode the request.
	input := new(types.TOTPSecretRefreshInput)
	if err := s.encoderDecoder.DecodeRequest(ctx, req, input); err != nil {
		observability.AcknowledgeError(err, logger, span, "decoding request body")
		errRes := types.NewAPIErrorResponse("invalid request content", types.ErrDecodingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}

	if err := input.ValidateWithContext(ctx); err != nil {
		logger.WithValue(keys.ValidationErrorKey, err).Debug("provided input was invalid")
		errRes := types.NewAPIErrorResponse(err.Error(), types.ErrValidatingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}

	sessionContextTimer := timing.NewMetric("session").WithDesc("fetch session context").Start()
	sessionCtxData, err := s.sessionContextDataFetcher(req)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "retrieving session context data")
		errRes := types.NewAPIErrorResponse("unauthenticated", types.ErrFetchingSessionContextData, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusUnauthorized)
		return
	}
	sessionContextTimer.Stop()

	tracing.AttachSessionContextDataToSpan(span, sessionCtxData)
	logger = sessionCtxData.AttachToLogger(logger)
	responseDetails.CurrentAccountID = sessionCtxData.ActiveAccountID

	// fetch user
	readTimer := timing.NewMetric("database").WithDesc("fetch").Start()
	user, err := s.userDataManager.GetUser(ctx, sessionCtxData.Requester.UserID)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "fetching user from database")
		if errors.Is(err, sql.ErrNoRows) {
			errRes := types.NewAPIErrorResponse("not found", types.ErrDataNotFound, responseDetails)
			s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusNotFound)
			return
		}
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	readTimer.Stop()

	if user.TwoFactorSecretVerifiedAt != nil {
		// validate login.
		valid, validationErr := s.authenticator.CredentialsAreValid(ctx, user.HashedPassword, input.CurrentPassword, user.TwoFactorSecret, input.TOTPToken)
		if validationErr != nil {
			observability.AcknowledgeError(validationErr, logger, span, "validating credentials")
			errRes := types.NewAPIErrorResponse("invalid request content", types.ErrDecodingRequestInput, responseDetails)
			s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
			return
		} else if !valid {
			observability.AcknowledgeError(validationErr, logger, span, "invalid credentials")
			errRes := types.NewAPIErrorResponse("unauthenticated", types.ErrUserIsNotAuthorized, responseDetails)
			s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusUnauthorized)
			return
		}
	} else {
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, []byte(""), http.StatusPreconditionFailed)
		return
	}

	// document who this is for.
	tracing.AttachToSpan(span, keys.RequesterIDKey, sessionCtxData.Requester.UserID)
	tracing.AttachToSpan(span, keys.UsernameKey, user.Username)
	logger = logger.WithValue(keys.UserIDKey, user.ID)

	// set the two factor secret.
	tfs, err := s.secretGenerator.GenerateBase32EncodedString(ctx, totpSecretSize)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "generating 2FA secret")
		errRes := types.NewAPIErrorResponse("generating secret", types.ErrSecretGeneration, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}

	// update the user in the database.
	if err = s.userDataManager.MarkUserTwoFactorSecretAsUnverified(ctx, user.ID, tfs); err != nil {
		observability.AcknowledgeError(err, logger, span, "updating 2FA secret")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}

	user.TwoFactorSecret = tfs
	user.TwoFactorSecretVerifiedAt = nil

	dcm := &types.DataChangeMessage{
		EventType: types.TwoFactorSecretChangedCustomerEventType,
		UserID:    user.ID,
	}

	if err = s.dataChangesPublisher.Publish(ctx, dcm); err != nil {
		observability.AcknowledgeError(err, logger, span, "publishing data change message")
	}

	// let the requester know we're all good.
	result := &types.TOTPSecretRefreshResponse{
		TwoFactorSecret: user.TwoFactorSecret,
		TwoFactorQRCode: s.buildQRCode(ctx, user.Username, user.TwoFactorSecret),
	}

	responseValue := &types.APIResponse[*types.TOTPSecretRefreshResponse]{
		Details: responseDetails,
		Data:    result,
	}

	s.encoderDecoder.EncodeResponseWithStatus(ctx, res, responseValue, http.StatusAccepted)
}

// UpdatePasswordHandler updates a user's password.
func (s *service) UpdatePasswordHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	// decode the request.
	input := new(types.PasswordUpdateInput)
	if err := s.encoderDecoder.DecodeRequest(ctx, req, input); err != nil {
		observability.AcknowledgeError(err, logger, span, "decoding request body")
		errRes := types.NewAPIErrorResponse("invalid request content", types.ErrDecodingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}

	if err := input.ValidateWithContext(ctx, s.authSettings.MinimumPasswordLength); err != nil {
		logger.WithValue(keys.ValidationErrorKey, err).Debug("provided input was invalid")
		errRes := types.NewAPIErrorResponse(err.Error(), types.ErrValidatingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}

	sessionContextTimer := timing.NewMetric("session").WithDesc("fetch session context").Start()
	sessionCtxData, err := s.sessionContextDataFetcher(req)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "retrieving session context data")
		errRes := types.NewAPIErrorResponse("unauthenticated", types.ErrFetchingSessionContextData, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusUnauthorized)
		return
	}
	sessionContextTimer.Stop()

	// determine relevant user ID.
	tracing.AttachToSpan(span, keys.RequesterIDKey, sessionCtxData.Requester.UserID)
	logger = sessionCtxData.AttachToLogger(logger)

	// make sure everything's on the up-and-up
	user, httpStatus := s.validateCredentialsForUpdateRequest(
		ctx,
		sessionCtxData.Requester.UserID,
		input.CurrentPassword,
		input.TOTPToken,
	)

	// if the above function returns something other than 200, it means some error occurred.
	if httpStatus != http.StatusOK {
		errRes := types.NewAPIErrorResponse("internal error", types.ErrValidatingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, httpStatus)
		return
	}

	tracing.AttachToSpan(span, keys.UsernameKey, user.Username)

	// ensure the password isn't garbage-tier
	if err = passwordvalidator.Validate(input.NewPassword, minimumPasswordEntropy); err != nil {
		logger.WithValue("password_validation_error", err).Debug("invalid password provided")
		errRes := types.NewAPIErrorResponse("password is too weak", types.ErrNothingSpecific, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}

	// hash the new password.
	newPasswordHash, err := s.authenticator.HashPassword(ctx, strings.TrimSpace(input.NewPassword))
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "hashing password")
		errRes := types.NewAPIErrorResponse("hashing password", types.ErrSecretGeneration, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}

	// update the user.
	updateTimer := timing.NewMetric("database").WithDesc("update").Start()
	if err = s.userDataManager.UpdateUserPassword(ctx, user.ID, newPasswordHash); err != nil {
		observability.AcknowledgeError(err, logger, span, "updating user")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	updateTimer.Stop()

	dcm := &types.DataChangeMessage{
		EventType: types.PasswordChangedEventType,
		UserID:    user.ID,
	}

	if err = s.dataChangesPublisher.Publish(ctx, dcm); err != nil {
		observability.AcknowledgeError(err, logger, span, "publishing data change message")
	}

	// we're all good, log the user out
	http.SetCookie(res, &http.Cookie{MaxAge: -1})

	responseValue := &types.APIResponse[any]{
		Details: responseDetails,
	}

	s.encoderDecoder.EncodeResponseWithStatus(ctx, res, responseValue, http.StatusAccepted)
}

// UpdateUserEmailAddressHandler updates a user's email address.
func (s *service) UpdateUserEmailAddressHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	// decode the request.
	input := new(types.UserEmailAddressUpdateInput)
	if err := s.encoderDecoder.DecodeRequest(ctx, req, input); err != nil {
		observability.AcknowledgeError(err, logger, span, "decoding request body")
		errRes := types.NewAPIErrorResponse("invalid request content", types.ErrDecodingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}

	if err := input.ValidateWithContext(ctx); err != nil {
		logger.WithValue(keys.ValidationErrorKey, err).Debug("provided input was invalid")
		errRes := types.NewAPIErrorResponse(err.Error(), types.ErrValidatingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}
	tracing.AttachToSpan(span, keys.UserEmailAddressKey, input.NewEmailAddress)

	sessionContextTimer := timing.NewMetric("session").WithDesc("fetch session context").Start()
	sessionCtxData, err := s.sessionContextDataFetcher(req)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "retrieving session context data")
		errRes := types.NewAPIErrorResponse("unauthenticated", types.ErrFetchingSessionContextData, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusUnauthorized)
		return
	}
	sessionContextTimer.Stop()

	// determine relevant user ID.
	tracing.AttachToSpan(span, keys.RequesterIDKey, sessionCtxData.Requester.UserID)
	logger = sessionCtxData.AttachToLogger(logger)

	// make sure everything's on the up-and-up
	user, httpStatus := s.validateCredentialsForUpdateRequest(
		ctx,
		sessionCtxData.Requester.UserID,
		input.CurrentPassword,
		input.TOTPToken,
	)

	// if the above function returns something other than 200, it means some error occurred.
	if httpStatus != http.StatusOK {
		res.WriteHeader(httpStatus)
		return
	}

	// update the user.
	updateTimer := timing.NewMetric("database").WithDesc("update").Start()
	if err = s.userDataManager.UpdateUserEmailAddress(ctx, user.ID, input.NewEmailAddress); err != nil {
		observability.AcknowledgeError(err, logger, span, "updating user")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	updateTimer.Stop()

	dcm := &types.DataChangeMessage{
		EventType: types.EmailAddressChangedEventType,
		UserID:    user.ID,
	}

	if err = s.dataChangesPublisher.Publish(ctx, dcm); err != nil {
		observability.AcknowledgeError(err, logger, span, "publishing data change message")
	}

	responseValue := &types.APIResponse[*types.User]{
		Details: responseDetails,
		Data:    user,
	}

	s.encoderDecoder.EncodeResponseWithStatus(ctx, res, responseValue, http.StatusAccepted)
}

// UpdateUserUsernameHandler updates a user's username.
func (s *service) UpdateUserUsernameHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	// decode the request.
	input := new(types.UsernameUpdateInput)
	if err := s.encoderDecoder.DecodeRequest(ctx, req, input); err != nil {
		observability.AcknowledgeError(err, logger, span, "decoding request body")
		errRes := types.NewAPIErrorResponse("invalid request content", types.ErrDecodingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}

	if err := input.ValidateWithContext(ctx); err != nil {
		logger.WithValue(keys.ValidationErrorKey, err).Debug("provided input was invalid")
		errRes := types.NewAPIErrorResponse(err.Error(), types.ErrValidatingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}
	tracing.AttachToSpan(span, keys.UsernameKey, input.NewUsername)

	sessionContextTimer := timing.NewMetric("session").WithDesc("fetch session context").Start()
	sessionCtxData, err := s.sessionContextDataFetcher(req)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "retrieving session context data")
		errRes := types.NewAPIErrorResponse("unauthenticated", types.ErrFetchingSessionContextData, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusUnauthorized)
		return
	}
	sessionContextTimer.Stop()

	// determine relevant user ID.
	tracing.AttachToSpan(span, keys.RequesterIDKey, sessionCtxData.Requester.UserID)
	logger = sessionCtxData.AttachToLogger(logger)

	// make sure everything's on the up-and-up
	user, httpStatus := s.validateCredentialsForUpdateRequest(
		ctx,
		sessionCtxData.Requester.UserID,
		input.CurrentPassword,
		input.TOTPToken,
	)

	// if the above function returns something other than 200, it means some error occurred.
	if httpStatus != http.StatusOK {
		res.WriteHeader(httpStatus)
		return
	}

	// update the user.
	updateTimer := timing.NewMetric("database").WithDesc("update").Start()
	if err = s.userDataManager.UpdateUserUsername(ctx, user.ID, input.NewUsername); err != nil {
		observability.AcknowledgeError(err, logger, span, "updating user")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	updateTimer.Stop()

	dcm := &types.DataChangeMessage{
		EventType: types.UsernameChangedEventType,
		UserID:    user.ID,
	}

	if err = s.dataChangesPublisher.Publish(ctx, dcm); err != nil {
		observability.AcknowledgeError(err, logger, span, "publishing data change message")
	}

	responseValue := &types.APIResponse[*types.User]{
		Details: responseDetails,
		Data:    user,
	}

	s.encoderDecoder.EncodeResponseWithStatus(ctx, res, responseValue, http.StatusAccepted)
}

// UpdateUserDetailsHandler updates a user's basic information.
func (s *service) UpdateUserDetailsHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	// decode the request.
	providedInput := new(types.UserDetailsUpdateRequestInput)
	if err := s.encoderDecoder.DecodeRequest(ctx, req, providedInput); err != nil {
		observability.AcknowledgeError(err, logger, span, "decoding request body")
		errRes := types.NewAPIErrorResponse("invalid request content", types.ErrDecodingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}

	if err := providedInput.ValidateWithContext(ctx); err != nil {
		logger.WithValue(keys.ValidationErrorKey, err).Debug("provided providedInput was invalid")
		errRes := types.NewAPIErrorResponse(err.Error(), types.ErrValidatingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}

	sessionContextTimer := timing.NewMetric("session").WithDesc("fetch session context").Start()
	sessionCtxData, err := s.sessionContextDataFetcher(req)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "retrieving session context data")
		errRes := types.NewAPIErrorResponse("unauthenticated", types.ErrFetchingSessionContextData, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusUnauthorized)
		return
	}
	sessionContextTimer.Stop()

	// determine relevant user ID.
	tracing.AttachToSpan(span, keys.RequesterIDKey, sessionCtxData.Requester.UserID)
	logger = sessionCtxData.AttachToLogger(logger)

	// make sure everything's on the up-and-up
	user, httpStatus := s.validateCredentialsForUpdateRequest(
		ctx,
		sessionCtxData.Requester.UserID,
		providedInput.CurrentPassword,
		providedInput.TOTPToken,
	)

	// if the above function returns something other than 200, it means some error occurred.
	if httpStatus != http.StatusOK {
		res.WriteHeader(httpStatus)
		return
	}

	dbInput := converters.ConvertUserDetailsUpdateRequestInputToUserDetailsUpdateInput(providedInput)

	// update the user.
	updateTimer := timing.NewMetric("database").WithDesc("update").Start()
	if err = s.userDataManager.UpdateUserDetails(ctx, user.ID, dbInput); err != nil {
		observability.AcknowledgeError(err, logger, span, "updating user")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	updateTimer.Stop()

	dcm := &types.DataChangeMessage{
		EventType: types.UserDetailsChangedEventType,
		UserID:    user.ID,
	}

	if err = s.dataChangesPublisher.Publish(ctx, dcm); err != nil {
		observability.AcknowledgeError(err, logger, span, "publishing data change message")
	}

	responseValue := &types.APIResponse[*types.User]{
		Details: responseDetails,
		Data:    user,
	}

	s.encoderDecoder.EncodeResponseWithStatus(ctx, res, responseValue, http.StatusAccepted)
}

// AvatarUploadHandler updates a user's avatar.
func (s *service) AvatarUploadHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	sessionContextTimer := timing.NewMetric("session").WithDesc("fetch session context").Start()
	sessionCtxData, err := s.sessionContextDataFetcher(req)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "retrieving session context data")
		errRes := types.NewAPIErrorResponse("unauthenticated", types.ErrFetchingSessionContextData, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusUnauthorized)
		return
	}
	sessionContextTimer.Stop()

	// decode the request.
	input := new(types.AvatarUpdateInput)
	if err = s.encoderDecoder.DecodeRequest(ctx, req, input); err != nil {
		observability.AcknowledgeError(err, logger, span, "decoding request body")
		errRes := types.NewAPIErrorResponse("invalid request content", types.ErrDecodingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}

	tracing.AttachSessionContextDataToSpan(span, sessionCtxData)
	logger = sessionCtxData.AttachToLogger(logger)
	logger.Debug("session context data extracted")

	readTimer := timing.NewMetric("database").WithDesc("fetch").Start()
	user, err := s.userDataManager.GetUser(ctx, sessionCtxData.Requester.UserID)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "fetching associated user")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	readTimer.Stop()

	logger = logger.WithValue(keys.UserIDKey, user.ID)
	logger.Debug("retrieved user from database")

	updateTimer := timing.NewMetric("database").WithDesc("update").Start()
	if err = s.userDataManager.UpdateUserAvatar(ctx, user.ID, input.Base64EncodedData); err != nil {
		observability.AcknowledgeError(err, logger, span, "updating user info")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	updateTimer.Stop()

	responseValue := &types.APIResponse[*types.User]{
		Details: responseDetails,
	}

	s.encoderDecoder.EncodeResponseWithStatus(ctx, res, responseValue, http.StatusAccepted)
}

// ArchiveHandler is a handler for archiving a user.
func (s *service) ArchiveHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	sessionContextTimer := timing.NewMetric("session").WithDesc("fetch session context").Start()
	sessionCtxData, err := s.sessionContextDataFetcher(req)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "retrieving session context data")
		errRes := types.NewAPIErrorResponse("unauthenticated", types.ErrFetchingSessionContextData, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusUnauthorized)
		return
	}
	sessionContextTimer.Stop()

	// figure out who this is for.
	userID := s.userIDFetcher(req)
	logger = logger.WithValue(keys.UserIDKey, userID)
	tracing.AttachToSpan(span, keys.UserIDKey, userID)

	logger.Debug("archiving user")

	// do the deed.
	archiveTimer := timing.NewMetric("database").WithDesc("archive").Start()
	err = s.userDataManager.ArchiveUser(ctx, userID)
	if errors.Is(err, sql.ErrNoRows) {
		errRes := types.NewAPIErrorResponse("not found", types.ErrDataNotFound, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusNotFound)
		return
	} else if err != nil {
		observability.AcknowledgeError(err, logger, span, "archiving user")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	archiveTimer.Stop()

	logger.Info("user archived")

	dcm := &types.DataChangeMessage{
		AccountID: sessionCtxData.ActiveAccountID,
		EventType: types.UserArchivedCustomerEventType,
		UserID:    userID,
	}

	if err = s.dataChangesPublisher.Publish(ctx, dcm); err != nil {
		observability.AcknowledgeError(err, logger, span, "publishing data change message")
	}

	responseValue := &types.APIResponse[*types.User]{
		Details: responseDetails,
	}

	// let everybody go home.
	s.encoderDecoder.RespondWithData(ctx, res, responseValue)
}

// RequestUsernameReminderHandler checks for a user with a given email address and notifies them via email if there is a username associated with it.
func (s *service) RequestUsernameReminderHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	decodeTimer := timing.NewMetric("decode").WithDesc("decode input").Start()
	input := new(types.UsernameReminderRequestInput)
	if err := s.encoderDecoder.DecodeRequest(ctx, req, input); err != nil {
		observability.AcknowledgeError(err, logger, span, "decoding request body")
		errRes := types.NewAPIErrorResponse("invalid request content", types.ErrDecodingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}
	decodeTimer.Stop()

	if err := input.ValidateWithContext(ctx); err != nil {
		logger.WithValue(keys.ValidationErrorKey, err).Debug("invalid input attached to request")
		errRes := types.NewAPIErrorResponse(err.Error(), types.ErrValidatingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}

	readTimer := timing.NewMetric("database").WithDesc("fetch").Start()
	u, err := s.userDataManager.GetUserByEmail(ctx, input.EmailAddress)
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		errRes := types.NewAPIErrorResponse("no such user found", types.ErrDataNotFound, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusNotFound)
		return
	} else if err != nil {
		observability.AcknowledgeError(err, logger, span, "fetching user")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	readTimer.Stop()

	dcm := &types.DataChangeMessage{
		EventType: types.UsernameReminderRequestedEventType,
		UserID:    u.ID,
	}

	if err = s.dataChangesPublisher.Publish(ctx, dcm); err != nil {
		observability.AcknowledgeError(err, logger, span, "publishing data change message")
	}

	responseValue := &types.APIResponse[*types.User]{
		Details: responseDetails,
	}

	s.encoderDecoder.EncodeResponseWithStatus(ctx, res, responseValue, http.StatusAccepted)
}

// CreatePasswordResetTokenHandler rotates the cookie building secret with a new random secret.
func (s *service) CreatePasswordResetTokenHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	decodeTimer := timing.NewMetric("decode").WithDesc("decode input").Start()
	input := new(types.PasswordResetTokenCreationRequestInput)
	if err := s.encoderDecoder.DecodeRequest(ctx, req, input); err != nil {
		observability.AcknowledgeError(err, logger, span, "decoding request body")
		errRes := types.NewAPIErrorResponse("invalid request content", types.ErrDecodingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}
	decodeTimer.Stop()

	if err := input.ValidateWithContext(ctx); err != nil {
		logger.WithValue(keys.ValidationErrorKey, err).Debug("invalid input attached to request")
		errRes := types.NewAPIErrorResponse(err.Error(), types.ErrValidatingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}

	token, err := s.secretGenerator.GenerateBase32EncodedString(ctx, passwordResetTokenSize)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "generating secret")
		errRes := types.NewAPIErrorResponse("internal error", types.ErrSecretGeneration, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}

	readTimer := timing.NewMetric("database").WithDesc("fetch").Start()
	u, err := s.userDataManager.GetUserByEmail(ctx, input.EmailAddress)
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		errRes := types.NewAPIErrorResponse("user not found", types.ErrDataNotFound, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusNotFound)
		return
	} else if err != nil {
		observability.AcknowledgeError(err, logger, span, "fetching user")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	readTimer.Stop()

	dbInput := &types.PasswordResetTokenDatabaseCreationInput{
		ID:            identifiers.New(),
		Token:         token,
		BelongsToUser: u.ID,
		ExpiresAt:     time.Now().Add(30 * time.Minute),
	}

	createTimer := timing.NewMetric("database").WithDesc("create").Start()
	t, err := s.passwordResetTokenDataManager.CreatePasswordResetToken(ctx, dbInput)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "creating password reset token")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	createTimer.Stop()

	dcm := &types.DataChangeMessage{
		EventType:          types.PasswordResetTokenCreatedEventType,
		UserID:             u.ID,
		PasswordResetToken: t,
	}

	if err = s.dataChangesPublisher.Publish(ctx, dcm); err != nil {
		observability.AcknowledgeError(err, logger, span, "publishing data change message")
	}

	responseValue := &types.APIResponse[*types.User]{
		Details: responseDetails,
	}

	s.encoderDecoder.EncodeResponseWithStatus(ctx, res, responseValue, http.StatusAccepted)
}

// PasswordResetTokenRedemptionHandler rotates the cookie building secret with a new random secret.
func (s *service) PasswordResetTokenRedemptionHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	decodeTimer := timing.NewMetric("decode").WithDesc("decode input").Start()
	input := new(types.PasswordResetTokenRedemptionRequestInput)
	if err := s.encoderDecoder.DecodeRequest(ctx, req, input); err != nil {
		observability.AcknowledgeError(err, logger, span, "decoding request body")
		errRes := types.NewAPIErrorResponse("invalid request content", types.ErrDecodingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}
	decodeTimer.Stop()

	if err := input.ValidateWithContext(ctx); err != nil {
		logger.WithValue(keys.ValidationErrorKey, err).Debug("invalid input attached to request")
		errRes := types.NewAPIErrorResponse(err.Error(), types.ErrValidatingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}

	readTimer := timing.NewMetric("database").WithDesc("fetch password reset token").Start()
	t, err := s.passwordResetTokenDataManager.GetPasswordResetTokenByToken(ctx, input.Token)
	if errors.Is(err, sql.ErrNoRows) {
		errRes := types.NewAPIErrorResponse(err.Error(), types.ErrDataNotFound, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusNotFound)
		return
	} else if err != nil {
		observability.AcknowledgeError(err, logger, span, "fetching password reset token")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	readTimer.Stop()

	readTimer = timing.NewMetric("database").WithDesc("fetch user").Start()
	u, err := s.userDataManager.GetUser(ctx, t.BelongsToUser)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			errRes := types.NewAPIErrorResponse("not found", types.ErrDataNotFound, responseDetails)
			s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusNotFound)
			return
		}

		observability.AcknowledgeError(err, logger, span, "fetching user")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	readTimer.Stop()

	// ensure the password isn't garbage-tier
	if err = passwordvalidator.Validate(strings.TrimSpace(input.NewPassword), minimumPasswordEntropy); err != nil {
		logger.WithValue("password_validation_error", err).Debug("invalid password provided")
		errRes := types.NewAPIErrorResponse("new password is too weak!", types.ErrValidatingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}

	// hash the new password.
	newPasswordHash, err := s.authenticator.HashPassword(ctx, strings.TrimSpace(input.NewPassword))
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "hashing password")
		errRes := types.NewAPIErrorResponse("hashing password", types.ErrSecretGeneration, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}

	// update the user.
	updateTimer := timing.NewMetric("database").WithDesc("update").Start()
	if err = s.userDataManager.UpdateUserPassword(ctx, u.ID, newPasswordHash); err != nil {
		observability.AcknowledgeError(err, logger, span, "updating user")
		if errors.Is(err, sql.ErrNoRows) {
			errRes := types.NewAPIErrorResponse("not found", types.ErrDataNotFound, responseDetails)
			s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusNotFound)
			return
		}

		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	updateTimer.Stop()

	redeemTimer := timing.NewMetric("database").WithDesc("redeem password reset token").Start()
	if redemptionErr := s.passwordResetTokenDataManager.RedeemPasswordResetToken(ctx, t.ID); redemptionErr != nil {
		observability.AcknowledgeError(err, logger, span, "redeeming password reset token")
		if errors.Is(err, sql.ErrNoRows) {
			errRes := types.NewAPIErrorResponse("not found", types.ErrDataNotFound, responseDetails)
			s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusNotFound)
			return
		}

		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	redeemTimer.Stop()

	dcm := &types.DataChangeMessage{
		EventType: types.PasswordResetTokenRedeemedEventType,
		UserID:    t.BelongsToUser,
	}

	if err = s.dataChangesPublisher.Publish(ctx, dcm); err != nil {
		observability.AcknowledgeError(err, logger, span, "publishing data change message")
	}

	responseValue := &types.APIResponse[*types.User]{
		Details: responseDetails,
	}

	s.encoderDecoder.EncodeResponseWithStatus(ctx, res, responseValue, http.StatusAccepted)
}

// VerifyUserEmailAddressHandler checks for a user with a given email address and notifies them via email if there is a username associated with it.
func (s *service) VerifyUserEmailAddressHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	decodeTimer := timing.NewMetric("decode").WithDesc("decode input").Start()
	input := new(types.EmailAddressVerificationRequestInput)
	if err := s.encoderDecoder.DecodeRequest(ctx, req, input); err != nil {
		observability.AcknowledgeError(err, logger, span, "decoding request body")
		errRes := types.NewAPIErrorResponse("invalid request content", types.ErrDecodingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}
	decodeTimer.Stop()

	if err := input.ValidateWithContext(ctx); err != nil {
		logger.WithValue(keys.ValidationErrorKey, err).Debug("invalid input attached to request")
		errRes := types.NewAPIErrorResponse(err.Error(), types.ErrValidatingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}

	readTimer := timing.NewMetric("database").WithDesc("fetch").Start()
	user, err := s.userDataManager.GetUserByEmailAddressVerificationToken(ctx, input.Token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			errRes := types.NewAPIErrorResponse("not found", types.ErrDataNotFound, responseDetails)
			s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusNotFound)
			return
		}

		observability.AcknowledgeError(err, logger, span, "fetching user")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	readTimer.Stop()

	if err = s.userDataManager.MarkUserEmailAddressAsVerified(ctx, user.ID, input.Token); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			errRes := types.NewAPIErrorResponse("not found", types.ErrDataNotFound, responseDetails)
			s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusNotFound)
			return
		}

		observability.AcknowledgeError(err, logger, span, "marking user email as verified")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}

	dcm := &types.DataChangeMessage{
		EventType: types.UserEmailAddressVerifiedEventType,
		UserID:    user.ID,
	}

	if err = s.dataChangesPublisher.Publish(ctx, dcm); err != nil {
		observability.AcknowledgeError(err, logger, span, "publishing data change message")
	}

	responseValue := &types.APIResponse[*types.User]{
		Details: responseDetails,
	}

	s.encoderDecoder.EncodeResponseWithStatus(ctx, res, responseValue, http.StatusAccepted)
}

// RequestEmailVerificationEmailHandler submits a request for an email verification email.
func (s *service) RequestEmailVerificationEmailHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	sessionContextTimer := timing.NewMetric("session").WithDesc("fetch session context").Start()
	sessionCtxData, err := s.sessionContextDataFetcher(req)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "retrieving session context data")
		errRes := types.NewAPIErrorResponse("unauthenticated", types.ErrFetchingSessionContextData, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusUnauthorized)
		return
	}
	sessionContextTimer.Stop()

	readTimer := timing.NewMetric("database").WithDesc("fetch").Start()
	verificationToken, err := s.userDataManager.GetEmailAddressVerificationTokenForUser(ctx, sessionCtxData.Requester.UserID)
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, nil, http.StatusAccepted)
		return
	} else if err != nil {
		observability.AcknowledgeError(err, logger, span, "fetching email address verification token")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	readTimer.Stop()

	dcm := &types.DataChangeMessage{
		EventType:              types.UserEmailAddressVerificationEmailRequestedEventType,
		UserID:                 sessionCtxData.Requester.UserID,
		EmailVerificationToken: verificationToken,
	}

	if err = s.dataChangesPublisher.Publish(ctx, dcm); err != nil {
		observability.AcknowledgeError(err, logger, span, "publishing data change message")
	}

	responseValue := &types.APIResponse[*types.User]{
		Details: responseDetails,
	}

	s.encoderDecoder.EncodeResponseWithStatus(ctx, res, responseValue, http.StatusAccepted)
}
