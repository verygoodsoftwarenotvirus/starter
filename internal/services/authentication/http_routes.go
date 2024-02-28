package authentication

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/verygoodsoftwarenotvirus/starter/internal/authentication"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"

	"github.com/gorilla/securecookie"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	servertiming "github.com/mitchellh/go-server-timing"
)

var (
	customCookieDomainHeader = "X-SERVICE-COOKIE-DOMAIN"

	allowedCookiesHat    sync.Mutex
	allowedCookieDomains = map[string]uint{
		".whatever.local": 0,
		".whatever.dev":   1,
		".whatever.com":   2,
	}
)

// determineCookieDomain determines which domain to assign a cookie.
func (s *service) determineCookieDomain(ctx context.Context, req *http.Request) string {
	_, span := s.tracer.StartSpan(ctx)
	defer span.End()

	requestedCookieDomain := s.config.Cookies.Domain
	if headerCookieDomain := req.Header.Get(customCookieDomainHeader); headerCookieDomain != "" {
		allowedCookiesHat.Lock()
		// if the requested domain is present in the map, and it has a lower score than the current domain, then
		if currentScore, ok1 := allowedCookieDomains[requestedCookieDomain]; ok1 {
			if newScore, ok2 := allowedCookieDomains[headerCookieDomain]; ok2 {
				if currentScore > newScore {
					requestedCookieDomain = headerCookieDomain
				}
			}
		}
		allowedCookiesHat.Unlock()
	}

	return requestedCookieDomain
}

// BuildLoginHandler is our login route.
func (s *service) BuildLoginHandler(adminOnly bool) func(http.ResponseWriter, *http.Request) {
	return func(res http.ResponseWriter, req *http.Request) {
		ctx, span := s.tracer.StartSpan(req.Context())
		defer span.End()

		timing := servertiming.FromContext(ctx)
		logger := s.logger.WithRequest(req).WithSpan(span)
		tracing.AttachRequestToSpan(span, req)

		responseDetails := types.ResponseDetails{
			TraceID: span.SpanContext().TraceID().String(),
		}

		if adminOnly {
			logger = logger.WithValue("admin_only", adminOnly)
		}

		loginData := new(types.UserLoginInput)
		if err := s.encoderDecoder.DecodeRequest(ctx, req, loginData); err != nil {
			observability.AcknowledgeError(err, logger, span, "decoding request body")
			errRes := types.NewAPIErrorResponse("invalid request content", types.ErrDecodingRequestInput, responseDetails)
			s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
			return
		}

		loginData.TOTPToken = strings.TrimSpace(loginData.TOTPToken)
		loginData.Password = strings.TrimSpace(loginData.Password)
		loginData.Username = strings.TrimSpace(loginData.Username)

		if err := loginData.ValidateWithContext(ctx, s.config.MinimumUsernameLength, s.config.MinimumPasswordLength); err != nil {
			observability.AcknowledgeError(err, logger, span, "validating input")
			errRes := types.NewAPIErrorResponse("invalid login body", types.ErrValidatingRequestInput, responseDetails)
			s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
			return
		}

		logger = logger.WithValue(keys.UsernameKey, loginData.Username)

		requestedCookieDomain := s.determineCookieDomain(ctx, req)
		if requestedCookieDomain != "" {
			logger = logger.WithValue("cookie_domain", requestedCookieDomain)
		}

		userFunc := s.userDataManager.GetUserByUsername
		if adminOnly {
			userFunc = s.userDataManager.GetAdminUserByUsername
		}

		readTimer := timing.NewMetric("database").WithDesc("fetch").Start()
		user, err := userFunc(ctx, loginData.Username)
		if err != nil || user == nil {
			observability.AcknowledgeError(err, logger, span, "fetching user")
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

		logger = logger.WithValue(keys.UserIDKey, user.ID)
		tracing.AttachUserToSpan(span, user)

		if user.IsBanned() {
			errRes := types.NewAPIErrorResponse("user is banned", types.ErrUserIsBanned, responseDetails)
			s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusForbidden)
			return
		}

		loginValid, err := s.validateLogin(ctx, user, loginData)
		logger.WithValue("login_valid", loginValid)

		if err != nil {
			if errors.Is(err, authentication.ErrInvalidTOTPToken) {
				observability.AcknowledgeError(err, logger, span, "validating TOTP token")
				errRes := types.NewAPIErrorResponse("login was invalid", types.ErrValidatingRequestInput, responseDetails)
				s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusUnauthorized)
				return
			}

			if errors.Is(err, authentication.ErrPasswordDoesNotMatch) {
				observability.AcknowledgeError(err, logger, span, "validating password")
				errRes := types.NewAPIErrorResponse("login was invalid", types.ErrValidatingRequestInput, responseDetails)
				s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusUnauthorized)
				return
			}

			observability.AcknowledgeError(err, logger, span, "validating login")
			errRes := types.NewAPIErrorResponse(staticError, types.ErrValidatingRequestInput, responseDetails)
			s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
			return
		} else if !loginValid {
			logger.Debug("login was invalid")
			s.encoderDecoder.EncodeErrorResponse(ctx, res, "login was invalid", http.StatusUnauthorized)
			return
		}

		if loginValid && user.TwoFactorSecretVerifiedAt != nil && loginData.TOTPToken == "" {
			logger.Debug("user with two factor verification active attempted to log in without providing TOTP")
			errRes := types.NewAPIErrorResponse("TOTP required", types.ErrValidatingRequestInput, responseDetails)
			s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusResetContent)
			return
		}

		defaultAccountID, err := s.accountMembershipManager.GetDefaultAccountIDForUser(ctx, user.ID)
		if err != nil {
			observability.AcknowledgeError(err, logger, span, "fetching user memberships")
			errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
			s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
			return
		}

		responseCode, err := s.postLogin(ctx, user, defaultAccountID, req, res)
		if err != nil {
			observability.AcknowledgeError(err, logger, span, "handling login status")
			errRes := types.NewAPIErrorResponse(staticError, types.ErrTalkingToDatabase, responseDetails)
			s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, responseCode)
			return
		}

		statusResponse := &types.UserStatusResponse{
			UserID:                   user.ID,
			UserIsAuthenticated:      true,
			AccountStatus:            user.AccountStatus,
			ActiveAccount:            defaultAccountID,
			AccountStatusExplanation: user.AccountStatusExplanation,
		}

		responseValue := &types.APIResponse[*types.UserStatusResponse]{
			Details: responseDetails,
			Data:    statusResponse,
		}

		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, responseValue, responseCode)
		logger.Debug("user logged in")
	}
}

func (s *service) postLogin(ctx context.Context, user *types.User, defaultAccountID string, req *http.Request, res http.ResponseWriter) (int, error) {
	ctx, span := s.tracer.StartSpan(ctx)
	defer span.End()

	requestedCookieDomain := s.determineCookieDomain(ctx, req)

	cookie, err := s.issueSessionManagedCookie(ctx, defaultAccountID, user.ID, requestedCookieDomain)
	if err != nil {
		return http.StatusInternalServerError, observability.PrepareError(err, span, "issuing cookie")
	}

	http.SetCookie(res, cookie)

	dcm := &types.DataChangeMessage{
		EventType: types.UserLoggedInCustomerEventType,
		AccountID: defaultAccountID,
		UserID:    user.ID,
	}

	if err = s.dataChangesPublisher.Publish(ctx, dcm); err != nil {
		observability.AcknowledgeError(err, s.logger, span, "publishing data change message")
		return http.StatusAccepted, nil
	}

	if err = s.analyticsReporter.AddUser(ctx, user.ID, map[string]any{
		"username":        user.Username,
		"default_account": defaultAccountID,
		"first_name":      user.FirstName,
		"last_name":       user.LastName,
	}); err != nil {
		return http.StatusAccepted, observability.PrepareError(err, span, "identifying user for analytics")
	}

	if err = s.featureFlagManager.Identify(ctx, user); err != nil {
		return http.StatusAccepted, observability.PrepareError(err, span, "identifying user in feature flag manager")
	}

	return http.StatusAccepted, nil
}

func (s *service) SSOLoginHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	providerName := s.authProviderFetcher(req)
	if providerName == "" {
		errRes := types.NewAPIErrorResponse("provider name is missing", types.ErrValidatingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}

	provider, err := goth.GetProvider(providerName)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "getting provider")
		s.encoderDecoder.EncodeErrorResponse(ctx, res, "provider is not supported", http.StatusBadRequest)
		return
	}

	sess, err := provider.BeginAuth(gothic.SetState(req))
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "beginning auth")
		s.encoderDecoder.EncodeErrorResponse(ctx, res, "failed to begin auth", http.StatusInternalServerError)
		return
	}

	loadSessionTimer := timing.NewMetric("session manager").WithDesc("load").Start()
	ctx, err = s.sessionManager.Load(ctx, providerName)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "loading session")
		s.encoderDecoder.EncodeErrorResponse(ctx, res, "failed to load session", http.StatusInternalServerError)
		return
	}
	loadSessionTimer.Stop()

	s.sessionManager.Put(ctx, providerName, sess.Marshal())

	u, err := sess.GetAuthURL()
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "getting auth url")
		s.encoderDecoder.EncodeErrorResponse(ctx, res, "failed to get auth url", http.StatusInternalServerError)
		return
	}

	res.Header().Set("Content-type", "application/json")
	http.Redirect(res, req, u, http.StatusTemporaryRedirect)
}

func (s *service) SSOLoginCallbackHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	providerName := s.authProviderFetcher(req)
	if providerName == "" {
		errRes := types.NewAPIErrorResponse("provider name is missing", types.ErrValidatingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}

	provider, err := goth.GetProvider(providerName)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "getting provider")
		s.encoderDecoder.EncodeErrorResponse(ctx, res, "provider is not supported", http.StatusBadRequest)
		return
	}

	rawValue := s.sessionManager.Get(ctx, providerName)
	value, ok := rawValue.(string)
	if !ok {
		s.encoderDecoder.EncodeErrorResponse(ctx, res, "failed to get session", http.StatusInternalServerError)
		return
	}

	sess, err := provider.UnmarshalSession(value)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "unmarshalling session")
		s.encoderDecoder.EncodeErrorResponse(ctx, res, "failed to unmarshal session", http.StatusInternalServerError)
		return
	}

	if err = validateState(req, sess); err != nil {
		observability.AcknowledgeError(err, logger, span, "validating state")
		s.encoderDecoder.EncodeErrorResponse(ctx, res, "failed to validate state", http.StatusInternalServerError)
		return
	}

	fetchUserTimer := timing.NewMetric("database").WithDesc("fetch").Start()
	providedUser, err := provider.FetchUser(sess)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "fetching user")
		s.encoderDecoder.EncodeErrorResponse(ctx, res, "failed to fetch user", http.StatusInternalServerError)
		return
	}
	fetchUserTimer.Stop()

	params := req.URL.Query()
	if params.Encode() == "" && req.Method == "POST" {
		if err = req.ParseForm(); err != nil {
			observability.AcknowledgeError(err, logger, span, "parsing form")
		}
		params = req.Form
	}

	// get new token and retry fetch
	if _, err = sess.Authorize(provider, params); err != nil {
		observability.AcknowledgeError(err, logger, span, "authorizing session")
		s.encoderDecoder.EncodeErrorResponse(ctx, res, "failed to authorize session", http.StatusInternalServerError)
		return
	}

	getUserTimer := timing.NewMetric("database").WithDesc("get user by email").Start()
	user, err := s.userDataManager.GetUserByEmail(ctx, providedUser.Email)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "getting user by email")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	getUserTimer.Stop()

	defaultAccountTimer := timing.NewMetric("database").WithDesc("get default account for user").Start()
	defaultAccountID, err := s.accountMembershipManager.GetDefaultAccountIDForUser(ctx, user.ID)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "fetching user memberships")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}
	defaultAccountTimer.Stop()

	responseCode, err := s.postLogin(ctx, user, defaultAccountID, req, res)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "handling login status")
		s.encoderDecoder.EncodeErrorResponse(ctx, res, staticError, responseCode)
		return
	}

	statusResponse := &types.UserStatusResponse{
		UserID:                   user.ID,
		UserIsAuthenticated:      true,
		AccountStatus:            user.AccountStatus,
		ActiveAccount:            defaultAccountID,
		AccountStatusExplanation: user.AccountStatusExplanation,
	}

	s.encoderDecoder.EncodeResponseWithStatus(ctx, res, statusResponse, responseCode)
	logger.Debug("user logged in via SSO")
}

// validateState ensures that the state token param from the original.
func validateState(req *http.Request, sess goth.Session) error {
	rawAuthURL, err := sess.GetAuthURL()
	if err != nil {
		return err
	}

	authURL, err := url.Parse(rawAuthURL)
	if err != nil {
		return err
	}

	reqState := gothic.GetState(req)

	originalState := authURL.Query().Get("state")
	if originalState != "" && (originalState != reqState) {
		return errors.New("state token mismatch")
	}
	return nil
}

// ChangeActiveAccountHandler is our login route.
func (s *service) ChangeActiveAccountHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	// determine user ID.
	sessionContextTimer := timing.NewMetric("session").WithDesc("fetch session context").Start()
	sessionCtxData, err := s.sessionContextDataFetcher(req)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "fetching session context data")
		errRes := types.NewAPIErrorResponse("unauthenticated", types.ErrFetchingSessionContextData, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusUnauthorized)
		return
	}
	sessionContextTimer.Stop()

	tracing.AttachSessionContextDataToSpan(span, sessionCtxData)
	logger = sessionCtxData.AttachToLogger(logger)
	responseDetails.CurrentAccountID = sessionCtxData.ActiveAccountID

	input := new(types.ChangeActiveAccountInput)
	if err = s.encoderDecoder.DecodeRequest(ctx, req, input); err != nil {
		observability.AcknowledgeError(err, logger, span, "decoding request body")
		errRes := types.NewAPIErrorResponse("invalid request content", types.ErrDecodingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}

	if err = input.ValidateWithContext(ctx); err != nil {
		logger.WithValue(keys.ValidationErrorKey, err).Debug("invalid input attached to request")
		errRes := types.NewAPIErrorResponse(err.Error(), types.ErrValidatingRequestInput, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusBadRequest)
		return
	}

	accountID := input.AccountID
	logger = logger.WithValue("new_session_account_id", accountID)

	requesterID := sessionCtxData.Requester.UserID
	logger = logger.WithValue("user_id", requesterID)

	authorizedForAccount, err := s.accountMembershipManager.UserIsMemberOfAccount(ctx, requesterID, accountID)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "checking permissions")
		errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}

	if !authorizedForAccount {
		logger.Debug("invalid account ID requested for activation")
		errRes := types.NewAPIErrorResponse("unauthenticated", types.ErrFetchingSessionContextData, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusUnauthorized)
		return
	}

	requestedCookieDomain := s.determineCookieDomain(ctx, req)
	if requestedCookieDomain != "" {
		logger = logger.WithValue("cookie_domain", requestedCookieDomain)
	}

	cookie, err := s.issueSessionManagedCookie(ctx, accountID, requesterID, requestedCookieDomain)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "issuing cookie")
		errRes := types.NewAPIErrorResponse(staticError, types.ErrNothingSpecific, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}

	dcm := &types.DataChangeMessage{
		EventType: types.UserChangedActiveAccountCustomerEventType,
		Context: map[string]any{
			"old_account_id": sessionCtxData.ActiveAccountID,
		},
		AccountID: accountID,
		UserID:    sessionCtxData.Requester.UserID,
	}

	if err = s.dataChangesPublisher.Publish(ctx, dcm); err != nil {
		observability.AcknowledgeError(err, logger, span, "publishing data change message")
	}

	logger.Info("successfully changed active session account")
	http.SetCookie(res, cookie)

	responseValue := &types.APIResponse[*types.UserStatusResponse]{
		Details: responseDetails,
	}

	// let everybody go home.
	s.encoderDecoder.EncodeResponseWithStatus(ctx, res, responseValue, http.StatusAccepted)
}

// EndSessionHandler is our logout route.
func (s *service) EndSessionHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	// determine user ID.
	sessionContextTimer := timing.NewMetric("session").WithDesc("fetch session context").Start()
	sessionCtxData, err := s.sessionContextDataFetcher(req)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "fetching session context data")
		errRes := types.NewAPIErrorResponse("unauthenticated", types.ErrFetchingSessionContextData, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusUnauthorized)
		return
	}
	sessionContextTimer.Stop()

	tracing.AttachSessionContextDataToSpan(span, sessionCtxData)
	logger = sessionCtxData.AttachToLogger(logger)
	responseDetails.CurrentAccountID = sessionCtxData.ActiveAccountID

	ctx, loadErr := s.sessionManager.Load(ctx, "")
	if loadErr != nil {
		// this can literally never happen in this version of scs, because the token is empty
		observability.AcknowledgeError(loadErr, logger, span, "loading token")
		errRes := types.NewAPIErrorResponse("error", types.ErrMisbehavingDependency, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}

	if destroyErr := s.sessionManager.Destroy(ctx); destroyErr != nil {
		observability.AcknowledgeError(destroyErr, logger, span, "destroying session")
		errRes := types.NewAPIErrorResponse("error", types.ErrMisbehavingDependency, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}

	requestedCookieDomain := s.determineCookieDomain(ctx, req)
	if requestedCookieDomain != "" {
		logger = logger.WithValue("cookie_domain", requestedCookieDomain)
	}

	newCookie, cookieBuildingErr := s.buildLogoutCookie(ctx, req)
	if cookieBuildingErr != nil || newCookie == nil {
		observability.AcknowledgeError(cookieBuildingErr, logger, span, "building cookie")
		errRes := types.NewAPIErrorResponse("building cookie", types.ErrMisbehavingDependency, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
		return
	}

	http.SetCookie(res, newCookie)

	dcm := &types.DataChangeMessage{
		EventType: types.UserLoggedOutCustomerEventType,
		UserID:    sessionCtxData.Requester.UserID,
	}

	if dataPublishErr := s.dataChangesPublisher.Publish(ctx, dcm); dataPublishErr != nil {
		observability.AcknowledgeError(dataPublishErr, logger, span, "publishing data change message")
	}

	logger.Debug("user logged out")

	responseValue := &types.APIResponse[*types.UserStatusResponse]{
		Details: responseDetails,
	}

	// let everybody go home.
	s.encoderDecoder.EncodeResponseWithStatus(ctx, res, responseValue, http.StatusAccepted)
}

// StatusHandler returns the user info for the user making the request.
func (s *service) StatusHandler(res http.ResponseWriter, req *http.Request) {
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
		observability.AcknowledgeError(err, logger, span, "fetching session context data")
		errRes := types.NewAPIErrorResponse("unauthenticated", types.ErrFetchingSessionContextData, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusUnauthorized)
		return
	}
	sessionContextTimer.Stop()

	tracing.AttachSessionContextDataToSpan(span, sessionCtxData)
	responseDetails.CurrentAccountID = sessionCtxData.ActiveAccountID

	statusResponse := &types.UserStatusResponse{
		ActiveAccount:            sessionCtxData.ActiveAccountID,
		AccountStatus:            sessionCtxData.Requester.AccountStatus,
		AccountStatusExplanation: sessionCtxData.Requester.AccountStatusExplanation,
		UserIsAuthenticated:      true,
	}

	responseValue := &types.APIResponse[*types.UserStatusResponse]{
		Details: responseDetails,
		Data:    statusResponse,
	}

	s.encoderDecoder.RespondWithData(ctx, res, responseValue)
}

// CycleCookieSecretHandler rotates the cookie building secret with a new random secret.
func (s *service) CycleCookieSecretHandler(res http.ResponseWriter, req *http.Request) {
	ctx, span := s.tracer.StartSpan(req.Context())
	defer span.End()

	timing := servertiming.FromContext(ctx)
	logger := s.logger.WithRequest(req).WithSpan(span)
	tracing.AttachRequestToSpan(span, req)

	responseDetails := types.ResponseDetails{
		TraceID: span.SpanContext().TraceID().String(),
	}

	logger.Info("cycling cookie secret!")

	// determine user ID.
	sessionContextTimer := timing.NewMetric("session").WithDesc("fetch session context").Start()
	sessionCtxData, err := s.sessionContextDataFetcher(req)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "fetching session context data")
		errRes := types.NewAPIErrorResponse("unauthenticated", types.ErrFetchingSessionContextData, responseDetails)
		s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusUnauthorized)
		return
	}
	sessionContextTimer.Stop()

	tracing.AttachSessionContextDataToSpan(span, sessionCtxData)
	logger = sessionCtxData.AttachToLogger(logger)
	responseDetails.CurrentAccountID = sessionCtxData.ActiveAccountID

	if !sessionCtxData.Requester.ServicePermissions.CanCycleCookieSecrets() {
		logger.Debug("invalid permissions")
		s.encoderDecoder.EncodeInvalidPermissionsResponse(ctx, res)
		return
	}

	s.cookieManager = securecookie.New(
		securecookie.GenerateRandomKey(cookieSecretSize),
		[]byte(s.config.Cookies.BlockKey),
	)

	res.WriteHeader(http.StatusAccepted)
}

var _ types.OAuth2Service = (*service)(nil)

// AuthorizeHandler is our oauth2 auth route.
func (s *service) AuthorizeHandler(res http.ResponseWriter, req *http.Request) {
	if err := s.oauth2Server.HandleAuthorizeRequest(res, req); err != nil {
		http.Error(res, err.Error(), http.StatusBadRequest)
	}
}

func (s *service) TokenHandler(res http.ResponseWriter, req *http.Request) {
	if err := s.oauth2Server.HandleTokenRequest(res, req); err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
	}
}
