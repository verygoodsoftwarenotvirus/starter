package authentication

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/verygoodsoftwarenotvirus/starter/internal/authentication"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

var (
	errNoUserIDFoundInSession = errors.New("no user ID found in session")
)

func (s *service) overrideSessionContextDataValuesWithSessionData(ctx context.Context, sessionCtxData *types.SessionContextData) {
	ctx, span := s.tracer.StartSpan(ctx)
	defer span.End()

	if activeAccount, ok := s.sessionManager.Get(ctx, accountIDContextKey).(string); ok {
		sessionCtxData.ActiveAccountID = activeAccount
	}
}

// getUserIDFromCookie takes a request object and fetches the cookie data if it is present.
func (s *service) getUserIDFromCookie(ctx context.Context, req *http.Request) (context.Context, string, error) {
	ctx, span := s.tracer.StartSpan(ctx)
	defer span.End()

	logger := s.logger.WithRequest(req).WithSpan(span).WithValue("cookie", req.Header[s.config.Cookies.Name])

	if cookie, cookieErr := req.Cookie(s.config.Cookies.Name); !errors.Is(cookieErr, http.ErrNoCookie) && cookie != nil {
		var (
			token string
			err   error
		)

		if err = s.cookieManager.Decode(s.config.Cookies.Name, cookie.Value, &token); err != nil {
			return nil, "", observability.PrepareError(err, span, "retrieving session context data")
		}

		ctx, err = s.sessionManager.Load(ctx, token)
		if err != nil {
			return nil, "", observability.PrepareError(err, span, "loading session")
		}

		if userID, ok := s.sessionManager.Get(ctx, userIDContextKey).(string); ok {
			logger.WithValue(keys.UserIDKey, userID).Debug("determined userID from request cookie")
			return ctx, userID, nil
		}

		return nil, "", observability.PrepareAndLogError(errNoUserIDFoundInSession, logger, span, "determining user ID from cookie")
	}

	return nil, "", http.ErrNoCookie
}

// validateLogin takes login information and returns whether the login is valid.
// In the event that there's an error, this function will return false and the error.
func (s *service) validateLogin(ctx context.Context, user *types.User, loginInput *types.UserLoginInput) (bool, error) {
	ctx, span := s.tracer.StartSpan(ctx)
	defer span.End()

	// alias the relevant data.
	logger := s.logger.WithValue(keys.UsernameKey, user.Username)

	// check for login validity.
	loginValid, err := s.authenticator.CredentialsAreValid(
		ctx,
		user.HashedPassword,
		loginInput.Password,
		user.TwoFactorSecret,
		loginInput.TOTPToken,
	)

	if errors.Is(err, authentication.ErrInvalidTOTPToken) || errors.Is(err, authentication.ErrPasswordDoesNotMatch) {
		return false, err
	}

	if err != nil {
		return false, observability.PrepareError(err, span, "validating login")
	}

	logger.Debug("login validated")

	return loginValid, nil
}

func (s *service) issueSessionManagedCookie(ctx context.Context, accountID, requesterID, cookieDomain string) (cookie *http.Cookie, err error) {
	ctx, span := s.tracer.StartSpan(ctx)
	defer span.End()

	logger := s.logger.Clone()

	ctx, err = s.sessionManager.Load(ctx, "")
	if err != nil {
		// this will never happen while token is empty.
		observability.AcknowledgeError(err, logger, span, "loading token")
		return nil, err
	}

	if err = s.sessionManager.RenewToken(ctx); err != nil {
		observability.AcknowledgeError(err, logger, span, "renewing token")
		return nil, err
	}

	s.sessionManager.Put(ctx, accountIDContextKey, accountID)
	s.sessionManager.Put(ctx, userIDContextKey, requesterID)

	token, expiry, err := s.sessionManager.Commit(ctx)
	if err != nil {
		// this branch cannot be tested because I cannot anticipate what the values committed will be
		observability.AcknowledgeError(err, logger, span, "writing to session store")
		return nil, err
	}

	cookie, err = s.buildCookie(ctx, cookieDomain, token, expiry)
	if err != nil {
		observability.AcknowledgeError(err, logger, span, "building cookie")
		return nil, err
	}

	return cookie, nil
}

func (s *service) buildLogoutCookie(ctx context.Context, req *http.Request) (*http.Cookie, error) {
	ctx, span := s.tracer.StartSpan(ctx)
	defer span.End()

	logger := s.logger.WithRequest(req).WithSpan(span)

	requestedCookieDomain := s.determineCookieDomain(ctx, req)
	if requestedCookieDomain != "" {
		logger = logger.WithValue("cookie_domain", requestedCookieDomain)
	}

	newCookie, cookieBuildingErr := s.buildCookie(ctx, requestedCookieDomain, "deleted", time.Time{})
	if cookieBuildingErr != nil || newCookie == nil {
		return nil, observability.PrepareAndLogError(cookieBuildingErr, logger, span, "building cookie")
	}

	newCookie.MaxAge = -1

	return newCookie, nil
}

// buildCookie provides a consistent way of constructing an HTTP cookie.
func (s *service) buildCookie(ctx context.Context, cookieDomain, value string, expiry time.Time) (*http.Cookie, error) {
	_, span := s.tracer.StartSpan(ctx)
	defer span.End()

	encoded, err := s.cookieManager.Encode(s.config.Cookies.Name, value)
	if err != nil {
		// NOTE: these errors should be infrequent, and should cause alarm when they do occur
		s.logger.WithName(cookieErrorLogName).Error(err, "error encoding cookie")
		return nil, err
	}

	// https://www.calhoun.io/securing-cookies-in-go/
	cookie := &http.Cookie{
		Name:     s.config.Cookies.Name,
		Value:    encoded,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.config.Cookies.SecureOnly,
		Domain:   cookieDomain,
		Expires:  expiry,
		SameSite: http.SameSiteNoneMode,
		MaxAge:   int(time.Until(expiry).Seconds()),
	}

	return cookie, nil
}
