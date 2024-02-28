package authentication

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/verygoodsoftwarenotvirus/starter/internal/authorization"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"

	servertiming "github.com/mitchellh/go-server-timing"
)

// CookieRequirementMiddleware requires every request have a valid cookie.
func (s *service) CookieRequirementMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		ctx, span := s.tracer.StartSpan(req.Context())
		defer span.End()

		timing := servertiming.FromContext(ctx)
		logger := s.logger.WithRequest(req).WithSpan(span)

		cookieFetchTimer := timing.NewMetric("cookie fetch").WithDesc("decoding cookie from request").Start()
		cookie, cookieErr := req.Cookie(s.config.Cookies.Name)
		cookieFetchTimer.Stop()
		if !errors.Is(cookieErr, http.ErrNoCookie) && cookie != nil {
			var token string
			if err := s.cookieManager.Decode(s.config.Cookies.Name, cookie.Value, &token); err == nil {
				next.ServeHTTP(res, req)
				return
			} else {
				observability.AcknowledgeError(err, logger, span, "decoding cookie")
			}
		}

		logger.Info("no cookie attached to request")

		// if no cookie was attached to the request, tell them to login first.
		res.WriteHeader(http.StatusUnauthorized)
	})
}

// UserAttributionMiddleware is concerned with figuring out who a user is, but not worried about kicking out users who are not known.
func (s *service) UserAttributionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		ctx, span := s.tracer.StartSpan(req.Context())
		defer span.End()

		timing := servertiming.FromContext(ctx)
		logger := s.logger.WithRequest(req).WithSpan(span).WithValue("cookie", req.Header[s.config.Cookies.Name])
		for _, cookie := range req.Cookies() {
			logger = logger.WithValue(fmt.Sprintf("cookie.%s", cookie.Name), cookie.Value)
		}

		responseDetails := types.ResponseDetails{
			TraceID: span.SpanContext().TraceID().String(),
		}

		// handle cookies if relevant.
		cookieTimer := timing.NewMetric("cookie fetch").WithDesc("decoding cookie from request").Start()
		cookieContext, userID, err := s.getUserIDFromCookie(ctx, req)
		cookieTimer.Stop()
		if err == nil && userID != "" {
			ctx = cookieContext

			tracing.AttachToSpan(span, keys.RequesterIDKey, userID)
			logger = logger.WithValue(keys.RequesterIDKey, userID)

			sessionCtxData, sessionCtxDataErr := s.accountMembershipManager.BuildSessionContextDataForUser(ctx, userID)
			if sessionCtxDataErr != nil {
				observability.AcknowledgeError(sessionCtxDataErr, logger, span, "fetching user info for cookie")
				errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
				s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
				return
			}

			s.overrideSessionContextDataValuesWithSessionData(ctx, sessionCtxData)

			next.ServeHTTP(res, req.WithContext(context.WithValue(ctx, types.SessionContextDataKey, sessionCtxData)))
			return
		}

		// validate bearer token.
		tokenTimer := timing.NewMetric("token validation").WithDesc("validating bearer token from request").Start()
		token, err := s.oauth2Server.ValidationBearerToken(req)
		if err != nil {
			s.logger.Error(err, "determining user ID")
		}
		tokenTimer.Stop()

		if token != nil {
			if userID = token.GetUserID(); userID != "" {
				userAttributionTimer := timing.NewMetric("user attribution").WithDesc("attributing user to request").Start()
				sessionCtxData, sessionCtxDataErr := s.accountMembershipManager.BuildSessionContextDataForUser(ctx, userID)
				if sessionCtxDataErr != nil {
					observability.AcknowledgeError(sessionCtxDataErr, logger, span, "fetching user info for cookie")
					errRes := types.NewAPIErrorResponse("database error", types.ErrTalkingToDatabase, responseDetails)
					s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusInternalServerError)
					return
				}
				userAttributionTimer.Stop()

				if sessionCtxData != nil {
					next.ServeHTTP(res, req.WithContext(context.WithValue(ctx, types.SessionContextDataKey, sessionCtxData)))
					return
				}
			}
		}

		next.ServeHTTP(res, req)
	})
}

// AuthorizationMiddleware checks to see if a user is associated with the request, and then determines whether said request can proceed.
func (s *service) AuthorizationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		_, span := s.tracer.StartSpan(req.Context())
		defer span.End()

		logger := s.logger.WithRequest(req).WithSpan(span)

		// UserAttributionMiddleware should be called before this middleware.
		if sessionCtxData, err := s.sessionContextDataFetcher(req); err == nil && sessionCtxData != nil {
			tracing.AttachSessionContextDataToSpan(span, sessionCtxData)
			logger = sessionCtxData.AttachToLogger(logger)

			if sessionCtxData.Requester.AccountStatus == string(types.BannedUserAccountStatus) || sessionCtxData.Requester.AccountStatus == string(types.TerminatedUserAccountStatus) {
				logger.Info("banned user attempted to make request")
				http.Redirect(res, req, "/", http.StatusForbidden)
				return
			}

			if _, authorizedForAccount := sessionCtxData.AccountPermissions[sessionCtxData.ActiveAccountID]; !authorizedForAccount {
				logger.Info("user trying to access account they are not authorized for")
				http.Redirect(res, req, "/", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(res, req)
			return
		}

		logger.Info("no user attached to request")
		http.Redirect(res, req, "/users/login", http.StatusUnauthorized)
	})
}

// PermissionFilterMiddleware filters users out of requests based on provided functions.
func (s *service) PermissionFilterMiddleware(permissions ...authorization.Permission) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			ctx, span := s.tracer.StartSpan(req.Context())
			defer span.End()

			timing := servertiming.FromContext(ctx)
			logger := s.logger.WithRequest(req).WithSpan(span)
			logger.Debug("checking permissions in middleware")

			// check for a session context data first.
			sessionContextData, err := s.sessionContextDataFetcher(req)
			if err != nil {
				observability.AcknowledgeError(err, logger, span, "retrieving session context data")
				s.encoderDecoder.EncodeUnauthorizedResponse(ctx, res)
				return
			}

			permissionCheckTimer := timing.NewMetric("permissions check").WithDesc("checking user permissions").Start()
			logger = sessionContextData.AttachToLogger(logger)
			isServiceAdmin := sessionContextData.Requester.ServicePermissions.IsServiceAdmin()
			logger = logger.WithValue("is_service_admin", isServiceAdmin)

			_, allowed := sessionContextData.AccountPermissions[sessionContextData.ActiveAccountID]
			if !allowed && !isServiceAdmin {
				permissionCheckTimer.Stop()
				logger.Info("not authorized for account")
				s.encoderDecoder.EncodeUnauthorizedResponse(ctx, res)
				return
			}

			for _, perm := range permissions {
				doesNotHaveServicePermission := !sessionContextData.ServiceRolePermissionChecker().HasPermission(perm)
				doesNotHaveAccountPermission := !sessionContextData.AccountRolePermissionsChecker().HasPermission(perm)
				if doesNotHaveServicePermission && doesNotHaveAccountPermission {
					permissionCheckTimer.Stop()
					logger.WithValue("deficient_permission", perm.ID()).Info("request filtered out")
					s.encoderDecoder.EncodeUnauthorizedResponse(ctx, res)
					return
				}
			}

			permissionCheckTimer.Stop()
			next.ServeHTTP(res, req)
		})
	}
}

// ServiceAdminMiddleware restricts requests to admin users only.
func (s *service) ServiceAdminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		ctx, span := s.tracer.StartSpan(req.Context())
		defer span.End()

		logger := s.logger.WithRequest(req).WithSpan(span)

		responseDetails := types.ResponseDetails{
			TraceID: span.SpanContext().TraceID().String(),
		}

		sessionCtxData, err := s.sessionContextDataFetcher(req)
		if err != nil {
			observability.AcknowledgeError(err, logger, span, "retrieving session context data")
			errRes := types.NewAPIErrorResponse("unauthenticated", types.ErrFetchingSessionContextData, responseDetails)
			s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusUnauthorized)
			return
		}

		tracing.AttachSessionContextDataToSpan(span, sessionCtxData)
		logger = sessionCtxData.AttachToLogger(logger)

		if !sessionCtxData.Requester.ServicePermissions.IsServiceAdmin() {
			logger.Debug("ServiceAdminMiddleware called by non-admin user")
			errRes := types.NewAPIErrorResponse("unauthenticated", types.ErrUserIsNotAuthorized, responseDetails)
			s.encoderDecoder.EncodeResponseWithStatus(ctx, res, errRes, http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(res, req)
	})
}

var (
	// ErrNoSessionContextDataAvailable indicates no SessionContextData was attached to the request.
	ErrNoSessionContextDataAvailable = errors.New("no SessionContextData attached to session context data")
)

// FetchContextFromRequest fetches a SessionContextData from a request.
func FetchContextFromRequest(req *http.Request) (*types.SessionContextData, error) {
	if sessionCtxData, ok := req.Context().Value(types.SessionContextDataKey).(*types.SessionContextData); ok && sessionCtxData != nil {
		return sessionCtxData, nil
	}

	return nil, ErrNoSessionContextDataAvailable
}
