package http

import (
	"context"
	"fmt"
	"net/http"
	"path"

	"github.com/verygoodsoftwarenotvirus/starter/internal/authorization"
	"github.com/verygoodsoftwarenotvirus/starter/internal/routing"
	accountinvitationsservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/accountinvitations"
	accountsservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/accounts"
	auditlogentriesservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/auditlogentries"
	authservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/authentication"
	oauth2clientsservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/oauth2clients"
	servicesettingconfigurationsservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/servicesettingconfigurations"
	servicesettingsservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/servicesettings"
	usernotificationsservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/usernotifications"
	usersservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/users"
	webhooksservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/webhooks"
)

const (
	root       = "/"
	searchRoot = "/search"
)

func buildURLVarChunk(key, pattern string) string {
	if pattern != "" {
		return fmt.Sprintf("/{%s:%s}", key, pattern)
	}
	return fmt.Sprintf("/{%s}", key)
}

func (s *server) setupRouter(ctx context.Context, router routing.Router) {
	_, span := s.tracer.StartSpan(ctx)
	defer span.End()

	router.Route("/_meta_", func(metaRouter routing.Router) {
		// Expose a readiness check on /ready
		metaRouter.Get("/ready", func(res http.ResponseWriter, req *http.Request) {
			res.WriteHeader(http.StatusOK)
		})
	})

	authenticatedRouter := router.WithMiddleware(s.authService.UserAttributionMiddleware)
	authenticatedRouter.Get("/auth/status", s.authService.StatusHandler)

	router.Route("/oauth2", func(userRouter routing.Router) {
		userRouter.
			WithMiddleware(s.authService.CookieRequirementMiddleware, s.authService.UserAttributionMiddleware).
			Get("/authorize", s.authService.AuthorizeHandler)
		userRouter.Post("/token", s.authService.TokenHandler)
	})

	router.Route("/users", func(userRouter routing.Router) {
		userRouter.Post(root, s.usersService.CreateHandler)
		userRouter.Post("/login", s.authService.BuildLoginHandler(false))
		userRouter.Post("/login/admin", s.authService.BuildLoginHandler(true))
		userRouter.WithMiddleware(s.authService.UserAttributionMiddleware, s.authService.CookieRequirementMiddleware).
			Post("/logout", s.authService.EndSessionHandler)
		userRouter.Post("/username/reminder", s.usersService.RequestUsernameReminderHandler)
		userRouter.Post("/password/reset", s.usersService.CreatePasswordResetTokenHandler)
		userRouter.Post("/password/reset/redeem", s.usersService.PasswordResetTokenRedemptionHandler)
		userRouter.Post("/email_address/verify", s.usersService.VerifyUserEmailAddressHandler)
		userRouter.Post("/totp_secret/verify", s.usersService.TOTPSecretVerificationHandler)
	})

	router.Route("/auth", func(authRouter routing.Router) {
		providerRouteParam := buildURLVarChunk(authservice.AuthProviderParamKey, "")
		authRouter.Get(providerRouteParam, s.authService.SSOLoginHandler)
		authRouter.Get(path.Join(providerRouteParam, "callback"), s.authService.SSOLoginCallbackHandler)
	})

	authenticatedRouter.WithMiddleware(s.authService.AuthorizationMiddleware).Route("/api/v1", func(v1Router routing.Router) {
		adminRouter := v1Router.WithMiddleware(s.authService.ServiceAdminMiddleware)

		// Admin
		adminRouter.Route("/admin", func(adminRouter routing.Router) {
			adminRouter.
				WithMiddleware(s.authService.PermissionFilterMiddleware(authorization.CycleCookieSecretPermission)).
				Post("/cycle_cookie_secret", s.authService.CycleCookieSecretHandler)
			adminRouter.
				WithMiddleware(s.authService.PermissionFilterMiddleware(authorization.UpdateUserStatusPermission)).
				Post("/users/status", s.adminService.UserAccountStatusChangeHandler)
		})

		// Workers
		adminRouter.Route("/workers", func(adminRouter routing.Router) {
		})

		// Users
		v1Router.Route("/users", func(usersRouter routing.Router) {
			usersRouter.
				WithMiddleware(s.authService.PermissionFilterMiddleware(authorization.ReadUserPermission)).
				Get(root, s.usersService.ListHandler)
			usersRouter.
				WithMiddleware(s.authService.PermissionFilterMiddleware(authorization.SearchUserPermission)).
				Get(searchRoot, s.usersService.UsernameSearchHandler)
			usersRouter.Post("/avatar/upload", s.usersService.AvatarUploadHandler)

			usersRouter.Get("/self", s.usersService.SelfHandler)
			usersRouter.Post("/email_address_verification", s.usersService.RequestEmailVerificationEmailHandler)
			usersRouter.Post("/permissions/check", s.usersService.PermissionsHandler)
			usersRouter.Post("/account/select", s.authService.ChangeActiveAccountHandler)
			usersRouter.Put("/password/new", s.usersService.UpdatePasswordHandler)
			usersRouter.Post("/totp_secret/new", s.usersService.NewTOTPSecretHandler)
			usersRouter.Put("/username", s.usersService.UpdateUserUsernameHandler)
			usersRouter.Put("/email_address", s.usersService.UpdateUserEmailAddressHandler)
			usersRouter.Put("/details", s.usersService.UpdateUserDetailsHandler)

			singleUserRoute := buildURLVarChunk(usersservice.UserIDURIParamKey, "")
			usersRouter.Route(singleUserRoute, func(singleUserRouter routing.Router) {
				singleUserRouter.
					WithMiddleware(s.authService.PermissionFilterMiddleware(authorization.ReadUserPermission)).
					Get(root, s.usersService.ReadHandler)

				singleUserRouter.Delete(root, s.usersService.ArchiveHandler)
			})
		})

		// Accounts
		v1Router.Route("/accounts", func(accountsRouter routing.Router) {
			accountsRouter.Post(root, s.accountsService.CreateHandler)
			accountsRouter.Get(root, s.accountsService.ListHandler)
			accountsRouter.Get("/current", s.accountsService.CurrentInfoHandler)

			singleUserRoute := buildURLVarChunk(accountsservice.UserIDURIParamKey, "")
			singleAccountRoute := buildURLVarChunk(accountsservice.AccountIDURIParamKey, "")
			accountsRouter.Route(singleAccountRoute, func(singleAccountRouter routing.Router) {
				singleAccountRouter.Get(root, s.accountsService.ReadHandler)
				singleAccountRouter.Put(root, s.accountsService.UpdateHandler)
				singleAccountRouter.
					WithMiddleware(s.authService.PermissionFilterMiddleware(authorization.ArchiveAccountPermission)).
					Delete(root, s.accountsService.ArchiveHandler)

				singleAccountRouter.Post("/default", s.accountsService.MarkAsDefaultAccountHandler)
				singleAccountRouter.
					WithMiddleware(s.authService.PermissionFilterMiddleware(authorization.RemoveMemberAccountPermission)).
					Delete("/members"+singleUserRoute, s.accountsService.RemoveMemberHandler)
				singleAccountRouter.
					WithMiddleware(s.authService.PermissionFilterMiddleware(authorization.InviteUserToAccountPermission)).
					Post("/invite", s.accountInvitationsService.InviteMemberHandler)
				singleAccountRouter.
					WithMiddleware(s.authService.PermissionFilterMiddleware(authorization.ModifyMemberPermissionsForAccountPermission)).
					Patch("/members"+singleUserRoute+"/permissions", s.accountsService.ModifyMemberPermissionsHandler)
				singleAccountRouter.Post("/transfer", s.accountsService.TransferAccountOwnershipHandler)

				singleAccountRouter.Route("/invitations", func(invitationsRouter routing.Router) {
					invitationsRouter.Post(root, s.accountInvitationsService.InviteMemberHandler)

					singleAccountInvitationRoute := buildURLVarChunk(accountinvitationsservice.AccountInvitationIDURIParamKey, "")
					invitationsRouter.Route(singleAccountInvitationRoute, func(singleAccountInvitationRouter routing.Router) {
						singleAccountInvitationRouter.Get(root, s.accountInvitationsService.ReadHandler)
					})
				})
			})
		})

		v1Router.Route("/account_invitations", func(accountInvitationsRouter routing.Router) {
			accountInvitationsRouter.Get("/sent", s.accountInvitationsService.OutboundInvitesHandler)
			accountInvitationsRouter.Get("/received", s.accountInvitationsService.InboundInvitesHandler)

			singleAccountInvitationRoute := buildURLVarChunk(accountinvitationsservice.AccountInvitationIDURIParamKey, "")
			accountInvitationsRouter.Route(singleAccountInvitationRoute, func(singleAccountInvitationRouter routing.Router) {
				singleAccountInvitationRouter.Get(root, s.accountInvitationsService.ReadHandler)
				singleAccountInvitationRouter.Put("/cancel", s.accountInvitationsService.CancelInviteHandler)
				singleAccountInvitationRouter.Put("/accept", s.accountInvitationsService.AcceptInviteHandler)
				singleAccountInvitationRouter.Put("/reject", s.accountInvitationsService.RejectInviteHandler)
			})
		})

		// OAuth2 Clients
		v1Router.Route("/oauth2_clients", func(clientRouter routing.Router) {
			clientRouter.
				WithMiddleware(s.authService.PermissionFilterMiddleware(authorization.ReadOAuth2ClientsPermission)).
				Get(root, s.oauth2ClientsService.ListHandler)
			clientRouter.
				WithMiddleware(s.authService.PermissionFilterMiddleware(authorization.CreateOAuth2ClientsPermission)).
				Post(root, s.oauth2ClientsService.CreateHandler)

			singleClientRoute := buildURLVarChunk(oauth2clientsservice.OAuth2ClientIDURIParamKey, "")
			clientRouter.Route(singleClientRoute, func(singleClientRouter routing.Router) {
				singleClientRouter.
					WithMiddleware(s.authService.PermissionFilterMiddleware(authorization.ReadOAuth2ClientsPermission)).
					Get(root, s.oauth2ClientsService.ReadHandler)
				singleClientRouter.
					WithMiddleware(s.authService.PermissionFilterMiddleware(authorization.ArchiveOAuth2ClientsPermission)).
					Delete(root, s.oauth2ClientsService.ArchiveHandler)
			})
		})

		// Webhooks
		v1Router.Route("/webhooks", func(webhookRouter routing.Router) {
			webhookRouter.
				WithMiddleware(s.authService.PermissionFilterMiddleware(authorization.ReadWebhooksPermission)).
				Get(root, s.webhooksService.ListWebhooksHandler)
			webhookRouter.
				WithMiddleware(s.authService.PermissionFilterMiddleware(authorization.CreateWebhooksPermission)).
				Post(root, s.webhooksService.CreateWebhookHandler)

			singleWebhookRoute := buildURLVarChunk(webhooksservice.WebhookIDURIParamKey, "")
			webhookRouter.Route(singleWebhookRoute, func(singleWebhookRouter routing.Router) {
				singleWebhookRouter.
					WithMiddleware(s.authService.PermissionFilterMiddleware(authorization.ReadWebhooksPermission)).
					Get(root, s.webhooksService.ReadWebhookHandler)
				singleWebhookRouter.
					WithMiddleware(s.authService.PermissionFilterMiddleware(authorization.ArchiveWebhooksPermission)).
					Delete(root, s.webhooksService.ArchiveWebhookHandler)

				singleWebhookTriggerEventRoute := buildURLVarChunk(webhooksservice.WebhookTriggerEventIDURIParamKey, "")
				singleWebhookRouter.Route("/trigger_events"+singleWebhookTriggerEventRoute, func(singleWebhookRouter routing.Router) {
					singleWebhookRouter.
						WithMiddleware(s.authService.PermissionFilterMiddleware(authorization.ArchiveWebhooksPermission)).
						Delete(root, s.webhooksService.ArchiveWebhookTriggerEventHandler)
				})
			})
		})

		// Audit Log Entries
		v1Router.Route("/audit_log_entries", func(auditLogEntriesRouter routing.Router) {
			singleAuditLogEntryRoute := buildURLVarChunk(auditlogentriesservice.AuditLogEntryIDURIParamKey, "")
			auditLogEntriesRouter.
				WithMiddleware(s.authService.PermissionFilterMiddleware(authorization.ReadAuditLogEntriesPermission)).
				Get(singleAuditLogEntryRoute, s.auditLogEntriesService.ReadAuditLogEntryHandler)
			auditLogEntriesRouter.
				WithMiddleware(s.authService.PermissionFilterMiddleware(authorization.ReadAuditLogEntriesPermission)).
				Get("/for_user", s.auditLogEntriesService.ListUserAuditLogEntriesHandler)
			auditLogEntriesRouter.
				WithMiddleware(s.authService.PermissionFilterMiddleware(authorization.ReadAuditLogEntriesPermission)).
				Get("/for_account", s.auditLogEntriesService.ListAccountAuditLogEntriesHandler)
		})

		// ServiceSettings
		serviceSettingPath := "settings"
		serviceSettingsRouteWithPrefix := fmt.Sprintf("/%s", serviceSettingPath)
		serviceSettingIDRouteParam := buildURLVarChunk(servicesettingsservice.ServiceSettingIDURIParamKey, "")
		v1Router.Route(serviceSettingsRouteWithPrefix, func(serviceSettingsRouter routing.Router) {
			serviceSettingsRouter.
				WithMiddleware(s.authService.PermissionFilterMiddleware(authorization.CreateServiceSettingsPermission)).
				Post(root, s.serviceSettingsService.CreateHandler)
			serviceSettingsRouter.
				WithMiddleware(s.authService.PermissionFilterMiddleware(authorization.ReadServiceSettingsPermission)).
				Get(root, s.serviceSettingsService.ListHandler)
			serviceSettingsRouter.
				WithMiddleware(s.authService.PermissionFilterMiddleware(authorization.ReadServiceSettingsPermission)).
				Get(searchRoot, s.serviceSettingsService.SearchHandler)

			serviceSettingsRouter.Route(serviceSettingIDRouteParam, func(singleServiceSettingRouter routing.Router) {
				singleServiceSettingRouter.
					WithMiddleware(s.authService.PermissionFilterMiddleware(authorization.ReadServiceSettingsPermission)).
					Get(root, s.serviceSettingsService.ReadHandler)
				singleServiceSettingRouter.
					WithMiddleware(s.authService.PermissionFilterMiddleware(authorization.ArchiveServiceSettingsPermission)).
					Delete(root, s.serviceSettingsService.ArchiveHandler)
			})

			serviceSettingConfigurationIDRouteParam := buildURLVarChunk(servicesettingconfigurationsservice.ServiceSettingConfigurationIDURIParamKey, "")
			serviceSettingsRouter.Route("/configurations", func(settingConfigurationRouter routing.Router) {
				settingConfigurationRouter.
					WithMiddleware(s.authService.PermissionFilterMiddleware(authorization.CreateServiceSettingConfigurationsPermission)).
					Post(root, s.serviceSettingConfigurationsService.CreateHandler)
				settingConfigurationRouter.
					WithMiddleware(s.authService.PermissionFilterMiddleware(authorization.ReadServiceSettingConfigurationsPermission)).
					Get("/user"+buildURLVarChunk(servicesettingconfigurationsservice.ServiceSettingConfigurationNameURIParamKey, ""), s.serviceSettingConfigurationsService.ForUserByNameHandler)
				settingConfigurationRouter.
					WithMiddleware(s.authService.PermissionFilterMiddleware(authorization.ReadServiceSettingConfigurationsPermission)).
					Get("/user", s.serviceSettingConfigurationsService.ForUserHandler)
				settingConfigurationRouter.
					WithMiddleware(s.authService.PermissionFilterMiddleware(authorization.ReadServiceSettingConfigurationsPermission)).
					Get("/account", s.serviceSettingConfigurationsService.ForAccountHandler)
				settingConfigurationRouter.
					WithMiddleware(s.authService.PermissionFilterMiddleware(authorization.UpdateServiceSettingConfigurationsPermission)).
					Put(serviceSettingConfigurationIDRouteParam, s.serviceSettingConfigurationsService.UpdateHandler)
				settingConfigurationRouter.
					WithMiddleware(s.authService.PermissionFilterMiddleware(authorization.ArchiveServiceSettingConfigurationsPermission)).
					Delete(serviceSettingConfigurationIDRouteParam, s.serviceSettingConfigurationsService.ArchiveHandler)
			})
		})

		// User Notifications
		userNotificationPath := "user_notifications"
		userNotificationsRouteWithPrefix := fmt.Sprintf("/%s", userNotificationPath)
		userNotificationIDRouteParam := buildURLVarChunk(usernotificationsservice.UserNotificationIDURIParamKey, "")
		v1Router.Route(userNotificationsRouteWithPrefix, func(userNotificationsRouter routing.Router) {
			userNotificationsRouter.
				WithMiddleware(s.authService.PermissionFilterMiddleware(authorization.CreateUserNotificationsPermission)).
				Post(root, s.userNotificationsService.CreateHandler)
			userNotificationsRouter.
				WithMiddleware(s.authService.PermissionFilterMiddleware(authorization.ReadUserNotificationsPermission)).
				Get(root, s.userNotificationsService.ListHandler)

			userNotificationsRouter.Route(userNotificationIDRouteParam, func(singleUserNotificationRouter routing.Router) {
				singleUserNotificationRouter.
					WithMiddleware(s.authService.PermissionFilterMiddleware(authorization.ReadUserNotificationsPermission)).
					Get(root, s.userNotificationsService.ReadHandler)
				singleUserNotificationRouter.
					WithMiddleware(s.authService.PermissionFilterMiddleware(authorization.UpdateUserNotificationsPermission)).
					Patch(root, s.userNotificationsService.UpdateHandler)
			})
		})
	})

	s.router = router
}
