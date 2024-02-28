package keys

const (
	// RequesterIDKey is the standard key for referring to a requesting user's ID.
	RequesterIDKey = "request.made_by"
	// AccountIDKey is the standard key for referring to a account ID.
	AccountIDKey = "account.id"
	// AccountInvitationIDKey is the standard key for referring to a account ID.
	AccountInvitationIDKey = "account_invitation.id"
	// AccountInvitationTokenKey is the standard key for referring to a account invitation token.
	AccountInvitationTokenKey = "account_invitation.token"
	// ActiveAccountIDKey is the standard key for referring to an active account ID.
	ActiveAccountIDKey = "active_account.id"
	// UserIDKey is the standard key for referring to a user ID.
	UserIDKey = "user.id"
	// UserNotificationIDKey is the standard key for referring to a user notification ID.
	UserNotificationIDKey = "user_notification.id"
	// UserEmailAddressKey is the standard key for referring to a user's email address.
	UserEmailAddressKey = "user.email_address"
	// UserIsServiceAdminKey is the standard key for referring to a user's admin status.
	UserIsServiceAdminKey = "user.is_admin"
	// UsernameKey is the standard key for referring to a username.
	UsernameKey = "user.username"
	// NameKey is the standard key for referring to a name.
	NameKey = "name"
	// SpanIDKey is the standard key for referring to a span ID.
	SpanIDKey = "span.id"
	// TraceIDKey is the standard key for referring to a trace ID.
	TraceIDKey = "trace.id"
	// FilterCreatedAfterKey is the standard key for referring to a types.QueryFilter's CreatedAfter field.
	FilterCreatedAfterKey = "query_filter.created_after"
	// FilterCreatedBeforeKey is the standard key for referring to a types.QueryFilter's CreatedBefore field.
	FilterCreatedBeforeKey = "query_filter.created_before"
	// FilterUpdatedAfterKey is the standard key for referring to a types.QueryFilter's UpdatedAfter field.
	FilterUpdatedAfterKey = "query_filter.updated_after"
	// FilterUpdatedBeforeKey is the standard key for referring to a types.QueryFilter's UpdatedAfter field.
	FilterUpdatedBeforeKey = "query_filter.updated_before"
	// FilterSortByKey is the standard key for referring to a types.QueryFilter's SortBy field.
	FilterSortByKey = "query_filter.sort_by"
	// FilterPageKey is the standard key for referring to a types.QueryFilter's page.
	FilterPageKey = "query_filter.page"
	// FilterLimitKey is the standard key for referring to a types.QueryFilter's limit.
	FilterLimitKey = "query_filter.limit"
	// FilterIsNilKey is the standard key for referring to a types.QueryFilter's null status.
	FilterIsNilKey = "query_filter.is_nil"
	// WebhookIDKey is the standard key for referring to a webhook's ID.
	WebhookIDKey = "webhook.id"
	// WebhookTriggerEventIDKey is the standard key for referring to a webhook trigger event's ID.
	WebhookTriggerEventIDKey = "webhook_trigger_event.id"
	// AuditLogEntryIDKey is the standard key for referring to an audit log entry's ID.
	AuditLogEntryIDKey = "audit_log_entry.id"
	// AuditLogEntryResourceTypesKey is the standard key for referring to an audit log entry's resource type.
	AuditLogEntryResourceTypesKey = "audit_log_entry.resource_types"
	// URLKey is the standard key for referring to a URL.
	URLKey = "url"
	// PasswordResetTokenIDKey is the standard key for referring to a password reset token's ID.
	PasswordResetTokenIDKey = "password_reset_token.id"
	// RequestHeadersKey is the standard key for referring to a http.Request's Headers.
	RequestHeadersKey = "request.headers"
	// RequestMethodKey is the standard key for referring to a http.Request's Method.
	RequestMethodKey = "request.method"
	// RequestURIKey is the standard key for referring to a http.Request's URI.
	RequestURIKey = "request.uri"
	// ResponseStatusKey is the standard key for referring to a http.Request's status.
	ResponseStatusKey = "response.status"
	// ResponseBytesWrittenKey is the standard key for referring to a http.Request's bytes written.
	ResponseBytesWrittenKey = "response.bytes_written"
	// ResponseHeadersKey is the standard key for referring to a http.Response's Headers.
	ResponseHeadersKey = "response.headers"
	// ReasonKey is the standard key for referring to a reason for a change.
	ReasonKey = "reason"
	// URLQueryKey is the standard key for referring to a URL query.
	URLQueryKey = "url.query"
	// SearchQueryKey is the standard key for referring to a search query parameter value.
	SearchQueryKey = "search_query"
	// UserAgentOSKey is the standard key for referring to a user agent's OS.
	UserAgentOSKey = "os"
	// UserAgentBotKey is the standard key for referring to a user agent's bot status.
	UserAgentBotKey = "is_bot"
	// UserAgentMobileKey is the standard key for referring to user agent's mobile status.
	UserAgentMobileKey = "is_mobile"
	// ValidationErrorKey is the standard key for referring to a struct validation error.
	ValidationErrorKey = "validation_error"
	// ServiceSettingIDKey is the standard key for referring to a service setting's ID.
	ServiceSettingIDKey = "service_setting.id"
	// ServiceSettingNameKey is the standard key for referring to a service setting's ID.
	ServiceSettingNameKey = "service_setting.name"
	// ServiceSettingConfigurationIDKey is the standard key for referring to a service setting configuration's ID.
	ServiceSettingConfigurationIDKey = "service_setting_configuration.id"
	// OAuth2ClientIDKey is the standard key for referring to an OAuth2 client's database ID.
	OAuth2ClientIDKey = "oauth2_clients.id"
	// OAuth2ClientClientIDKey is the standard key for referring to an OAuth2 client's client ID.
	OAuth2ClientClientIDKey = "oauth2_clients.client_id"
	// OAuth2ClientTokenIDKey is the standard key for referring to an OAuth2 client token's ID.
	/* #nosec G101 */
	OAuth2ClientTokenIDKey = "oauth2_client_tokens.id"
	// OAuth2ClientTokenCodeKey is the standard key for referring to an OAuth2 client token's code.
	/* #nosec G101 */
	OAuth2ClientTokenCodeKey = "oauth2_client_tokens.code"
	// OAuth2ClientTokenAccessKey is the standard key for referring to an OAuth2 client token's access.
	/* #nosec G101 */
	OAuth2ClientTokenAccessKey = "oauth2_client_tokens.access"
	// OAuth2ClientTokenRefreshKey is the standard key for referring to an OAuth2 client token's refresh.
	/* #nosec G101 */
	OAuth2ClientTokenRefreshKey = "oauth2_client_tokens.refresh"
)
