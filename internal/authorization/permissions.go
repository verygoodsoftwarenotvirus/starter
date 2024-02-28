package authorization

import (
	"github.com/mikespook/gorbac/v2"
)

var _ gorbac.Permission = (*Permission)(nil)

type (
	// Permission is a simple string alias.
	Permission string
)

const (
	// CycleCookieSecretPermission is a service admin permission.
	CycleCookieSecretPermission Permission = "update.cookie_secret"
	// UpdateUserStatusPermission is a service admin permission.
	UpdateUserStatusPermission Permission = "update.user_status"
	// ReadUserPermission is a service admin permission.
	ReadUserPermission Permission = "read.user"
	// SearchUserPermission is a service admin permission.
	SearchUserPermission Permission = "search.user"

	// UpdateAccountPermission is a account admin permission.
	UpdateAccountPermission Permission = "update.account"
	// ArchiveAccountPermission is a account admin permission.
	ArchiveAccountPermission Permission = "archive.account"
	// InviteUserToAccountPermission is a account admin permission.
	InviteUserToAccountPermission Permission = "account.add.member"
	// ModifyMemberPermissionsForAccountPermission is an account admin permission.
	ModifyMemberPermissionsForAccountPermission Permission = "account.membership.modify"
	// RemoveMemberAccountPermission is a account admin permission.
	RemoveMemberAccountPermission Permission = "remove_member.account"
	// TransferAccountPermission is a account admin permission.
	TransferAccountPermission Permission = "transfer.account"

	// CreateWebhooksPermission is a account admin permission.
	CreateWebhooksPermission Permission = "create.webhooks"
	// ReadWebhooksPermission is a account admin permission.
	ReadWebhooksPermission Permission = "read.webhooks"
	// UpdateWebhooksPermission is a account admin permission.
	UpdateWebhooksPermission Permission = "update.webhooks"
	// ArchiveWebhooksPermission is a account admin permission.
	ArchiveWebhooksPermission Permission = "archive.webhooks"

	// ReadAuditLogEntriesPermission is a service permission.
	ReadAuditLogEntriesPermission Permission = "read.audit_log_entries"

	// CreateServiceSettingsPermission is an admin user permission.
	CreateServiceSettingsPermission Permission = "create.service_settings"
	// ReadServiceSettingsPermission is an admin user permission.
	ReadServiceSettingsPermission Permission = "read.service_settings"
	// SearchServiceSettingsPermission is an admin user permission.
	SearchServiceSettingsPermission Permission = "search.service_settings"
	// ArchiveServiceSettingsPermission is an admin user permission.
	ArchiveServiceSettingsPermission Permission = "archive.service_settings"

	// CreateServiceSettingConfigurationsPermission is an admin user permission.
	CreateServiceSettingConfigurationsPermission Permission = "create.service_setting_configurations"
	// ReadServiceSettingConfigurationsPermission is an admin user permission.
	ReadServiceSettingConfigurationsPermission Permission = "read.service_setting_configurations"
	// UpdateServiceSettingConfigurationsPermission is an admin user permission.
	UpdateServiceSettingConfigurationsPermission Permission = "update.service_setting_configurations"
	// ArchiveServiceSettingConfigurationsPermission is an admin user permission.
	ArchiveServiceSettingConfigurationsPermission Permission = "archive.service_setting_configurations"

	// CreateOAuth2ClientsPermission is a account admin permission.
	CreateOAuth2ClientsPermission Permission = "create.oauth2_clients"
	// ReadOAuth2ClientsPermission is a account admin permission.
	ReadOAuth2ClientsPermission Permission = "read.oauth2_clients"
	// ArchiveOAuth2ClientsPermission is a account admin permission.
	ArchiveOAuth2ClientsPermission Permission = "archive.oauth2_clients"

	// CreateUserNotificationsPermission is an admin user permission.
	CreateUserNotificationsPermission Permission = "create.user_notifications"
	// ReadUserNotificationsPermission is a account user permission.
	ReadUserNotificationsPermission Permission = "read.user_notifications"
	// UpdateUserNotificationsPermission is a account user permission.
	UpdateUserNotificationsPermission Permission = "update.user_notifications"
)

// ID implements the gorbac Permission interface.
func (p Permission) ID() string {
	return string(p)
}

// Match implements the gorbac Permission interface.
func (p Permission) Match(perm gorbac.Permission) bool {
	return p.ID() == perm.ID()
}

var (
	// service admin permissions.
	serviceAdminPermissions = []gorbac.Permission{
		CycleCookieSecretPermission,
		UpdateUserStatusPermission,
		ReadUserPermission,
		SearchUserPermission,
		CreateOAuth2ClientsPermission,
		ArchiveOAuth2ClientsPermission,
		ArchiveServiceSettingsPermission,
		CreateUserNotificationsPermission,
		// only admins can arbitrarily create these via the API, this is exclusively for integration test purposes.
		CreateServiceSettingsPermission,
	}

	// account admin permissions.
	accountAdminPermissions = []gorbac.Permission{
		UpdateAccountPermission,
		ArchiveAccountPermission,
		TransferAccountPermission,
		InviteUserToAccountPermission,
		ModifyMemberPermissionsForAccountPermission,
		RemoveMemberAccountPermission,
		CreateWebhooksPermission,
		UpdateWebhooksPermission,
		ArchiveWebhooksPermission,
	}

	// account member permissions.
	accountMemberPermissions = []gorbac.Permission{
		ReadWebhooksPermission,
		ReadAuditLogEntriesPermission,
		ReadOAuth2ClientsPermission,
		ReadServiceSettingsPermission,
		SearchServiceSettingsPermission,
		CreateServiceSettingConfigurationsPermission,
		ReadServiceSettingConfigurationsPermission,
		UpdateServiceSettingConfigurationsPermission,
		ArchiveServiceSettingConfigurationsPermission,
		ReadUserNotificationsPermission,
		UpdateUserNotificationsPermission,
	}
)

func init() {
	// assign service admin permissions.
	for _, perm := range serviceAdminPermissions {
		must(serviceAdmin.Assign(perm))
	}

	// assign account admin permissions.
	for _, perm := range accountAdminPermissions {
		must(accountAdmin.Assign(perm))
	}

	// assign account member permissions.
	for _, perm := range accountMemberPermissions {
		must(accountMember.Assign(perm))
	}
}
