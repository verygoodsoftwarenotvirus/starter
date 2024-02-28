package database

import (
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"

	"github.com/google/wire"
)

var (
	// DBProviders represents what we provide to dependency injectors.
	DBProviders = wire.NewSet(
		ProvideAccountDataManager,
		ProvideAccountInvitationDataManager,
		ProvideAccountUserMembershipDataManager,
		ProvideUserDataManager,
		ProvideAdminUserDataManager,
		ProvidePasswordResetTokenDataManager,
		ProvideWebhookDataManager,
		ProvideServiceSettingDataManager,
		ProvideServiceSettingConfigurationDataManager,
		ProvideOAuth2ClientDataManager,
		ProvideUserNotificationDataManager,
		ProvideAuditLogEntryDataManager,
	)
)

// ProvideAccountDataManager is an arbitrary function for dependency injection's sake.
func ProvideAccountDataManager(db DataManager) types.AccountDataManager {
	return db
}

// ProvideAccountInvitationDataManager is an arbitrary function for dependency injection's sake.
func ProvideAccountInvitationDataManager(db DataManager) types.AccountInvitationDataManager {
	return db
}

// ProvideAccountUserMembershipDataManager is an arbitrary function for dependency injection's sake.
func ProvideAccountUserMembershipDataManager(db DataManager) types.AccountUserMembershipDataManager {
	return db
}

// ProvideUserDataManager is an arbitrary function for dependency injection's sake.
func ProvideUserDataManager(db DataManager) types.UserDataManager {
	return db
}

// ProvideAdminUserDataManager is an arbitrary function for dependency injection's sake.
func ProvideAdminUserDataManager(db DataManager) types.AdminUserDataManager {
	return db
}

// ProvidePasswordResetTokenDataManager is an arbitrary function for dependency injection's sake.
func ProvidePasswordResetTokenDataManager(db DataManager) types.PasswordResetTokenDataManager {
	return db
}

// ProvideWebhookDataManager is an arbitrary function for dependency injection's sake.
func ProvideWebhookDataManager(db DataManager) types.WebhookDataManager {
	return db
}

// ProvideServiceSettingDataManager is an arbitrary function for dependency injection's sake.
func ProvideServiceSettingDataManager(db DataManager) types.ServiceSettingDataManager {
	return db
}

// ProvideServiceSettingConfigurationDataManager is an arbitrary function for dependency injection's sake.
func ProvideServiceSettingConfigurationDataManager(db DataManager) types.ServiceSettingConfigurationDataManager {
	return db
}

// ProvideOAuth2ClientDataManager is an arbitrary function for dependency injection's sake.
func ProvideOAuth2ClientDataManager(db DataManager) types.OAuth2ClientDataManager {
	return db
}

// ProvideUserNotificationDataManager is an arbitrary function for dependency injection's sake.
func ProvideUserNotificationDataManager(db DataManager) types.UserNotificationDataManager {
	return db
}

// ProvideAuditLogEntryDataManager is an arbitrary function for dependency injection's sake.
func ProvideAuditLogEntryDataManager(db DataManager) types.AuditLogEntryDataManager {
	return db
}
