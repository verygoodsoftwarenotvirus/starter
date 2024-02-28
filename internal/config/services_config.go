package config

import (
	"context"
	"fmt"

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

	"github.com/hashicorp/go-multierror"
)

type (
	// ServicesConfig collects the various service configurations.
	ServicesConfig struct {
		_                            struct{}                                   `json:"-"`
		AuditLogEntries              auditlogentriesservice.Config              `json:"auditLogEntries"              toml:"audit_log_entries,omitempty"`
		ServiceSettingConfigurations servicesettingconfigurationsservice.Config `json:"serviceSettingConfigurations" toml:"service_setting_configurations,omitempty"`
		ServiceSettings              servicesettingsservice.Config              `json:"serviceSettings"              toml:"service_settings,omitempty"`
		Accounts                     accountsservice.Config                     `json:"accounts"                     toml:"accounts,omitempty"`
		UserNotifications            usernotificationsservice.Config            `json:"userNotifications"            toml:"user_notifications,omitempty"`
		Users                        usersservice.Config                        `json:"users"                        toml:"users,omitempty"`
		OAuth2Clients                oauth2clientsservice.Config                `json:"oauth2Clients"                toml:"oauth2_clients,omitempty"`
		Webhooks                     webhooksservice.Config                     `json:"webhooks"                     toml:"webhooks,omitempty"`
		AccountInvitations           accountinvitationsservice.Config           `json:"accountInvitations"           toml:"account_invitations,omitempty"`
		Auth                         authservice.Config                         `json:"auth"                         toml:"auth,omitempty"`
	}
)

// ValidateWithContext validates a InstanceConfig struct.
func (cfg *ServicesConfig) ValidateWithContext(ctx context.Context) error {
	var result *multierror.Error

	validatorsToRun := map[string]func(context.Context) error{
		"Auth":                         cfg.Auth.ValidateWithContext,
		"Users":                        cfg.Users.ValidateWithContext,
		"Webhooks":                     cfg.Webhooks.ValidateWithContext,
		"ServiceSettings":              cfg.ServiceSettings.ValidateWithContext,
		"ServiceSettingConfigurations": cfg.ServiceSettingConfigurations.ValidateWithContext,
		"UserNotifications":            cfg.UserNotifications.ValidateWithContext,
		"AuditLogEntries":              cfg.AuditLogEntries.ValidateWithContext,
	}

	for name, validator := range validatorsToRun {
		if err := validator(ctx); err != nil {
			result = multierror.Append(fmt.Errorf("error validating %s config: %w", name, err), result)
		}
	}

	return result.ErrorOrNil()
}
