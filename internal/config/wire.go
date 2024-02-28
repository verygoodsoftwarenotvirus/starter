package config

import (
	"github.com/google/wire"
)

var (
	// ServiceConfigProviders represents this package's offering to the dependency injector.
	ServiceConfigProviders = wire.NewSet(
		wire.FieldsOf(
			new(*InstanceConfig),
			"Observability",
			"Email",
			"Analytics",
			"FeatureFlags",
			"Encoding",
			"Routing",
			"Database",
			"Meta",
			"Events",
			"Search",
			"Server",
			"Services",
		),
		wire.FieldsOf(
			new(*ServicesConfig),
			"AuditLogEntries",
			"Auth",
			"Accounts",
			"AccountInvitations",
			"ServiceSettings",
			"ServiceSettingConfigurations",
			"Users",
			"UserNotifications",
			"Webhooks",
			"Workers",
		),
	)
)
