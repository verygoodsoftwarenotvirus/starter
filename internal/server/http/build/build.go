//go:build wireinject
// +build wireinject

package build

import (
	"context"

	analyticscfg "github.com/verygoodsoftwarenotvirus/starter/internal/analytics/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/authentication"
	"github.com/verygoodsoftwarenotvirus/starter/internal/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/database"
	dbconfig "github.com/verygoodsoftwarenotvirus/starter/internal/database/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/database/postgres"
	emailcfg "github.com/verygoodsoftwarenotvirus/starter/internal/email/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/encoding"
	featureflagscfg "github.com/verygoodsoftwarenotvirus/starter/internal/featureflags/config"
	msgconfig "github.com/verygoodsoftwarenotvirus/starter/internal/messagequeue/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	logcfg "github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	tracingcfg "github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/pkg/random"
	"github.com/verygoodsoftwarenotvirus/starter/internal/routing/chi"
	"github.com/verygoodsoftwarenotvirus/starter/internal/server/http"
	accountinvitationssservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/accountinvitations"
	accountsservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/accounts"
	adminservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/admin"
	auditlogentriesservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/auditlogentries"
	authservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/authentication"
	oauth2clientsservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/oauth2clients"
	servicesettingconfigurationsservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/servicesettingconfigurations"
	servicesettingsservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/servicesettings"
	usernotificationsservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/usernotifications"
	usersservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/users"
	webhooksservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/webhooks"
	"github.com/verygoodsoftwarenotvirus/starter/internal/uploads/images"

	"github.com/google/wire"
)

// Build builds a server.
func Build(
	ctx context.Context,
	cfg *config.InstanceConfig,
) (http.Server, error) {
	wire.Build(
		authentication.AuthProviders,
		config.ServiceConfigProviders,
		database.DBProviders,
		dbconfig.DatabaseConfigProviders,
		encoding.EncDecProviders,
		msgconfig.MessageQueueProviders,
		http.ProvidersHTTP,
		images.ProvidersImages,
		chi.ProvidersChi,
		random.ProvidersRandom,
		featureflagscfg.ProvidersFeatureFlags,
		tracing.ProvidersTracing,
		emailcfg.ProvidersEmail,
		tracingcfg.ProvidersTracing,
		observability.ProvidersObservability,
		postgres.ProvidersPostgres,
		logcfg.ProvidersLogConfig,
		authservice.Providers,
		usersservice.Providers,
		accountsservice.Providers,
		accountinvitationssservice.Providers,
		webhooksservice.Providers,
		adminservice.Providers,
		servicesettingsservice.Providers,
		servicesettingconfigurationsservice.Providers,
		oauth2clientsservice.Providers,
		analyticscfg.ProvidersAnalytics,
		usernotificationsservice.Providers,
		auditlogentriesservice.Providers,
	)

	return nil, nil
}
