package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"

	analyticsconfig "github.com/verygoodsoftwarenotvirus/starter/internal/analytics/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/analytics/segment"
	"github.com/verygoodsoftwarenotvirus/starter/internal/config"
	dbconfig "github.com/verygoodsoftwarenotvirus/starter/internal/database/config"
	emailconfig "github.com/verygoodsoftwarenotvirus/starter/internal/email/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/email/sendgrid"
	"github.com/verygoodsoftwarenotvirus/starter/internal/encoding"
	msgconfig "github.com/verygoodsoftwarenotvirus/starter/internal/messagequeue/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/messagequeue/redis"
	"github.com/verygoodsoftwarenotvirus/starter/internal/objectstorage"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	logcfg "github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing/cloudtrace"
	tracingcfg "github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing/oteltracehttp"
	"github.com/verygoodsoftwarenotvirus/starter/internal/routing"
	"github.com/verygoodsoftwarenotvirus/starter/internal/search/algolia"
	searchcfg "github.com/verygoodsoftwarenotvirus/starter/internal/search/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/server/http"
	accountinvitationsservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/accountinvitations"
	accountsservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/accounts"
	auditlogentriesservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/auditlogentries"
	authservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/authentication"
	oauth2clientsservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/oauth2clients"
	"github.com/verygoodsoftwarenotvirus/starter/internal/services/servicesettingconfigurations"
	"github.com/verygoodsoftwarenotvirus/starter/internal/services/servicesettings"
	usernotificationsservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/usernotifications"
	usersservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/users"
	webhooksservice "github.com/verygoodsoftwarenotvirus/starter/internal/services/webhooks"
	"github.com/verygoodsoftwarenotvirus/starter/internal/uploads"
)

const (
	defaultPort         = 8000
	defaultCookieDomain = ".whatever.gov"
	/* #nosec G101 */
	debugCookieSecret = "HEREISA32CHARSECRETWHICHISMADEUP"
	/* #nosec G101 */
	debugCookieSigningKey    = "DIFFERENT32CHARSECRETTHATIMADEUP"
	devPostgresDBConnDetails = "postgres://dbuser:hunter2@pgdatabase:5432/service-name?sslmode=disable"
	defaultCookieName        = authservice.DefaultCookieName

	// run modes.
	developmentEnv = "development"
	testingEnv     = "testing"

	// message provider topics.
	dataChangesTopicName = "data_changes"

	maxAttempts = 50

	contentTypeJSON               = "application/json"
	workerQueueAddress            = "worker_queue:6379"
	localOAuth2TokenEncryptionKey = debugCookieSecret
)

var (
	localRoutingConfig = routing.Config{
		Provider:               routing.ChiProvider,
		EnableCORSForLocalhost: true,
		SilenceRouteLogging:    false,
	}

	devRoutingConfig = routing.Config{
		Provider:               routing.ChiProvider,
		EnableCORSForLocalhost: true,
		SilenceRouteLogging:    false,
	}

	devEnvLogConfig = logcfg.Config{
		Level:    logging.DebugLevel,
		Provider: logcfg.ProviderSlog,
	}

	localLogConfig = logcfg.Config{
		Level:    logging.DebugLevel,
		Provider: logcfg.ProviderSlog,
	}

	localServer = http.Config{
		Debug:           true,
		HTTPPort:        defaultPort,
		StartupDeadline: time.Minute,
	}

	localCookies = authservice.CookieConfig{
		Name:       defaultCookieName,
		Domain:     defaultCookieDomain,
		HashKey:    debugCookieSecret,
		BlockKey:   debugCookieSigningKey,
		Lifetime:   authservice.DefaultCookieLifetime,
		SecureOnly: false,
	}

	localTracingConfig = tracingcfg.Config{
		Provider: tracingcfg.ProviderOtel,
		Otel: &oteltracehttp.Config{
			SpanCollectionProbability: 1,
			CollectorEndpoint:         "http://tracing-server:14268/api/traces",
			ServiceName:               "company_name_service",
		},
	}
)

func saveConfig(ctx context.Context, outputPath string, cfg *config.InstanceConfig, indent, validate bool) error {
	/* #nosec G301 */
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o777); err != nil {
		// okay, who gives a shit?
		_ = err
	}

	if validate {
		if err := cfg.ValidateWithContext(ctx, true); err != nil {
			return err
		}
	}

	var (
		output []byte
		err    error
	)

	if indent {
		output, err = json.MarshalIndent(cfg, "", "\t")
	} else {
		output, err = json.Marshal(cfg)
	}

	if err != nil {
		return err
	}

	/* #nosec G306 */
	return os.WriteFile(outputPath, output, 0o644)
}

type configFunc func(ctx context.Context, filePath string) error

var files = map[string]configFunc{
	"environments/local/config_files/service-config.json":             buildLocalDevelopmentServiceConfig(false),
	"environments/local/config_files/service-config-local.json":       buildLocalDevelopmentServiceConfig(true),
	"environments/testing/config_files/integration-tests-config.json": integrationTestConfig,
	"environments/dev/config_files/service-config.json":               devEnvironmentServerConfig,
}

func buildDevEnvironmentServerConfig() *config.InstanceConfig {
	cookieConfig := authservice.CookieConfig{
		Name:       defaultCookieName,
		Domain:     ".whatever.dev",
		Lifetime:   (24 * time.Hour) * 30,
		SecureOnly: true,
	}

	emailConfig := emailconfig.Config{
		Provider: emailconfig.ProviderSendgrid,
		Sendgrid: &sendgrid.Config{},
	}

	analyticsConfig := analyticsconfig.Config{
		Provider: analyticsconfig.ProviderSegment,
		Segment:  &segment.Config{APIToken: ""},
	}

	cfg := &config.InstanceConfig{
		Routing: devRoutingConfig,
		Meta: config.MetaSettings{
			Debug:   true,
			RunMode: developmentEnv,
		},
		Encoding: encoding.Config{
			ContentType: contentTypeJSON,
		},
		Events: msgconfig.Config{
			Consumers: msgconfig.MessageQueueConfig{
				Provider: msgconfig.ProviderPubSub,
			},
			Publishers: msgconfig.MessageQueueConfig{
				Provider: msgconfig.ProviderPubSub,
			},
		},
		Email:     emailConfig,
		Analytics: analyticsConfig,
		Server: http.Config{
			Debug:           true,
			HTTPPort:        defaultPort,
			StartupDeadline: time.Minute,
		},
		Search: searchcfg.Config{
			Algolia:  &algolia.Config{},
			Provider: searchcfg.AlgoliaProvider,
		},
		Database: dbconfig.Config{
			Debug:           true,
			LogQueries:      true,
			RunMigrations:   true,
			MaxPingAttempts: maxAttempts,
			PingWaitPeriod:  time.Second,
		},
		Observability: observability.Config{
			Logging: devEnvLogConfig,
			Tracing: tracingcfg.Config{
				Provider: tracingcfg.ProviderCloudTrace,
				CloudTrace: &cloudtrace.Config{
					ProjectID:                 "project-name",
					ServiceName:               "company_name_api",
					SpanCollectionProbability: 1,
				},
			},
		},
		Services: config.ServicesConfig{
			AuditLogEntries: auditlogentriesservice.Config{},
			Auth: authservice.Config{
				OAuth2: authservice.OAuth2Config{
					Domain:               "https://whatever.dev",
					AccessTokenLifespan:  time.Hour,
					RefreshTokenLifespan: time.Hour,
					Debug:                false,
				},
				Cookies:               cookieConfig,
				Debug:                 true,
				EnableUserSignup:      true,
				MinimumUsernameLength: 3,
				MinimumPasswordLength: 8,
			},
			Users: usersservice.Config{
				DataChangesTopicName: dataChangesTopicName,
				PublicMediaURLPrefix: "https://media.whatever.dev/avatars",
				Uploads: uploads.Config{
					Debug: true,
					Storage: objectstorage.Config{
						UploadFilenameKey: "avatar",
						Provider:          objectstorage.GCPCloudStorageProvider,
						BucketName:        "media.whatever.dev",
						BucketPrefix:      "avatars/",
						GCPConfig: &objectstorage.GCPConfig{
							BucketName: "media.whatever.dev",
						},
					},
				},
			},
		},
	}

	return cfg
}

func devEnvironmentServerConfig(ctx context.Context, filePath string) error {
	cfg := buildDevEnvironmentServerConfig()

	return saveConfig(ctx, filePath, cfg, false, false)
}

func buildDevConfig() *config.InstanceConfig {
	return &config.InstanceConfig{
		Routing: localRoutingConfig,
		Meta: config.MetaSettings{
			Debug:   true,
			RunMode: developmentEnv,
		},
		Encoding: encoding.Config{
			ContentType: contentTypeJSON,
		},
		Events: msgconfig.Config{
			Consumers: msgconfig.MessageQueueConfig{
				Provider: msgconfig.ProviderRedis,
				Redis: redis.Config{
					QueueAddresses: []string{workerQueueAddress},
				},
			},
			Publishers: msgconfig.MessageQueueConfig{
				Provider: msgconfig.ProviderRedis,
				Redis: redis.Config{
					QueueAddresses: []string{workerQueueAddress},
				},
			},
		},
		Search: searchcfg.Config{
			Algolia:  &algolia.Config{},
			Provider: searchcfg.AlgoliaProvider,
		},
		Server: localServer,
		Database: dbconfig.Config{
			OAuth2TokenEncryptionKey: localOAuth2TokenEncryptionKey,
			Debug:                    true,
			RunMigrations:            true,
			LogQueries:               true,
			MaxPingAttempts:          maxAttempts,
			PingWaitPeriod:           time.Second,
			ConnectionDetails:        devPostgresDBConnDetails,
		},
		Observability: observability.Config{
			Logging: localLogConfig,
			Tracing: localTracingConfig,
		},
		Services: config.ServicesConfig{
			AuditLogEntries: auditlogentriesservice.Config{},
			Auth: authservice.Config{
				OAuth2: authservice.OAuth2Config{
					Domain:               "http://localhost:9000",
					AccessTokenLifespan:  time.Hour,
					RefreshTokenLifespan: time.Hour,
					Debug:                false,
				},
				SSO: authservice.SSOConfigs{
					Google: authservice.GoogleSSOConfig{
						CallbackURL: "https://app.whatever.dev/auth/google/callback",
					},
				},
				Cookies:               localCookies,
				Debug:                 true,
				EnableUserSignup:      true,
				MinimumUsernameLength: 3,
				MinimumPasswordLength: 8,
				DataChangesTopicName:  dataChangesTopicName,
			},
			Users: usersservice.Config{
				DataChangesTopicName: dataChangesTopicName,
				Uploads: uploads.Config{
					Debug: true,
					Storage: objectstorage.Config{
						UploadFilenameKey: "avatar",
						Provider:          objectstorage.FilesystemProvider,
						BucketName:        "avatars",
						FilesystemConfig: &objectstorage.FilesystemConfig{
							RootDirectory: "/uploads",
						},
					},
				},
			},
			Accounts: accountsservice.Config{
				DataChangesTopicName: dataChangesTopicName,
			},
			AccountInvitations: accountinvitationsservice.Config{
				DataChangesTopicName: dataChangesTopicName,
			},
			Webhooks: webhooksservice.Config{
				DataChangesTopicName: dataChangesTopicName,
			},
			ServiceSettings: servicesettings.Config{
				DataChangesTopicName: dataChangesTopicName,
			},
			ServiceSettingConfigurations: servicesettingconfigurations.Config{
				DataChangesTopicName: dataChangesTopicName,
			},
			OAuth2Clients: oauth2clientsservice.Config{
				DataChangesTopicName: dataChangesTopicName,
			},
			UserNotifications: usernotificationsservice.Config{
				DataChangesTopicName: dataChangesTopicName,
			},
		},
	}
}

func buildLocalDevelopmentServiceConfig(local bool) func(context.Context, string) error {
	const localUploadsDir = "artifacts/uploads"
	const localRedisAddr = "localhost:6379"
	return func(ctx context.Context, filePath string) error {
		cfg := buildDevConfig()

		if local {
			cfg.Database.ConnectionDetails = "postgres://dbuser:hunter2@localhost:5432/service-name?sslmode=disable"
			cfg.Events.Consumers.Redis.QueueAddresses = []string{localRedisAddr}
			cfg.Events.Publishers.Redis.QueueAddresses = []string{localRedisAddr}
			cfg.Services.Users.Uploads.Storage.FilesystemConfig.RootDirectory = localUploadsDir
		}

		return saveConfig(ctx, filePath, cfg, true, true)
	}
}

func buildIntegrationTestsConfig() *config.InstanceConfig {
	return &config.InstanceConfig{
		Routing: localRoutingConfig,
		Meta: config.MetaSettings{
			Debug:   false,
			RunMode: testingEnv,
		},
		Events: msgconfig.Config{
			Consumers: msgconfig.MessageQueueConfig{
				Provider: msgconfig.ProviderRedis,
				Redis: redis.Config{
					QueueAddresses: []string{workerQueueAddress},
				},
			},
			Publishers: msgconfig.MessageQueueConfig{
				Provider: msgconfig.ProviderRedis,
				Redis: redis.Config{
					QueueAddresses: []string{workerQueueAddress},
				},
			},
		},
		Encoding: encoding.Config{
			ContentType: contentTypeJSON,
		},
		Server: http.Config{
			Debug:           false,
			HTTPPort:        defaultPort,
			StartupDeadline: time.Minute,
		},
		Database: dbconfig.Config{
			OAuth2TokenEncryptionKey: localOAuth2TokenEncryptionKey,
			Debug:                    true,
			RunMigrations:            true,
			LogQueries:               true,
			MaxPingAttempts:          maxAttempts,
			PingWaitPeriod:           1500 * time.Millisecond,
			ConnectionDetails:        devPostgresDBConnDetails,
		},
		Observability: observability.Config{
			Logging: logcfg.Config{
				Level:    logging.InfoLevel,
				Provider: logcfg.ProviderSlog,
			},
			Tracing: localTracingConfig,
		},
		Services: config.ServicesConfig{
			AuditLogEntries: auditlogentriesservice.Config{},
			Auth: authservice.Config{
				OAuth2: authservice.OAuth2Config{
					Domain:               "http://localhost:9000",
					AccessTokenLifespan:  time.Hour,
					RefreshTokenLifespan: time.Hour,
					Debug:                false,
				},
				Cookies: authservice.CookieConfig{
					Name:       defaultCookieName,
					Domain:     defaultCookieDomain,
					HashKey:    debugCookieSecret,
					BlockKey:   debugCookieSigningKey,
					Lifetime:   authservice.DefaultCookieLifetime,
					SecureOnly: false,
				},
				Debug:                 false,
				EnableUserSignup:      true,
				MinimumUsernameLength: 3,
				MinimumPasswordLength: 8,
				DataChangesTopicName:  dataChangesTopicName,
			},
			Users: usersservice.Config{
				DataChangesTopicName: dataChangesTopicName,
				Uploads: uploads.Config{
					Debug: false,
					Storage: objectstorage.Config{
						Provider:   "memory",
						BucketName: "avatars",
						S3Config:   nil,
					},
				},
			},
			Accounts: accountsservice.Config{
				DataChangesTopicName: dataChangesTopicName,
			},
			AccountInvitations: accountinvitationsservice.Config{
				DataChangesTopicName: dataChangesTopicName,
			},
			Webhooks: webhooksservice.Config{
				DataChangesTopicName: dataChangesTopicName,
			},
			ServiceSettings: servicesettings.Config{
				DataChangesTopicName: dataChangesTopicName,
			},
			ServiceSettingConfigurations: servicesettingconfigurations.Config{
				DataChangesTopicName: dataChangesTopicName,
			},
			UserNotifications: usernotificationsservice.Config{
				DataChangesTopicName: dataChangesTopicName,
			},
		},
	}
}

func integrationTestConfig(ctx context.Context, filePath string) error {
	cfg := buildIntegrationTestsConfig()

	return saveConfig(ctx, filePath, cfg, true, true)
}

func main() {
	ctx := context.Background()

	for filePath, fun := range files {
		if err := fun(ctx, filePath); err != nil {
			log.Fatalf("error rendering %s: %v", filePath, err)
		}
	}
}
