package config

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"

	analyticscfg "github.com/verygoodsoftwarenotvirus/starter/internal/analytics/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/analytics/posthog"
	"github.com/verygoodsoftwarenotvirus/starter/internal/analytics/segment"
	dbconfig "github.com/verygoodsoftwarenotvirus/starter/internal/database/config"
	emailcfg "github.com/verygoodsoftwarenotvirus/starter/internal/email/config"
	"github.com/verygoodsoftwarenotvirus/starter/internal/email/sendgrid"
	"github.com/verygoodsoftwarenotvirus/starter/internal/search/algolia"
	searchcfg "github.com/verygoodsoftwarenotvirus/starter/internal/search/config"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/googleapis/gax-go/v2"
)

const (
	dataChangesTopicAccessName           = "data_changes_topic_name"
	googleCloudCloudSQLSocket            = "/cloudsql"
	gcpConfigFilePathEnvVarKey           = "CONFIGURATION_FILEPATH"
	gcpPortEnvVarKey                     = "PORT"
	gcpDatabaseSocketDirEnvVarKey        = "DB_SOCKET_DIR"
	gcpDatabaseUserEnvVarKey             = "COMPANY_NAME_DATABASE_USER"
	gcpDatabaseNameEnvVarKey             = "COMPANY_NAME_DATABASE_NAME"
	gcpDatabaseInstanceConnNameEnvVarKey = "COMPANY_NAME_DATABASE_INSTANCE_CONNECTION_NAME"
	gcpCookieHashKeyEnvVarKey            = "COMPANY_NAME_COOKIE_HASH_KEY"
	gcpCookieBlockKeyEnvVarKey           = "COMPANY_NAME_COOKIE_BLOCK_KEY"
	gcpAlgoliaAPIKeyEnvVarKey            = "COMPANY_NAME_ALGOLIA_API_KEY"
	gcpAlgoliaAppIDEnvVarKey             = "COMPANY_NAME_ALGOLIA_APPLICATION_ID"
	gcpGoogleSSOClientIDEnvVarKey        = "COMPANY_NAME_GOOGLE_SSO_CLIENT_ID"
	gcpGoogleSSOClientSecretEnvVarKey    = "COMPANY_NAME_GOOGLE_SSO_CLIENT_SECRET"
	/* #nosec G101 */
	gcpOauth2TokenEncryptionKeyEnvVarKey = "COMPANY_NAME_OAUTH2_TOKEN_ENCRYPTION_KEY"
	/* #nosec G101 */
	gcpDatabaseUserPasswordEnvVarKey = "COMPANY_NAME_DATABASE_PASSWORD"
	/* #nosec G101 */
	gcpSendgridTokenEnvVarKey = "COMPANY_NAME_SENDGRID_API_TOKEN"
	/* #nosec G101 */
	gcpSegmentTokenEnvVarKey = "COMPANY_NAME_SEGMENT_API_TOKEN"
	/* #nosec G101 */
	gcpPostHogKeyEnvVarKey = "COMPANY_NAME_POSTHOG_API_KEY"
)

// SecretVersionAccessor is an interface abstraction of the GCP Secret Manager API call we use during config hydration.
// This interface exists for testing purposes. Yes, you're not supposed to write arbitrary interfaces for testing.
// Yes I'm still doing it.
type SecretVersionAccessor interface {
	AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error)
}

func buildDatabaseURIFromGCPEnvVars() string {
	socketDir, isSet := os.LookupEnv(gcpDatabaseSocketDirEnvVarKey)
	if !isSet {
		socketDir = googleCloudCloudSQLSocket
	}

	return fmt.Sprintf(
		"user=%s password=%s database=%s host=%s/%s",
		os.Getenv(gcpDatabaseUserEnvVarKey),
		os.Getenv(gcpDatabaseUserPasswordEnvVarKey),
		os.Getenv(gcpDatabaseNameEnvVarKey),
		socketDir,
		os.Getenv(gcpDatabaseInstanceConnNameEnvVarKey),
	)
}

// GetAPIServerConfigFromGoogleCloudRunEnvironment fetches an InstanceConfig from GCP Secret Manager.
func GetAPIServerConfigFromGoogleCloudRunEnvironment(ctx context.Context, client SecretVersionAccessor) (*InstanceConfig, error) {
	configBytes, err := os.ReadFile(os.Getenv(gcpConfigFilePathEnvVarKey))
	if err != nil {
		return nil, err
	}

	var cfg *InstanceConfig
	if err = json.NewDecoder(bytes.NewReader(configBytes)).Decode(&cfg); err != nil || cfg == nil {
		return nil, err
	}

	rawPort := os.Getenv(gcpPortEnvVarKey)
	var port uint64
	port, err = strconv.ParseUint(rawPort, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parsing port: %w", err)
	}
	cfg.Server.HTTPPort = uint16(port)

	// fetch supplementary data from env vars
	dbURI := buildDatabaseURIFromGCPEnvVars()

	cfg.Database.ConnectionDetails = dbURI
	cfg.Database.OAuth2TokenEncryptionKey = os.Getenv(gcpOauth2TokenEncryptionKeyEnvVarKey)
	cfg.Services.Auth.Cookies.HashKey = os.Getenv(gcpCookieHashKeyEnvVarKey)
	cfg.Services.Auth.Cookies.BlockKey = os.Getenv(gcpCookieBlockKeyEnvVarKey)
	cfg.Services.Auth.SSO.Google.ClientID = os.Getenv(gcpGoogleSSOClientIDEnvVarKey)
	cfg.Services.Auth.SSO.Google.ClientSecret = os.Getenv(gcpGoogleSSOClientSecretEnvVarKey)

	cfg.Search = searchcfg.Config{
		Provider: searchcfg.AlgoliaProvider,
		Algolia: &algolia.Config{
			APIKey: os.Getenv(gcpAlgoliaAPIKeyEnvVarKey),
			AppID:  os.Getenv(gcpAlgoliaAppIDEnvVarKey),
		},
	}

	// TODO: get this from the env var DATA_CHANGES_TOPIC_NAME, dump GOOGLE_CLOUD_SECRET_STORE_PREFIX
	changesTopic, err := fetchSecretFromSecretStore(ctx, client, dataChangesTopicAccessName)
	if err != nil {
		return nil, fmt.Errorf("getting data changes topic name from secret store: %w", err)
	}
	dataChangesTopicName := string(changesTopic)

	cfg.Email.Sendgrid.APIToken = os.Getenv(gcpSendgridTokenEnvVarKey)
	cfg.Analytics.Segment = &segment.Config{APIToken: os.Getenv(gcpSegmentTokenEnvVarKey)}

	cfg.Services.Accounts.DataChangesTopicName = dataChangesTopicName
	cfg.Services.AccountInvitations.DataChangesTopicName = dataChangesTopicName
	cfg.Services.Users.DataChangesTopicName = dataChangesTopicName
	cfg.Services.Webhooks.DataChangesTopicName = dataChangesTopicName
	cfg.Services.Auth.DataChangesTopicName = dataChangesTopicName
	cfg.Services.ServiceSettings.DataChangesTopicName = dataChangesTopicName
	cfg.Services.ServiceSettingConfigurations.DataChangesTopicName = dataChangesTopicName
	cfg.Services.UserNotifications.DataChangesTopicName = dataChangesTopicName

	if err = cfg.ValidateWithContext(ctx, true); err != nil {
		return nil, err
	}

	return cfg, nil
}

var secretStorePrefix = os.Getenv("GOOGLE_CLOUD_SECRET_STORE_PREFIX")

func buildSecretPathForGCPSecretStore(secretName string) string {
	return fmt.Sprintf(
		"%s/%s/versions/latest",
		secretStorePrefix,
		secretName,
	)
}

func fetchSecretFromSecretStore(ctx context.Context, client SecretVersionAccessor, secretName string) ([]byte, error) {
	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: buildSecretPathForGCPSecretStore(secretName),
	}

	result, err := client.AccessSecretVersion(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to access secret version: %w", err)
	}

	return result.Payload.Data, nil
}

// getWorkerConfigFromGoogleCloudSecretManager fetches an InstanceConfig from GCP Secret Manager.
func getWorkerConfigFromGoogleCloudSecretManager(ctx context.Context) (*InstanceConfig, error) {
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create secretmanager client: %w", err)
	}

	var cfg *InstanceConfig
	configBytes, err := fetchSecretFromSecretStore(ctx, client, "api_service_config")
	if err != nil {
		return nil, fmt.Errorf("fetching config from secret store: %w", err)
	}

	if err = json.NewDecoder(bytes.NewReader(configBytes)).Decode(&cfg); err != nil {
		return nil, err
	}

	if cfg == nil {
		return nil, errors.New("config is nil")
	}

	// fetch supplementary data from env vars
	dbURI := buildDatabaseURIFromGCPEnvVars()

	cfg.Search = searchcfg.Config{
		Provider: searchcfg.AlgoliaProvider,
		Algolia: &algolia.Config{
			APIKey: os.Getenv(gcpAlgoliaAPIKeyEnvVarKey),
			AppID:  os.Getenv(gcpAlgoliaAppIDEnvVarKey),
		},
	}

	cfg.Database.ConnectionDetails = dbURI
	cfg.Database.RunMigrations = false
	cfg.Database.OAuth2TokenEncryptionKey = os.Getenv(gcpOauth2TokenEncryptionKeyEnvVarKey)
	cfg.Email.Sendgrid.APIToken = os.Getenv(gcpSendgridTokenEnvVarKey)
	cfg.Analytics = analyticscfg.Config{
		Segment:  &segment.Config{APIToken: os.Getenv(gcpSegmentTokenEnvVarKey)},
		Posthog:  &posthog.Config{APIKey: os.Getenv(gcpPostHogKeyEnvVarKey)},
		Provider: analyticscfg.ProviderSegment,
	}

	return cfg, nil
}

// GetDataChangesWorkerConfigFromGoogleCloudSecretManager fetches an InstanceConfig from GCP Secret Manager.
func GetDataChangesWorkerConfigFromGoogleCloudSecretManager(ctx context.Context) (*InstanceConfig, error) {
	cfg, err := getWorkerConfigFromGoogleCloudSecretManager(ctx)
	if err != nil {
		return nil, err
	}

	cfg.Email = emailcfg.Config{}

	if err = cfg.ValidateWithContext(ctx, false); err != nil {
		return nil, err
	}

	return cfg, nil
}

// GetOutboundEmailerConfigFromGoogleCloudSecretManager fetches an InstanceConfig from GCP Secret Manager.
func GetOutboundEmailerConfigFromGoogleCloudSecretManager(ctx context.Context) (*InstanceConfig, error) {
	cfg, err := getWorkerConfigFromGoogleCloudSecretManager(ctx)
	if err != nil {
		return nil, err
	}

	cfg.Analytics = analyticscfg.Config{}
	cfg.Email = emailcfg.Config{
		Provider: emailcfg.ProviderSendgrid,
		Sendgrid: &sendgrid.Config{
			APIToken: os.Getenv(gcpSendgridTokenEnvVarKey),
		},
	}

	if err = cfg.ValidateWithContext(ctx, false); err != nil {
		return nil, err
	}

	return cfg, nil
}

// GetSearchDataIndexSchedulerConfigFromGoogleCloudSecretManager fetches an InstanceConfig from GCP Secret Manager.
func GetSearchDataIndexSchedulerConfigFromGoogleCloudSecretManager(ctx context.Context) (*InstanceConfig, error) {
	cfg, err := getWorkerConfigFromGoogleCloudSecretManager(ctx)
	if err != nil {
		return nil, err
	}

	cfg.Analytics = analyticscfg.Config{}
	cfg.Email = emailcfg.Config{}

	if err = cfg.ValidateWithContext(ctx, false); err != nil {
		return nil, err
	}

	return cfg, nil
}

// GetSearchDataIndexerConfigFromGoogleCloudSecretManager fetches an InstanceConfig from GCP Secret Manager.
func GetSearchDataIndexerConfigFromGoogleCloudSecretManager(ctx context.Context) (*InstanceConfig, error) {
	cfg, err := getWorkerConfigFromGoogleCloudSecretManager(ctx)
	if err != nil {
		return nil, err
	}

	cfg.Analytics = analyticscfg.Config{}
	cfg.Email = emailcfg.Config{}

	if err = cfg.ValidateWithContext(ctx, false); err != nil {
		return nil, err
	}

	return cfg, nil
}

// GetEmailProberConfigFromGoogleCloudSecretManager fetches an InstanceConfig from GCP Secret Manager.
func GetEmailProberConfigFromGoogleCloudSecretManager(ctx context.Context) (*InstanceConfig, error) {
	cfg, err := getWorkerConfigFromGoogleCloudSecretManager(ctx)
	if err != nil {
		return nil, err
	}

	// this just needs to pass validation, the prober has no business connecting to the database
	cfg.Database = dbconfig.Config{ConnectionDetails: " ", OAuth2TokenEncryptionKey: " "}
	cfg.Analytics = analyticscfg.Config{}
	cfg.Email = emailcfg.Config{
		Provider: emailcfg.ProviderSendgrid,
		Sendgrid: &sendgrid.Config{
			APIToken: os.Getenv(gcpSendgridTokenEnvVarKey),
		},
	}

	if err = cfg.ValidateWithContext(ctx, false); err != nil {
		return nil, err
	}

	return cfg, nil
}
