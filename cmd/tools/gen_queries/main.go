package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/spf13/pflag"
)

var (
	checkOnlyFlag = pflag.Bool("check", false, "only check if files match")
)

func main() {
	pflag.Parse()

	var runErrors *multierror.Error

	queryOutput := map[string][]*Query{
		"admin.sql":                          buildAdminQueries(),
		"webhooks.sql":                       buildWebhooksQueries(),
		"user_notifications.sql":             buildUserNotificationQueries(),
		"users.sql":                          buildUsersQueries(),
		"accounts.sql":                       buildAccountsQueries(),
		"account_user_memberships.sql":       buildAccountUserMembershipsQueries(),
		"webhook_trigger_events.sql":         buildWebhookTriggerEventsQueries(),
		"password_reset_tokens.sql":          buildPasswordResetTokensQueries(),
		"oauth2_client_tokens.sql":           buildOAuth2ClientTokensQueries(),
		"oauth2_clients.sql":                 buildOAuth2ClientsQueries(),
		"service_settings.sql":               buildServiceSettingQueries(),
		"service_setting_configurations.sql": buildServiceSettingConfigurationQueries(),
		"account_invitations.sql":            buildAccountInvitationsQueries(),
		"audit_logs.sql":                     buildAuditLogEntryQueries(),
	}

	checkOnly := *checkOnlyFlag

	for filePath, queries := range queryOutput {
		localFilePath := path.Join("internal", "database", "postgres", "sqlc_queries", filePath)
		existingFile, err := os.ReadFile(localFilePath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				if _, err = os.Create(localFilePath); err != nil {
					log.Fatal(err)
				}
			}
			if err != nil {
				log.Fatal(err)
			}
		}

		var fileContent string
		for i, query := range queries {
			if i != 0 {
				fileContent += "\n"
			}
			fileContent += query.Render()
		}

		fileOutput := ""
		for _, line := range strings.Split(strings.TrimSpace(fileContent), "\n") {
			fileOutput += strings.TrimSuffix(line, " ") + "\n"
		}

		if string(existingFile) != fileOutput && checkOnly {
			runErrors = multierror.Append(runErrors, fmt.Errorf("files don't match: %s", filePath))
		}

		if !checkOnly {
			if err = os.WriteFile(localFilePath, []byte(fileOutput), 0o600); err != nil {
				runErrors = multierror.Append(runErrors, err)
			}
		}
	}

	if runErrors.ErrorOrNil() != nil {
		log.Fatal(runErrors)
	}
}
