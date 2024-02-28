package main

import (
	"fmt"
	"strings"

	"github.com/cristalhq/builq"
)

const (
	accountsTableName = "accounts"

	/* #nosec G101 */
	webhookHMACSecretColumn = "webhook_hmac_secret"
)

var accountsColumns = []string{
	idColumn,
	nameColumn,
	"billing_status",
	"contact_phone",
	"payment_processor_customer_id",
	"subscription_plan_id",
	belongsToUserColumn,
	"time_zone",
	"address_line_1",
	"address_line_2",
	"city",
	"state",
	"zip_code",
	"country",
	"latitude",
	"longitude",
	"last_payment_provider_sync_occurred_at",
	webhookHMACSecretColumn,
	createdAtColumn,
	lastUpdatedAtColumn,
	archivedAtColumn,
}

func buildAccountsQueries() []*Query {
	insertColumns := filterForInsert(accountsColumns)

	return []*Query{
		{
			Annotation: QueryAnnotation{
				Name: "AddToAccountDuringCreation",
				Type: ExecType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`INSERT INTO account_user_memberships (
	%s
) VALUES (
	%s
);`,
				strings.Join(filterForInsert(accountUserMembershipsColumns, "default_account"), ",\n\t"),
				strings.Join(applyToEach(filterForInsert(accountUserMembershipsColumns, "default_account"), func(_ int, s string) string {
					return fmt.Sprintf("sqlc.arg(%s)", s)
				}), ",\n\t"),
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "ArchiveAccount",
				Type: ExecRowsType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`UPDATE %s SET
	%s = %s,
	%s = %s
WHERE %s IS NULL
	AND %s = sqlc.arg(%s)
	AND %s = sqlc.arg(%s);`,
				accountsTableName,
				lastUpdatedAtColumn,
				currentTimeExpression,
				archivedAtColumn,
				currentTimeExpression,
				archivedAtColumn,
				belongsToUserColumn,
				belongsToUserColumn,
				idColumn,
				idColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "CreateAccount",
				Type: ExecType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`INSERT INTO %s (
	%s
) VALUES (
	%s
);`,
				accountsTableName,
				strings.Join(filterForInsert(
					insertColumns,
					"time_zone",
					"payment_processor_customer_id",
					"last_payment_provider_sync_occurred_at",
					"subscription_plan_id",
				), ",\n\t"),
				strings.Join(applyToEach(filterForInsert(
					insertColumns,
					"time_zone",
					"payment_processor_customer_id",
					"last_payment_provider_sync_occurred_at",
					"subscription_plan_id",
				), func(_ int, s string) string {
					return fmt.Sprintf("sqlc.arg(%s)", s)
				}), ",\n\t"),
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "GetAccountByIDWithMemberships",
				Type: ManyType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT
	%s
FROM %s
	JOIN %s ON %s.%s = %s.%s
	JOIN %s ON %s.%s = %s.%s
WHERE %s.%s IS NULL
	AND %s.%s IS NULL
	AND %s.%s = sqlc.arg(%s);`,
				strings.Join(append(
					append(
						applyToEach(accountsColumns, func(_ int, s string) string {
							return fmt.Sprintf("%s.%s", accountsTableName, s)
						}),
						applyToEach(usersColumns, func(_ int, s string) string {
							return fmt.Sprintf("%s.%s as user_%s", usersTableName, s, s)
						})...,
					),
					applyToEach(accountUserMembershipsColumns, func(_ int, s string) string {
						return fmt.Sprintf("%s.%s as membership_%s", accountUserMembershipsTableName, s, s)
					})...,
				), ",\n\t"),
				accountsTableName,
				accountUserMembershipsTableName, accountUserMembershipsTableName, belongsToAccountColumn, accountsTableName, idColumn,
				usersTableName, accountUserMembershipsTableName, belongsToUserColumn, usersTableName, idColumn,
				accountsTableName, archivedAtColumn,
				accountUserMembershipsTableName, archivedAtColumn,
				accountsTableName, idColumn, idColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "GetAccountsForUser",
				Type: ManyType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT
	%s,
	(
		SELECT COUNT(%s.%s)
		FROM %s
			JOIN %s ON %s.%s = %s.%s
		WHERE %s.%s IS NULL
			AND %s.%s = sqlc.arg(%s)%s
	) as filtered_count,
	%s
FROM %s
	JOIN %s ON %s.%s = %s.%s
	JOIN %s ON %s.%s = %s.%s
WHERE %s.%s IS NULL
	AND %s.%s IS NULL
	AND %s.%s = sqlc.arg(%s)
	%s
%s;`,
				strings.Join(applyToEach(accountsColumns, func(_ int, s string) string {
					return fmt.Sprintf("%s.%s", accountsTableName, s)
				}), ",\n\t"),
				accountsTableName, idColumn,
				accountsTableName,
				accountUserMembershipsTableName, accountUserMembershipsTableName, belongsToAccountColumn, accountsTableName, idColumn,
				accountsTableName, archivedAtColumn,
				accountUserMembershipsTableName, belongsToUserColumn, belongsToUserColumn,
				strings.Join(applyToEach(strings.Split(buildFilterConditions(
					accountsTableName,
					true,
				), "\n"), func(i int, s string) string {
					if i == 0 {
						return fmt.Sprintf("\n\t\t\t%s", s)
					}
					return fmt.Sprintf("\n\t\t%s", s)
				}), ""),
				buildTotalCountSelect(accountsTableName, true),
				accountsTableName,
				accountUserMembershipsTableName, accountUserMembershipsTableName, belongsToAccountColumn, accountsTableName, idColumn,
				usersTableName, accountUserMembershipsTableName, belongsToUserColumn, usersTableName, idColumn,
				accountsTableName, archivedAtColumn,
				accountUserMembershipsTableName, archivedAtColumn,
				accountUserMembershipsTableName, belongsToUserColumn, belongsToUserColumn,
				buildFilterConditions(
					accountsTableName,
					true,
				),
				offsetLimitAddendum,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "UpdateAccount",
				Type: ExecRowsType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`UPDATE %s SET
	%s,
	%s = %s
WHERE %s IS NULL
	AND %s = sqlc.arg(%s)
	AND %s = sqlc.arg(%s);`,
				accountsTableName,
				strings.Join(
					applyToEach(
						filterForUpdate(
							accountsColumns,
							"billing_status",
							"payment_processor_customer_id",
							"subscription_plan_id",
							belongsToUserColumn,
							"time_zone",
							"last_payment_provider_sync_occurred_at",
							"webhook_hmac_secret",
						),
						func(_ int, s string) string {
							return fmt.Sprintf("%s = sqlc.arg(%s)", s, s)
						},
					),
					",\n\t",
				),
				lastUpdatedAtColumn,
				currentTimeExpression,
				archivedAtColumn,
				belongsToUserColumn,
				belongsToUserColumn,
				idColumn,
				idColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "UpdateAccountWebhookEncryptionKey",
				Type: ExecRowsType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`UPDATE %s SET
	%s = sqlc.arg(%s),
	%s = %s
WHERE %s IS NULL
	AND %s = sqlc.arg(%s)
	AND %s = sqlc.arg(%s);`,
				accountsTableName,
				webhookHMACSecretColumn, webhookHMACSecretColumn,
				lastUpdatedAtColumn, currentTimeExpression,
				archivedAtColumn,
				belongsToUserColumn, belongsToUserColumn,
				idColumn, idColumn,
			)),
		},
	}
}
