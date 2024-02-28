package main

import (
	"fmt"
	"strings"

	"github.com/cristalhq/builq"
)

const (
	webhooksTableName = "webhooks"
)

var (
	webhooksColumns = []string{
		idColumn,
		nameColumn,
		"content_type",
		"url",
		"method",
		createdAtColumn,
		lastUpdatedAtColumn,
		archivedAtColumn,
		belongsToAccountColumn,
	}
)

func buildWebhooksQueries() []*Query {
	insertColumns := filterForInsert(webhooksColumns)
	fullSelectColumns := mergeColumns(
		applyToEach(webhooksColumns, func(_ int, s string) string {
			return fullColumnName(webhooksTableName, s)
		}),
		applyToEach(webhookTriggerEventsColumns, func(_ int, s string) string {
			return fullColumnName(webhookTriggerEventsTableName, s)
		}),
		5,
	)

	return []*Query{
		{
			Annotation: QueryAnnotation{
				Name: "ArchiveWebhook",
				Type: ExecRowsType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`UPDATE %s SET
	%s = %s
WHERE %s IS NULL
	AND %s = sqlc.arg(%s)
	AND %s = sqlc.arg(%s);`,
				webhooksTableName,
				archivedAtColumn, currentTimeExpression,
				archivedAtColumn,
				idColumn, idColumn,
				belongsToAccountColumn, belongsToAccountColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "ArchiveWebhookTriggerEvent",
				Type: ExecRowsType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`UPDATE %s SET
	%s = %s
WHERE %s IS NULL
	AND %s = sqlc.arg(%s)
	AND %s = sqlc.arg(%s);`,
				webhookTriggerEventsTableName,
				archivedAtColumn, currentTimeExpression,
				archivedAtColumn,
				idColumn, idColumn,
				belongsToWebhookColumn, belongsToWebhookColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "CreateWebhook",
				Type: ExecType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`INSERT INTO %s (
	%s
) VALUES (
	%s
);`,
				webhooksTableName,
				strings.Join(insertColumns, ",\n\t"),
				strings.Join(applyToEach(insertColumns, func(_ int, s string) string {
					return fmt.Sprintf("sqlc.arg(%s)", s)
				}), ",\n\t"),
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "CheckWebhookExistence",
				Type: OneType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT EXISTS(
	SELECT %s.%s
	FROM %s
	WHERE %s.%s IS NULL
	AND %s.%s = sqlc.arg(%s)
	AND %s.%s = sqlc.arg(%s)
);`,
				webhooksTableName, idColumn,
				webhooksTableName,
				webhooksTableName, archivedAtColumn,
				webhooksTableName, idColumn, idColumn,
				webhooksTableName, belongsToAccountColumn, belongsToAccountColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "GetWebhooksForAccount",
				Type: ManyType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT
	%s,
	%s,
	%s
FROM %s
	JOIN %s ON %s.%s = %s.%s
WHERE %s.%s IS NULL
	%s
%s;`,
				strings.Join(fullSelectColumns, ",\n\t"),
				buildFilterCountSelect(webhooksTableName, true, true, "webhooks.belongs_to_account = sqlc.arg(account_id)"),
				buildTotalCountSelect(
					webhooksTableName,
					true,
					"webhooks.belongs_to_account = sqlc.arg(account_id)",
					"webhook_trigger_events.archived_at IS NULL",
				),
				webhooksTableName,
				webhookTriggerEventsTableName, webhooksTableName, idColumn, webhookTriggerEventsTableName, belongsToWebhookColumn,
				webhooksTableName, archivedAtColumn,
				buildFilterConditions(
					webhooksTableName,
					true,
					"webhooks.belongs_to_account = sqlc.arg(account_id)",
					"webhook_trigger_events.archived_at IS NULL",
				),
				offsetLimitAddendum,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "GetWebhooksForAccountAndEvent",
				Type: ManyType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT 
	%s
FROM %s
	JOIN %s ON %s.%s = %s.%s
WHERE %s.%s IS NULL
	AND %s.%s = sqlc.arg(%s)
	AND %s.%s = sqlc.arg(%s)
	AND %s.%s IS NULL;`,
				strings.Join(applyToEach(webhooksColumns, func(_ int, s string) string {
					return fullColumnName(webhooksTableName, s)
				}), ",\n\t"),
				webhooksTableName,
				webhookTriggerEventsTableName, webhooksTableName, idColumn, webhookTriggerEventsTableName, belongsToWebhookColumn,
				webhookTriggerEventsTableName, archivedAtColumn,
				webhookTriggerEventsTableName, triggerEventColumn, triggerEventColumn,
				webhooksTableName, belongsToAccountColumn, belongsToAccountColumn,
				webhooksTableName, archivedAtColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "GetWebhook",
				Type: ManyType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT 
	%s
FROM %s
	JOIN %s ON %s.%s = %s.%s
WHERE %s.%s IS NULL
	AND %s.%s IS NULL
	AND %s.%s = sqlc.arg(%s)
	AND %s.%s = sqlc.arg(%s);`,
				strings.Join(applyToEach(fullSelectColumns, func(_ int, s string) string {
					parts := strings.Split(s, ".")
					return fmt.Sprintf("%s as %s_%s",
						s, strings.TrimSuffix(parts[0], "s"), parts[1],
					)
				}), ",\n\t"),
				webhooksTableName,
				webhookTriggerEventsTableName, webhooksTableName, idColumn, webhookTriggerEventsTableName, belongsToWebhookColumn,
				webhookTriggerEventsTableName, archivedAtColumn,
				webhooksTableName, archivedAtColumn,
				webhooksTableName, belongsToAccountColumn, belongsToAccountColumn,
				webhooksTableName, idColumn, idColumn,
			)),
		},
	}
}
