package main

import (
	"fmt"
	"strings"

	"github.com/cristalhq/builq"
)

const (
	webhookTriggerEventsTableName = "webhook_trigger_events"
	belongsToWebhookColumn        = "belongs_to_webhook"
	triggerEventColumn            = "trigger_event"
)

var (
	webhookTriggerEventsColumns = []string{
		idColumn,
		triggerEventColumn,
		belongsToWebhookColumn,
		createdAtColumn,
		archivedAtColumn,
	}
)

func buildWebhookTriggerEventsQueries() []*Query {
	insertColumns := filterForInsert(webhookTriggerEventsColumns)

	return []*Query{
		{
			Annotation: QueryAnnotation{
				Name: "CreateWebhookTriggerEvent",
				Type: ExecType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`INSERT INTO %s (
	%s
) VALUES (
	%s
);`,
				webhookTriggerEventsTableName,
				strings.Join(insertColumns, ",\n\t"),
				strings.Join(applyToEach(insertColumns, func(i int, s string) string {
					return fmt.Sprintf("sqlc.arg(%s)", s)
				}), ",\n\t"),
			)),
		},
	}
}
