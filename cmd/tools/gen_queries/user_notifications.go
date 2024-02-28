package main

import (
	"fmt"
	"strings"

	"github.com/cristalhq/builq"
)

const (
	userNotificationsTableName      = "user_notifications"
	contentColumn                   = "content"
	statusColumn                    = "status"
	userNotificationStatusUnread    = "unread"
	userNotificationStatusRead      = "read"
	userNotificationStatusDismissed = "dismissed"
)

var (
	userNotificationsColumns = []string{
		idColumn,
		"content",
		"status",
		belongsToUserColumn,
		createdAtColumn,
		lastUpdatedAtColumn,
	}
)

func buildUserNotificationQueries() []*Query {
	insertColumns := filterForInsert(userNotificationsColumns, "status")
	fullSelectColumns := applyToEach(userNotificationsColumns, func(_ int, s string) string {
		return fullColumnName(userNotificationsTableName, s)
	})

	return []*Query{
		{
			Annotation: QueryAnnotation{
				Name: "CreateUserNotification",
				Type: ExecType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`INSERT INTO %s (
	%s
) VALUES (
	%s
);`,
				userNotificationsTableName,
				strings.Join(insertColumns, ",\n\t"),
				strings.Join(applyToEach(insertColumns, func(_ int, s string) string {
					return fmt.Sprintf("sqlc.arg(%s)", s)
				}), ",\n\t"),
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "GetUserNotification",
				Type: OneType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT
	%s
FROM %s
WHERE %s = sqlc.arg(%s)
AND %s.%s = sqlc.arg(%s);`,
				strings.Join(applyToEach(userNotificationsColumns, func(i int, s string) string {
					return fmt.Sprintf("%s.%s", userNotificationsTableName, s)
				}), ",\n\t"),
				userNotificationsTableName,
				belongsToUserColumn, belongsToUserColumn,
				userNotificationsTableName, idColumn, idColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "CheckUserNotificationExistence",
				Type: OneType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT EXISTS(
	SELECT %s.%s
	FROM %s
	WHERE %s.%s = sqlc.arg(%s)
	AND %s.%s = sqlc.arg(%s)
);`,
				userNotificationsTableName, idColumn,
				userNotificationsTableName,
				userNotificationsTableName, idColumn, idColumn,
				userNotificationsTableName, belongsToUserColumn, belongsToUserColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "GetUserNotificationsForUser",
				Type: ManyType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT
	%s,
	%s,
	%s
FROM %s
WHERE %s%s
%s;`,
				strings.Join(fullSelectColumns, ",\n\t"),
				buildFilterCountSelect(
					userNotificationsTableName,
					true,
					false,
					fmt.Sprintf("user_notifications.status != '%s'", userNotificationStatusDismissed),
					"user_notifications.belongs_to_user = sqlc.arg(user_id)",
				),
				buildTotalCountSelect(
					userNotificationsTableName,
					false,
					fmt.Sprintf("user_notifications.status != '%s'", userNotificationStatusDismissed),
					"user_notifications.belongs_to_user = sqlc.arg(user_id)",
				),
				userNotificationsTableName,
				fmt.Sprintf("user_notifications.status != '%s'\n\t", userNotificationStatusDismissed),
				buildFilterConditions(
					userNotificationsTableName,
					true,
					"user_notifications.belongs_to_user = sqlc.arg(user_id)",
				),
				offsetLimitAddendum,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "UpdateUserNotification",
				Type: ExecRowsType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`UPDATE %s SET
	%s,
	%s = %s
WHERE %s = sqlc.arg(%s);`,
				userNotificationsTableName,
				strings.Join(applyToEach(filterForUpdate(userNotificationsColumns, contentColumn, belongsToUserColumn), func(i int, s string) string {
					return fmt.Sprintf("%s = sqlc.arg(%s)", s, s)
				}), ",\n\t"),
				lastUpdatedAtColumn, currentTimeExpression,
				idColumn, idColumn,
			)),
		},
	}
}
