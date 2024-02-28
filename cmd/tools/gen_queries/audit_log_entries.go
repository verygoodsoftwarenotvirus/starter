package main

import (
	"fmt"
	"strings"

	"github.com/cristalhq/builq"
)

const (
	auditLogsTableName = "audit_log_entries"
	resourceTypeColumn = "resource_type"
	eventTypeColumn    = "event_type"
)

var (
	auditLogsColumns = []string{
		idColumn,
		resourceTypeColumn,
		"relevant_id",
		eventTypeColumn,
		"changes",
		belongsToUserColumn,
		belongsToAccountColumn,
		createdAtColumn,
	}
)

func buildAuditLogEntryQueries() []*Query {
	insertColumns := filterForInsert(auditLogsColumns)
	fullSelectColumns := applyToEach(auditLogsColumns, func(_ int, s string) string {
		return fullColumnName(auditLogsTableName, s)
	})

	return []*Query{
		{
			Annotation: QueryAnnotation{
				Name: "CreateAuditLogEntry",
				Type: ExecType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`INSERT INTO %s (
	%s
) VALUES (
	%s
);`,
				auditLogsTableName,
				strings.Join(insertColumns, ",\n\t"),
				strings.Join(applyToEach(insertColumns, func(_ int, s string) string {
					if s == belongsToUserColumn || s == belongsToAccountColumn {
						return fmt.Sprintf("sqlc.narg(%s)", s)
					}
					return fmt.Sprintf("sqlc.arg(%s)", s)
				}), ",\n\t"),
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "GetAuditLogEntry",
				Type: OneType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT 
	%s
FROM %s
WHERE %s.%s = sqlc.arg(%s);`,
				strings.Join(fullSelectColumns, ",\n\t"),
				auditLogsTableName,
				auditLogsTableName, idColumn, idColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "GetAuditLogEntriesForUser",
				Type: ManyType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT
	%s,
	%s,
	%s
FROM %s
WHERE %s
%s;`,
				strings.Join(fullSelectColumns, ",\n\t"),
				buildFilterCountSelect(
					auditLogsTableName,
					false,
					false,
					fmt.Sprintf("%s.%s = sqlc.arg(%s)", auditLogsTableName, belongsToUserColumn, belongsToUserColumn),
				),
				buildTotalCountSelect(
					auditLogsTableName,
					false,
					fmt.Sprintf("%s.%s = sqlc.arg(%s)", auditLogsTableName, belongsToUserColumn, belongsToUserColumn),
				),
				auditLogsTableName,
				strings.TrimPrefix(buildFilterConditions(
					auditLogsTableName,
					false,
					fmt.Sprintf("%s.%s = sqlc.arg(%s)", auditLogsTableName, belongsToUserColumn, belongsToUserColumn),
				), "AND "),
				offsetLimitAddendum,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "GetAuditLogEntriesForUserAndResourceType",
				Type: ManyType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT
	%s,
	%s,
	%s
FROM %s
WHERE %s
%s;`,
				strings.Join(fullSelectColumns, ",\n\t"),
				buildFilterCountSelect(
					auditLogsTableName,
					false,
					false,
					fmt.Sprintf("%s.%s = sqlc.arg(%s)", auditLogsTableName, belongsToUserColumn, belongsToUserColumn),
					fmt.Sprintf("%s.%s = ANY(sqlc.arg(%s)::text[])", auditLogsTableName, resourceTypeColumn, "resources"),
				),
				buildTotalCountSelect(
					auditLogsTableName,
					false,
					fmt.Sprintf("%s.%s = sqlc.arg(%s)", auditLogsTableName, belongsToUserColumn, belongsToUserColumn),
					fmt.Sprintf("%s.%s = ANY(sqlc.arg(%s)::text[])", auditLogsTableName, resourceTypeColumn, "resources"),
				),
				auditLogsTableName,
				strings.TrimPrefix(buildFilterConditions(
					auditLogsTableName,
					false,
					fmt.Sprintf("%s.%s = sqlc.arg(%s)", auditLogsTableName, belongsToUserColumn, belongsToUserColumn),
					fmt.Sprintf("%s.%s = ANY(sqlc.arg(%s)::text[])", auditLogsTableName, resourceTypeColumn, "resources"),
				), "AND "),
				offsetLimitAddendum,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "GetAuditLogEntriesForAccount",
				Type: ManyType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT
	%s,
	%s,
	%s
FROM %s
WHERE %s
%s;`,
				strings.Join(fullSelectColumns, ",\n\t"),
				buildFilterCountSelect(
					auditLogsTableName,
					false,
					false,
					fmt.Sprintf("%s.%s = sqlc.arg(%s)", auditLogsTableName, belongsToAccountColumn, belongsToAccountColumn),
				),
				buildTotalCountSelect(
					auditLogsTableName,
					false,
					fmt.Sprintf("%s.%s = sqlc.arg(%s)", auditLogsTableName, belongsToAccountColumn, belongsToAccountColumn),
				),
				auditLogsTableName,
				strings.TrimPrefix(buildFilterConditions(
					auditLogsTableName,
					false,
					fmt.Sprintf("%s.%s = sqlc.arg(%s)", auditLogsTableName, belongsToAccountColumn, belongsToAccountColumn),
				), "AND "),
				offsetLimitAddendum,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "GetAuditLogEntriesForAccountAndResourceType",
				Type: ManyType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT
	%s,
	%s,
	%s
FROM %s
WHERE %s
%s;`,
				strings.Join(fullSelectColumns, ",\n\t"),
				buildFilterCountSelect(
					auditLogsTableName,
					false,
					false,
					fmt.Sprintf("%s.%s = sqlc.arg(%s)", auditLogsTableName, belongsToAccountColumn, belongsToAccountColumn),
					fmt.Sprintf("%s.%s = ANY(sqlc.arg(%s)::text[])", auditLogsTableName, resourceTypeColumn, "resources"),
				),
				buildTotalCountSelect(
					auditLogsTableName,
					false,
					fmt.Sprintf("%s.%s = sqlc.arg(%s)", auditLogsTableName, belongsToAccountColumn, belongsToAccountColumn),
					fmt.Sprintf("%s.%s = ANY(sqlc.arg(%s)::text[])", auditLogsTableName, resourceTypeColumn, "resources"),
				),
				auditLogsTableName,
				strings.TrimPrefix(buildFilterConditions(
					auditLogsTableName,
					false,
					fmt.Sprintf("%s.%s = sqlc.arg(%s)", auditLogsTableName, belongsToAccountColumn, belongsToAccountColumn),
					fmt.Sprintf("%s.%s = ANY(sqlc.arg(%s)::text[])", auditLogsTableName, resourceTypeColumn, "resources"),
				), "AND "),
				offsetLimitAddendum,
			)),
		},
	}
}
