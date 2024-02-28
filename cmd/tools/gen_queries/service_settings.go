package main

import (
	"fmt"
	"strings"

	"github.com/cristalhq/builq"
)

const (
	serviceSettingsTableName = "service_settings"
)

var serviceSettingsColumns = []string{
	idColumn,
	nameColumn,
	"type",
	descriptionColumn,
	"default_value",
	"enumeration",
	"admins_only",
	createdAtColumn,
	lastUpdatedAtColumn,
	archivedAtColumn,
}

func buildServiceSettingQueries() []*Query {
	insertColumns := filterForInsert(serviceSettingsColumns)

	return []*Query{
		{
			Annotation: QueryAnnotation{
				Name: "ArchiveServiceSetting",
				Type: ExecRowsType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`UPDATE %s SET %s = %s WHERE %s = sqlc.arg(%s);`,
				serviceSettingsTableName,
				archivedAtColumn,
				currentTimeExpression,
				idColumn,
				idColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "CreateServiceSetting",
				Type: ExecType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`INSERT INTO %s (
	%s
) VALUES (
	%s
);`,
				serviceSettingsTableName,
				strings.Join(insertColumns, ",\n\t"),
				strings.Join(applyToEach(insertColumns, func(_ int, s string) string {
					return fmt.Sprintf("sqlc.arg(%s)", s)
				}), ",\n\t"),
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "CheckServiceSettingExistence",
				Type: OneType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT EXISTS (
	SELECT %s.%s
	FROM %s
	WHERE %s.%s IS NULL
	AND %s.%s = sqlc.arg(%s)
);`,
				serviceSettingsTableName, idColumn,
				serviceSettingsTableName,
				serviceSettingsTableName, archivedAtColumn,
				serviceSettingsTableName, idColumn, idColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "GetServiceSettings",
				Type: ManyType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT
	%s,
	%s,
	%s
FROM %s
WHERE %s.%s IS NULL
	%s
%s;`,
				strings.Join(applyToEach(serviceSettingsColumns, func(i int, s string) string {
					return fmt.Sprintf("%s.%s", serviceSettingsTableName, s)
				}), ",\n\t"),
				buildFilterCountSelect(serviceSettingsTableName, true, true),
				buildTotalCountSelect(serviceSettingsTableName, true),
				serviceSettingsTableName,
				serviceSettingsTableName, archivedAtColumn,
				buildFilterConditions(
					serviceSettingsTableName,
					true,
				),
				offsetLimitAddendum,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "GetServiceSetting",
				Type: OneType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT
	%s
FROM %s
WHERE %s.%s IS NULL
	AND %s.%s = sqlc.arg(%s);`,
				strings.Join(applyToEach(serviceSettingsColumns, func(i int, s string) string {
					return fmt.Sprintf("%s.%s", serviceSettingsTableName, s)
				}), ",\n\t"),
				serviceSettingsTableName,
				serviceSettingsTableName, archivedAtColumn,
				serviceSettingsTableName, idColumn, idColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "SearchForServiceSettings",
				Type: ManyType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT
	%s
FROM %s
WHERE %s.%s IS NULL
	AND %s.%s %s
LIMIT 50;`,
				strings.Join(applyToEach(serviceSettingsColumns, func(i int, s string) string {
					return fmt.Sprintf("%s.%s", serviceSettingsTableName, s)
				}), ",\n\t"),
				serviceSettingsTableName,
				serviceSettingsTableName, archivedAtColumn,
				serviceSettingsTableName, nameColumn, buildILIKEForArgument("name_query"),
			)),
		},
	}
}
