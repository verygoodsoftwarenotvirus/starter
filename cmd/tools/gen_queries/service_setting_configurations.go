package main

import (
	"fmt"
	"strings"

	"github.com/cristalhq/builq"
)

const (
	serviceSettingConfigurationsTableName = "service_setting_configurations"

	serviceSettingIDColumn    = "service_setting_id"
	serviceSettingValueColumn = "value"
)

var serviceSettingConfigurationsColumns = []string{
	idColumn,
	serviceSettingValueColumn,
	notesColumn,
	serviceSettingIDColumn,
	belongsToUserColumn,
	belongsToAccountColumn,
	createdAtColumn,
	lastUpdatedAtColumn,
	archivedAtColumn,
}

func buildServiceSettingConfigurationQueries() []*Query {
	insertColumns := filterForInsert(serviceSettingConfigurationsColumns)

	selectColumnsWithServiceSettingColumns := mergeColumns(
		applyToEach(filterFromSlice(serviceSettingConfigurationsColumns, "service_setting_id"), func(i int, s string) string {
			return fmt.Sprintf("%s.%s", serviceSettingConfigurationsTableName, s)
		}),
		applyToEach(serviceSettingsColumns, func(i int, s string) string {
			return fmt.Sprintf("%s.%s as service_setting_%s", serviceSettingsTableName, s, s)
		}),
		3,
	)

	return []*Query{
		{
			Annotation: QueryAnnotation{
				Name: "ArchiveServiceSettingConfiguration",
				Type: ExecRowsType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`UPDATE %s SET
	%s = %s
WHERE %s IS NULL
	AND %s = sqlc.arg(%s);`,
				serviceSettingConfigurationsTableName,
				archivedAtColumn,
				currentTimeExpression,
				archivedAtColumn,
				idColumn,
				idColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "CreateServiceSettingConfiguration",
				Type: ExecType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`INSERT INTO %s (
	%s
) VALUES (
	%s
);`,
				serviceSettingConfigurationsTableName,
				strings.Join(insertColumns, ",\n\t"),
				strings.Join(applyToEach(insertColumns, func(_ int, s string) string {
					return fmt.Sprintf("sqlc.arg(%s)", s)
				}), ",\n\t"),
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "CheckServiceSettingConfigurationExistence",
				Type: OneType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT EXISTS (
	SELECT %s.%s
	FROM %s
	WHERE %s.%s IS NULL
		AND %s.%s = sqlc.arg(%s)
);`,
				serviceSettingConfigurationsTableName, idColumn,
				serviceSettingConfigurationsTableName,
				serviceSettingConfigurationsTableName, archivedAtColumn,
				serviceSettingConfigurationsTableName, idColumn, idColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "GetServiceSettingConfigurationByID",
				Type: OneType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT
	%s
FROM %s
	JOIN %s ON %s.%s=%s.%s
WHERE %s.%s IS NULL
	AND %s.%s IS NULL
	AND %s.%s = sqlc.arg(%s);`,
				strings.Join(selectColumnsWithServiceSettingColumns, ",\n\t"),
				serviceSettingConfigurationsTableName,
				serviceSettingsTableName, serviceSettingConfigurationsTableName, serviceSettingIDColumn, serviceSettingsTableName, idColumn,
				serviceSettingsTableName, archivedAtColumn,
				serviceSettingConfigurationsTableName, archivedAtColumn,
				serviceSettingConfigurationsTableName, idColumn, idColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "GetServiceSettingConfigurationForAccountBySettingName",
				Type: OneType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT
	%s
FROM %s
	JOIN %s ON %s.%s=%s.%s
WHERE %s.%s IS NULL
	AND %s.%s IS NULL
	AND %s.%s = sqlc.arg(%s)
	AND %s.%s = sqlc.arg(%s);`,
				strings.Join(selectColumnsWithServiceSettingColumns, ",\n\t"),
				serviceSettingConfigurationsTableName,
				serviceSettingsTableName, serviceSettingConfigurationsTableName, serviceSettingIDColumn, serviceSettingsTableName, idColumn,
				serviceSettingsTableName, archivedAtColumn,
				serviceSettingConfigurationsTableName, archivedAtColumn,
				serviceSettingsTableName, nameColumn, nameColumn,
				serviceSettingConfigurationsTableName, belongsToAccountColumn, belongsToAccountColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "GetServiceSettingConfigurationForUserBySettingName",
				Type: OneType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT
	%s
FROM %s
	JOIN %s ON %s.%s=%s.%s
WHERE %s.%s IS NULL
	AND %s.%s IS NULL
	AND %s.%s = sqlc.arg(%s)
	AND %s.%s = sqlc.arg(%s);`,
				strings.Join(selectColumnsWithServiceSettingColumns, ",\n\t"),
				serviceSettingConfigurationsTableName,
				serviceSettingsTableName, serviceSettingConfigurationsTableName, serviceSettingIDColumn, serviceSettingsTableName, idColumn,
				serviceSettingsTableName, archivedAtColumn,
				serviceSettingConfigurationsTableName, archivedAtColumn,
				serviceSettingsTableName, nameColumn, nameColumn,
				serviceSettingConfigurationsTableName, belongsToUserColumn, belongsToUserColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "GetServiceSettingConfigurationsForAccount",
				Type: ManyType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT
	%s
FROM %s
	JOIN %s ON %s.%s=%s.%s
WHERE %s.%s IS NULL
	AND %s.%s IS NULL
	AND %s.%s = sqlc.arg(%s);`,
				strings.Join(selectColumnsWithServiceSettingColumns, ",\n\t"),
				serviceSettingConfigurationsTableName,
				serviceSettingsTableName, serviceSettingConfigurationsTableName, serviceSettingIDColumn, serviceSettingsTableName, idColumn,
				serviceSettingsTableName, archivedAtColumn,
				serviceSettingConfigurationsTableName, archivedAtColumn,
				serviceSettingConfigurationsTableName, belongsToAccountColumn, belongsToAccountColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "GetServiceSettingConfigurationsForUser",
				Type: ManyType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT
	%s
FROM %s
	JOIN %s ON %s.%s=%s.%s
WHERE %s.%s IS NULL
	AND %s.%s IS NULL
	AND %s.%s = sqlc.arg(%s);`,
				strings.Join(selectColumnsWithServiceSettingColumns, ",\n\t"),
				serviceSettingConfigurationsTableName,
				serviceSettingsTableName, serviceSettingConfigurationsTableName, serviceSettingIDColumn, serviceSettingsTableName, idColumn,
				serviceSettingsTableName, archivedAtColumn,
				serviceSettingConfigurationsTableName, archivedAtColumn,
				serviceSettingConfigurationsTableName, belongsToUserColumn, belongsToUserColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "UpdateServiceSettingConfiguration",
				Type: ExecRowsType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`UPDATE %s SET
	%s,
	%s = %s
WHERE %s IS NULL
	AND %s = sqlc.arg(%s);`,
				serviceSettingConfigurationsTableName,
				strings.Join(applyToEach(filterForUpdate(serviceSettingConfigurationsColumns), func(i int, s string) string {
					return fmt.Sprintf("%s = sqlc.arg(%s)", s, s)
				}), ",\n\t"),
				lastUpdatedAtColumn, currentTimeExpression,
				archivedAtColumn,
				idColumn, idColumn,
			)),
		},
	}
}
