package main

import (
	"fmt"
	"slices"
	"strings"

	"github.com/cristalhq/builq"
)

const (
	idColumn               = "id"
	nameColumn             = "name"
	pluralNameColumn       = "plural_name"
	notesColumn            = "notes"
	descriptionColumn      = "description"
	iconPathColumn         = "icon_path"
	slugColumn             = "slug"
	createdAtColumn        = "created_at"
	lastUpdatedAtColumn    = "last_updated_at"
	archivedAtColumn       = "archived_at"
	lastIndexedAtColumn    = "last_indexed_at"
	belongsToAccountColumn = "belongs_to_account"
	belongsToUserColumn    = "belongs_to_user"

	currentTimeExpression = "NOW()"

	offsetLimitAddendum = `LIMIT sqlc.narg(query_limit)
OFFSET sqlc.narg(query_offset)`
)

func applyToEach[T comparable](x []T, f func(int, T) T) []T {
	output := []T{}

	for i, v := range x {
		output = append(output, f(i, v))
	}

	return output
}

func buildRawQuery(builder *builq.Builder) string {
	query, _, err := builder.Build()
	if err != nil {
		panic(err)
	}

	return query
}

func filterForInsert(columns []string, exceptions ...string) []string {
	return filterFromSlice(columns, append([]string{archivedAtColumn, createdAtColumn, lastUpdatedAtColumn, lastIndexedAtColumn}, exceptions...)...)
}

func filterForUpdate(columns []string, exceptions ...string) []string {
	return filterForInsert(columns, append(exceptions, idColumn)...)
}

func fullColumnName(tableName, columnName string) string {
	return fmt.Sprintf("%s.%s", tableName, columnName)
}

func filterFromSlice(slice []string, filtered ...string) []string {
	output := []string{}

	for _, s := range slice {
		if !slices.Contains(filtered, s) {
			output = append(output, s)
		}
	}

	return output
}

func mergeColumns(columns1, columns2 []string, indexToInsertSecondSet uint) []string {
	output := []string{}

	for i, col1 := range columns1 {
		if i == int(indexToInsertSecondSet) {
			output = append(output, columns2...)
		}
		output = append(output, col1)
	}

	return output
}

func buildFilterConditions(tableName string, withUpdateColumn bool, conditions ...string) string {
	updateAddendum := ""
	if withUpdateColumn {
		updateAddendum = fmt.Sprintf("\n\t%s", strings.TrimSpace(buildRawQuery((&builq.Builder{}).Addf(`
	AND (
		%s.%s IS NULL
		OR %s.%s > COALESCE(sqlc.narg(updated_after), (SELECT %s - '999 years'::INTERVAL))
	)
	AND (
		%s.%s IS NULL
		OR %s.%s < COALESCE(sqlc.narg(updated_before), (SELECT %s + '999 years'::INTERVAL))
	)
		`,
			tableName,
			lastUpdatedAtColumn,
			tableName,
			lastUpdatedAtColumn,
			currentTimeExpression,
			tableName,
			lastUpdatedAtColumn,
			tableName,
			lastUpdatedAtColumn,
			currentTimeExpression,
		))))
	}

	allConditions := ""
	for _, condition := range conditions {
		allConditions += fmt.Sprintf("\n\tAND %s", condition)
	}

	rv := strings.TrimSpace(buildRawQuery((&builq.Builder{}).Addf(`AND %s.%s > COALESCE(sqlc.narg(created_after), (SELECT %s - '999 years'::INTERVAL))
	AND %s.%s < COALESCE(sqlc.narg(created_before), (SELECT %s + '999 years'::INTERVAL))%s%s`,
		tableName,
		createdAtColumn,
		currentTimeExpression,
		tableName,
		createdAtColumn,
		currentTimeExpression,
		updateAddendum,
		allConditions,
	)))

	return rv
}

func buildFilterCountSelect(tableName string, withUpdateColumn, withArchivedAtColumn bool, conditions ...string) string {
	updateAddendum := ""
	if withUpdateColumn {
		updateAddendum = fmt.Sprintf("\n\t\t\t%s", strings.TrimSpace(buildRawQuery((&builq.Builder{}).Addf(`
			AND (
				%s.%s IS NULL
				OR %s.%s > COALESCE(sqlc.narg(updated_before), (SELECT %s - '999 years'::INTERVAL))
			)
			AND (
				%s.%s IS NULL
				OR %s.%s < COALESCE(sqlc.narg(updated_after), (SELECT %s + '999 years'::INTERVAL))
			)
		`,
			tableName,
			lastUpdatedAtColumn,
			tableName,
			lastUpdatedAtColumn,
			currentTimeExpression,
			tableName,
			lastUpdatedAtColumn,
			tableName,
			lastUpdatedAtColumn,
			currentTimeExpression,
		))))
	}

	allConditions := ""
	for _, condition := range conditions {
		allConditions += fmt.Sprintf("\n\t\t\tAND %s", strings.TrimSpace(condition))
	}

	archivedAtAddendum := "WHERE"
	if withArchivedAtColumn {
		archivedAtAddendum = fmt.Sprintf("WHERE %s.%s IS NULL\n\t\t\tAND", tableName, archivedAtColumn)
	}

	return strings.TrimSpace(buildRawQuery((&builq.Builder{}).Addf(`(
		SELECT COUNT(%s.%s)
		FROM %s
		%s %s.%s > COALESCE(sqlc.narg(created_after), (SELECT %s - '999 years'::INTERVAL))
			AND %s.%s < COALESCE(sqlc.narg(created_before), (SELECT %s + '999 years'::INTERVAL))%s%s
	) AS filtered_count`,
		tableName, idColumn,
		tableName,
		archivedAtAddendum,
		tableName, createdAtColumn, currentTimeExpression,
		tableName, createdAtColumn, currentTimeExpression,
		updateAddendum,
		allConditions,
	)))
}

func buildTotalCountSelect(tableName string, withArchivedAtColumn bool, conditions ...string) string {
	allConditons := ""
	for i, condition := range conditions {
		prefix := "AND "
		if !withArchivedAtColumn && i == 0 {
			prefix = ""
		}
		allConditons += fmt.Sprintf("\n\t\t\t%s%s", prefix, strings.TrimSpace(condition))
	}

	archivedAtAddendum := "WHERE"
	if withArchivedAtColumn {
		archivedAtAddendum = fmt.Sprintf("WHERE %s.%s IS NULL", tableName, archivedAtColumn)
	}

	return strings.TrimSpace(buildRawQuery((&builq.Builder{}).Addf(`(
		SELECT COUNT(%s.%s)
		FROM %s
		%s%s
	) AS total_count`,
		tableName, idColumn,
		tableName,
		archivedAtAddendum,
		allConditons,
	)))
}

func buildILIKEForArgument(argumentName string) string {
	return fmt.Sprintf(`ILIKE '%%' || sqlc.arg(%s)::text || '%%'`, argumentName)
}

type joinStatement struct {
	joinTarget   string
	targetColumn string
	onTable      string
	onColumn     string
}

func buildJoinStatement(js joinStatement) string {
	return fmt.Sprintf("JOIN %s ON %s.%s=%s.%s", js.joinTarget, js.onTable, js.onColumn, js.joinTarget, js.targetColumn)
}
