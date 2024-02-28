package main

import (
	"github.com/cristalhq/builq"
)

func buildAdminQueries() []*Query {
	return []*Query{
		{
			Annotation: QueryAnnotation{
				Name: "SetUserAccountStatus",
				Type: ExecRowsType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`UPDATE %s SET
	%s = %s,
	%s = sqlc.arg(%s),
	%s = sqlc.arg(%s)
WHERE %s IS NULL
	AND %s = sqlc.arg(%s);`,
				usersTableName,
				lastUpdatedAtColumn, currentTimeExpression,
				userAccountStatusColumn, userAccountStatusColumn,
				userAccountStatusExplanationColumn, userAccountStatusExplanationColumn,
				archivedAtColumn,
				idColumn, idColumn,
			)),
		},
	}
}
