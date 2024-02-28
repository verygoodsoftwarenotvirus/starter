package main

import (
	"fmt"
	"strings"

	"github.com/cristalhq/builq"
)

const (
	oauth2ClientsTableName = "oauth2_clients"
	clientIDColumn         = "client_id"
)

var oauth2ClientsColumns = []string{
	idColumn,
	nameColumn,
	descriptionColumn,
	clientIDColumn,
	"client_secret",
	createdAtColumn,
	archivedAtColumn,
}

func buildOAuth2ClientsQueries() []*Query {
	insertColumns := filterForInsert(oauth2ClientsColumns)

	return []*Query{
		{
			Annotation: QueryAnnotation{
				Name: "ArchiveOAuth2Client",
				Type: ExecRowsType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`UPDATE %s SET
	%s = %s
WHERE %s IS NULL
	AND %s = sqlc.arg(%s);`,
				oauth2ClientsTableName,
				archivedAtColumn,
				currentTimeExpression,
				archivedAtColumn,
				idColumn,
				idColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "CreateOAuth2Client",
				Type: ExecType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`INSERT INTO %s (
	%s
) VALUES (
	%s
);`,
				oauth2ClientsTableName,
				strings.Join(insertColumns, ",\n\t"),
				strings.Join(applyToEach(insertColumns, func(_ int, s string) string {
					return fmt.Sprintf("sqlc.arg(%s)", s)
				}), ",\n\t"),
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "GetOAuth2ClientByClientID",
				Type: OneType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT
	%s
FROM %s
WHERE %s.%s IS NULL
	AND %s.%s = sqlc.arg(%s);`,
				strings.Join(applyToEach(oauth2ClientsColumns, func(_ int, s string) string {
					return fmt.Sprintf("%s.%s", oauth2ClientsTableName, s)
				}), ",\n\t"),
				oauth2ClientsTableName,
				oauth2ClientsTableName, archivedAtColumn,
				oauth2ClientsTableName, clientIDColumn, clientIDColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "GetOAuth2ClientByDatabaseID",
				Type: OneType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT
	%s
FROM %s
WHERE %s.%s IS NULL
	AND %s.%s = sqlc.arg(%s);`,
				strings.Join(applyToEach(oauth2ClientsColumns, func(_ int, s string) string {
					return fmt.Sprintf("%s.%s", oauth2ClientsTableName, s)
				}), ",\n\t"),
				oauth2ClientsTableName,
				oauth2ClientsTableName, archivedAtColumn,
				oauth2ClientsTableName, idColumn, idColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "GetOAuth2Clients",
				Type: ManyType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT
	%s,
	(
		SELECT COUNT(%s.%s)
		FROM %s
		WHERE %s.%s IS NULL
			%s
	) as filtered_count,
	%s
FROM %s
WHERE %s.%s IS NULL
	%s
%s;
`,
				strings.Join(applyToEach(oauth2ClientsColumns, func(_ int, s string) string {
					return fmt.Sprintf("%s.%s", oauth2ClientsTableName, s)
				}), ",\n\t"),
				oauth2ClientsTableName, idColumn,
				oauth2ClientsTableName,
				oauth2ClientsTableName, archivedAtColumn,
				strings.Join(strings.Split(
					buildFilterConditions(
						oauth2ClientsTableName,
						false,
					), "\n"),
					"\n\t\t",
				),
				buildTotalCountSelect(usersTableName, true),
				oauth2ClientsTableName,
				oauth2ClientsTableName, archivedAtColumn,
				buildFilterConditions(
					oauth2ClientsTableName,
					false,
				),
				offsetLimitAddendum,
			)),
		},
	}
}
