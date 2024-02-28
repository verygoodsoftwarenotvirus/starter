package main

import (
	"fmt"
	"strings"

	"github.com/cristalhq/builq"
)

/* #nosec G101 */
const (
	oauth2ClientTokensTableName = "oauth2_client_tokens"
	codeColumn                  = "code"
	accessColumn                = "access"
	refreshColumn               = "refresh"
)

/* #nosec G101 */
var oauth2ClientTokensColumns = []string{
	idColumn,
	"client_id",
	belongsToUserColumn,
	"redirect_uri",
	"scope",
	codeColumn,
	"code_challenge",
	"code_challenge_method",
	"code_created_at",
	"code_expires_at",
	accessColumn,
	"access_created_at",
	"access_expires_at",
	refreshColumn,
	"refresh_created_at",
	"refresh_expires_at",
}

func buildOAuth2ClientTokensQueries() []*Query {
	return []*Query{
		{
			Annotation: QueryAnnotation{
				Name: "ArchiveOAuth2ClientTokenByAccess",
				Type: ExecRowsType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`DELETE FROM %s WHERE %s = sqlc.arg(%s);`, oauth2ClientTokensTableName, accessColumn, accessColumn)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "ArchiveOAuth2ClientTokenByCode",
				Type: ExecRowsType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`DELETE FROM %s WHERE %s = sqlc.arg(%s);`, oauth2ClientTokensTableName, codeColumn, codeColumn)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "ArchiveOAuth2ClientTokenByRefresh",
				Type: ExecRowsType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`DELETE FROM %s WHERE %s = sqlc.arg(%s);`, oauth2ClientTokensTableName, refreshColumn, refreshColumn)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "CreateOAuth2ClientToken",
				Type: ExecType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`INSERT INTO %s (
	%s
) VALUES (
	%s
);`,
				oauth2ClientTokensTableName,
				strings.Join(oauth2ClientTokensColumns, ",\n\t"),
				strings.Join(applyToEach(oauth2ClientTokensColumns, func(i int, s string) string {
					return fmt.Sprintf("sqlc.arg(%s)", s)
				}), ",\n\t"),
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "CheckOAuth2ClientTokenExistence",
				Type: OneType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT EXISTS (
	SELECT %s.%s
	FROM %s
	WHERE %s.%s IS NULL
		AND %s.%s = sqlc.arg(%s)
);`,
				oauth2ClientTokensTableName, idColumn,
				oauth2ClientTokensTableName,
				oauth2ClientTokensTableName, archivedAtColumn,
				oauth2ClientTokensTableName, idColumn, idColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "GetOAuth2ClientTokenByAccess",
				Type: OneType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT
	%s
FROM %s
WHERE %s.%s = sqlc.arg(%s);`,
				strings.Join(applyToEach(oauth2ClientTokensColumns, func(i int, s string) string {
					return fmt.Sprintf("%s.%s", oauth2ClientTokensTableName, s)
				}), ",\n\t"),
				oauth2ClientTokensTableName,
				oauth2ClientTokensTableName, accessColumn, accessColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "GetOAuth2ClientTokenByCode",
				Type: OneType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT
	%s
FROM %s
WHERE %s.%s = sqlc.arg(%s);`,
				strings.Join(applyToEach(oauth2ClientTokensColumns, func(i int, s string) string {
					return fmt.Sprintf("%s.%s", oauth2ClientTokensTableName, s)
				}), ",\n\t"),
				oauth2ClientTokensTableName,
				oauth2ClientTokensTableName, codeColumn, codeColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "GetOAuth2ClientTokenByRefresh",
				Type: OneType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT
	%s
FROM %s
WHERE %s.%s = sqlc.arg(%s);`,
				strings.Join(applyToEach(oauth2ClientTokensColumns, func(i int, s string) string {
					return fmt.Sprintf("%s.%s", oauth2ClientTokensTableName, s)
				}), ",\n\t"),
				oauth2ClientTokensTableName,
				oauth2ClientTokensTableName, refreshColumn, refreshColumn,
			)),
		},
	}
}
