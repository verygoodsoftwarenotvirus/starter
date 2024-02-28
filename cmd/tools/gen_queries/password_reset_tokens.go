package main

import (
	"fmt"
	"strings"

	"github.com/cristalhq/builq"
)

const (
	passwordResetTokensTableName = "password_reset_tokens"

	passwordResetTokenColumn          = "token"
	redeemedAtColumn                  = "redeemed_at"
	passwordResetTokenExpiresAtColumn = "expires_at"
)

var passwordResetTokensColumns = []string{
	idColumn,
	passwordResetTokenColumn,
	passwordResetTokenExpiresAtColumn,
	redeemedAtColumn,
	belongsToUserColumn,
	createdAtColumn,
	lastUpdatedAtColumn,
}

func buildPasswordResetTokensQueries() []*Query {
	insertColumns := filterForInsert(passwordResetTokensColumns, "redeemed_at")

	return []*Query{
		{
			Annotation: QueryAnnotation{
				Name: "CreatePasswordResetToken",
				Type: ExecType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`INSERT INTO %s (
	%s
) VALUES (
	sqlc.arg(%s),
	sqlc.arg(%s),
	%s + (30 * '1 minutes'::INTERVAL),
	sqlc.arg(%s)
);`,
				passwordResetTokensTableName,
				strings.Join(insertColumns, ",\n\t"),
				idColumn,
				passwordResetTokenColumn,
				currentTimeExpression,
				belongsToUserColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "GetPasswordResetToken",
				Type: OneType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT
	%s
FROM %s
WHERE %s.%s IS NULL
	AND %s < %s.%s
	AND %s.%s = sqlc.arg(%s);`,
				strings.Join(applyToEach(passwordResetTokensColumns, func(i int, s string) string {
					return fmt.Sprintf("password_reset_tokens.%s", s)
				}), ",\n\t"),
				passwordResetTokensTableName,
				passwordResetTokensTableName, redeemedAtColumn,
				currentTimeExpression, passwordResetTokensTableName, passwordResetTokenExpiresAtColumn,
				passwordResetTokensTableName, passwordResetTokenColumn, passwordResetTokenColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "RedeemPasswordResetToken",
				Type: ExecType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`UPDATE %s SET
	%s = %s
WHERE %s IS NULL
	AND %s = sqlc.arg(%s);`,
				passwordResetTokensTableName,
				redeemedAtColumn, currentTimeExpression,
				redeemedAtColumn,
				idColumn, idColumn,
			)),
		},
	}
}
