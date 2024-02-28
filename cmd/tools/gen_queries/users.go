package main

import (
	"fmt"
	"strings"

	"github.com/cristalhq/builq"
)

const (
	usersTableName = "users"

	createdByUserColumn = "created_by_user"

	usernameColumn               = "username"
	avatarSourceColumn           = "avatar_src"
	emailAddressColumn           = "email_address"
	hashedPasswordColumn         = "hashed_password"
	passwordLastChangedAtColumn  = "password_last_changed_at"
	requiresPasswordChangeColumn = "requires_password_change"
	/* #nosec G101 */
	twoFactorSecretColumn = "two_factor_secret"
	/* #nosec G101 */
	twoFactorSecretVerifiedAtColumn     = "two_factor_secret_verified_at"
	serviceRoleColumn                   = "service_role"
	userAccountStatusColumn             = "user_account_status"
	userAccountStatusExplanationColumn  = "user_account_status_explanation"
	birthdayColumn                      = "birthday"
	emailAddressVerificationTokenColumn = "email_address_verification_token"
	emailAddressVerifiedAtColumn        = "email_address_verified_at"
	firstNameColumn                     = "first_name"
	lastNameColumn                      = "last_name"
	lastAcceptedTOSColumn               = "last_accepted_terms_of_service"
	lastAcceptedPrivacyPolicyColumn     = "last_accepted_privacy_policy"
)

var usersColumns = []string{
	idColumn,
	usernameColumn,
	avatarSourceColumn,
	emailAddressColumn,
	hashedPasswordColumn,
	passwordLastChangedAtColumn,
	requiresPasswordChangeColumn,
	twoFactorSecretColumn,
	twoFactorSecretVerifiedAtColumn,
	serviceRoleColumn,
	userAccountStatusColumn,
	userAccountStatusExplanationColumn,
	birthdayColumn,
	emailAddressVerificationTokenColumn,
	emailAddressVerifiedAtColumn,
	firstNameColumn,
	lastNameColumn,
	lastAcceptedTOSColumn,
	lastAcceptedPrivacyPolicyColumn,
	lastIndexedAtColumn,
	createdAtColumn,
	lastUpdatedAtColumn,
	archivedAtColumn,
}

func buildUpdateAccountMembershipsQuery(ownershipColumn string, nowColumns []string) string {
	var updateQueryBuilder builq.Builder

	addendum := ""
	for _, col := range nowColumns {
		addendum = fmt.Sprintf(",\n\t%s = %s", col, currentTimeExpression)
	}

	builder := updateQueryBuilder.Addf(
		`UPDATE %s SET
	%s = %s%s
WHERE %s IS NULL
	AND %s = sqlc.arg(%s);`,
		accountUserMembershipsTableName,
		archivedAtColumn,
		currentTimeExpression,
		addendum,
		archivedAtColumn,
		ownershipColumn,
		idColumn,
	)

	return buildRawQuery(builder)
}

func buildUserUpdateQuery(columnName string, nowColumns []string) string {
	var updateQueryBuilder builq.Builder

	addendum := ""
	for _, col := range nowColumns {
		addendum = fmt.Sprintf(",\n\t%s = %s", col, currentTimeExpression)
	}

	builder := updateQueryBuilder.Addf(
		`UPDATE %s SET
	%s = %s%s
WHERE %s IS NULL
	AND %s = sqlc.arg(%s);`,
		usersTableName,
		columnName,
		currentTimeExpression,
		addendum,
		archivedAtColumn,
		idColumn,
		idColumn,
	)

	return buildRawQuery(builder)
}

func buildUsersQueries() []*Query {
	insertColumns := filterForInsert(usersColumns,
		"password_last_changed_at",
		"email_address_verified_at",
		lastAcceptedTOSColumn,
		lastAcceptedPrivacyPolicyColumn,
		lastIndexedAtColumn,
	)

	return []*Query{
		{
			Annotation: QueryAnnotation{
				Name: "AcceptPrivacyPolicyForUser",
				Type: ExecType,
			},
			Content: buildUserUpdateQuery(lastAcceptedPrivacyPolicyColumn, nil),
		},
		{
			Annotation: QueryAnnotation{
				Name: "AcceptTermsOfServiceForUser",
				Type: ExecType,
			},
			Content: buildUserUpdateQuery(lastAcceptedTOSColumn, nil),
		},
		{
			Annotation: QueryAnnotation{
				Name: "ArchiveUser",
				Type: ExecRowsType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`UPDATE %s SET %s = %s WHERE %s IS NULL AND %s = sqlc.arg(%s);`,
				usersTableName,
				archivedAtColumn,
				currentTimeExpression,
				archivedAtColumn,
				idColumn,
				idColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "ArchiveUserMemberships",
				Type: ExecRowsType,
			},
			Content: buildUpdateAccountMembershipsQuery(belongsToUserColumn, []string{}),
		},
		{
			Annotation: QueryAnnotation{
				Name: "CreateUser",
				Type: ExecType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`INSERT INTO %s
(
	%s
) VALUES (
	%s
);`,
				usersTableName,
				strings.Join(insertColumns, ",\n\t"),
				strings.Join(applyToEach(insertColumns, func(_ int, s string) string {
					return fmt.Sprintf("sqlc.arg(%s)", s)
				}), ",\n\t"),
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "GetAdminUserByUsername",
				Type: OneType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT
	%s
FROM %s
WHERE %s.%s IS NULL
	AND %s.%s = 'service_admin'
	AND %s.%s = sqlc.arg(%s)
	AND %s.%s IS NOT NULL;`,

				strings.Join(applyToEach(usersColumns, func(_ int, s string) string {
					return fmt.Sprintf("%s.%s", usersTableName, s)
				}), ",\n\t"),
				usersTableName,
				usersTableName, archivedAtColumn,
				usersTableName, serviceRoleColumn,
				usersTableName, usernameColumn, usernameColumn,
				usersTableName, twoFactorSecretVerifiedAtColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "GetUserByEmail",
				Type: OneType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT
	%s
FROM %s
WHERE %s.%s IS NULL
	AND %s.%s = sqlc.arg(%s);`,
				strings.Join(applyToEach(usersColumns, func(_ int, s string) string {
					return fmt.Sprintf("%s.%s", usersTableName, s)
				}), ",\n\t"),
				usersTableName,
				usersTableName, archivedAtColumn,
				usersTableName, emailAddressColumn, emailAddressColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "GetUserByEmailAddressVerificationToken",
				Type: OneType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT
	%s
FROM %s
WHERE %s.%s IS NULL
	AND %s.%s = sqlc.arg(%s);`,
				strings.Join(applyToEach(usersColumns, func(_ int, s string) string {
					return fmt.Sprintf("%s.%s", usersTableName, s)
				}), ",\n\t"),
				usersTableName,
				usersTableName, archivedAtColumn,
				usersTableName, emailAddressVerificationTokenColumn, emailAddressVerificationTokenColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "GetUserByID",
				Type: OneType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT
	%s
FROM %s
WHERE %s.%s IS NULL
	AND %s.%s = sqlc.arg(%s);`,
				strings.Join(applyToEach(usersColumns, func(_ int, s string) string {
					return fmt.Sprintf("%s.%s", usersTableName, s)
				}), ",\n\t"),
				usersTableName,
				usersTableName, archivedAtColumn,
				usersTableName, idColumn, idColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "GetUserByUsername",
				Type: OneType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT
	%s
FROM %s
WHERE %s.%s IS NULL
	AND %s.%s = sqlc.arg(%s);`,
				strings.Join(applyToEach(usersColumns, func(_ int, s string) string {
					return fmt.Sprintf("%s.%s", usersTableName, s)
				}), ",\n\t"),
				usersTableName,
				usersTableName, archivedAtColumn,
				usersTableName, usernameColumn, usernameColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "GetEmailVerificationTokenByUserID",
				Type: OneType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT
	%s.%s
FROM %s
WHERE %s.%s IS NULL
	AND %s.%s IS NULL
	AND %s.%s = sqlc.arg(%s);`,
				usersTableName, emailAddressVerificationTokenColumn,
				usersTableName,
				usersTableName, archivedAtColumn,
				usersTableName, emailAddressVerifiedAtColumn,
				usersTableName, idColumn, idColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "GetUsers",
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
				strings.Join(applyToEach(usersColumns, func(_ int, s string) string {
					return fmt.Sprintf("%s.%s", usersTableName, s)
				}), ",\n\t"),
				buildFilterCountSelect(usersTableName, true, true),
				buildTotalCountSelect(usersTableName, true),
				usersTableName,
				usersTableName, archivedAtColumn,
				buildFilterConditions(
					usersTableName,
					true,
				),
				offsetLimitAddendum,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "GetUserIDsNeedingIndexing",
				Type: ManyType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT %s.%s
FROM %s
WHERE %s.%s IS NULL
	AND %s.%s IS NULL
	OR %s.%s < %s - '24 hours'::INTERVAL;`,
				usersTableName, idColumn,
				usersTableName,
				usersTableName, archivedAtColumn,
				usersTableName, lastIndexedAtColumn,
				usersTableName, lastIndexedAtColumn, currentTimeExpression,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "GetUserWithUnverifiedTwoFactor",
				Type: OneType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT
	%s
FROM %s
WHERE %s.%s IS NULL
	AND %s.%s = sqlc.arg(%s)
	AND %s.%s IS NULL;`,
				strings.Join(applyToEach(usersColumns, func(_ int, s string) string {
					return fmt.Sprintf("%s.%s", usersTableName, s)
				}), ",\n\t"),
				usersTableName,
				usersTableName, archivedAtColumn,
				usersTableName, idColumn, idColumn,
				usersTableName, twoFactorSecretVerifiedAtColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "GetUserWithVerifiedTwoFactor",
				Type: OneType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT
	%s
FROM %s
WHERE %s.%s IS NULL
	AND %s.%s = sqlc.arg(%s)
	AND %s.%s IS NOT NULL;`,
				strings.Join(applyToEach(usersColumns, func(_ int, s string) string {
					return fmt.Sprintf("%s.%s", usersTableName, s)
				}), ",\n\t"),
				usersTableName,
				usersTableName, archivedAtColumn,
				usersTableName, idColumn, idColumn,
				usersTableName, twoFactorSecretVerifiedAtColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "MarkEmailAddressAsVerified",
				Type: ExecType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`UPDATE %s SET
	%s = %s,
	%s = %s
WHERE %s IS NULL
	AND %s IS NULL
	AND %s = sqlc.arg(%s)
	AND %s = sqlc.arg(%s);`,
				usersTableName,
				emailAddressVerifiedAtColumn, currentTimeExpression,
				lastUpdatedAtColumn, currentTimeExpression,
				archivedAtColumn,
				emailAddressVerifiedAtColumn,
				idColumn, idColumn,
				emailAddressVerificationTokenColumn, emailAddressVerificationTokenColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "MarkEmailAddressAsUnverified",
				Type: ExecType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`UPDATE %s SET
	%s = NULL,
	%s = %s
WHERE %s IS NULL
	AND %s IS NOT NULL
	AND %s = sqlc.arg(%s);`,
				usersTableName,
				emailAddressVerifiedAtColumn,
				lastUpdatedAtColumn, currentTimeExpression,
				archivedAtColumn,
				emailAddressVerifiedAtColumn,
				idColumn, idColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "MarkTwoFactorSecretAsUnverified",
				Type: ExecType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`UPDATE %s SET
	%s = NULL,
	%s = sqlc.arg(%s),
	%s = %s
WHERE %s IS NULL
	AND %s = sqlc.arg(%s);`,
				usersTableName,
				twoFactorSecretVerifiedAtColumn,
				twoFactorSecretColumn, twoFactorSecretColumn,
				lastUpdatedAtColumn,
				currentTimeExpression,
				archivedAtColumn,
				idColumn,
				idColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "MarkTwoFactorSecretAsVerified",
				Type: ExecType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`UPDATE %s SET
	%s = %s,
	%s = %s
WHERE %s IS NULL
	AND %s = sqlc.arg(%s);`,
				usersTableName,
				twoFactorSecretVerifiedAtColumn, currentTimeExpression,
				lastUpdatedAtColumn, currentTimeExpression,
				archivedAtColumn,
				idColumn, idColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "SearchUsersByUsername",
				Type: ManyType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`SELECT
	%s
FROM %s
WHERE %s.%s %s
AND %s.%s IS NULL;`,
				strings.Join(applyToEach(usersColumns, func(_ int, s string) string {
					return fmt.Sprintf("%s.%s", usersTableName, s)
				}), ",\n\t"),
				usersTableName,
				usersTableName, usernameColumn, buildILIKEForArgument(usernameColumn),
				usersTableName, archivedAtColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "UpdateUserAvatarSrc",
				Type: ExecRowsType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`UPDATE %s SET
	%s = sqlc.arg(%s),
	%s = %s
WHERE %s IS NULL
	AND %s = sqlc.arg(%s);`,
				usersTableName,
				avatarSourceColumn, avatarSourceColumn,
				lastUpdatedAtColumn, currentTimeExpression,
				archivedAtColumn,
				idColumn, idColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "UpdateUserDetails",
				Type: ExecRowsType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`UPDATE %s SET
	%s = sqlc.arg(%s),
	%s = sqlc.arg(%s),
	%s = sqlc.arg(%s),
	%s = %s
WHERE %s IS NULL
	AND %s = sqlc.arg(%s);`,
				usersTableName,
				firstNameColumn, firstNameColumn,
				lastNameColumn, lastNameColumn,
				birthdayColumn, birthdayColumn,
				lastUpdatedAtColumn, currentTimeExpression,
				archivedAtColumn,
				idColumn, idColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "UpdateUserEmailAddress",
				Type: ExecRowsType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`UPDATE %s SET
	%s = sqlc.arg(%s),
	%s = NULL,
	%s = %s
WHERE %s IS NULL
	AND %s = sqlc.arg(%s);`,
				usersTableName,
				emailAddressColumn, emailAddressColumn,
				emailAddressVerifiedAtColumn,
				lastUpdatedAtColumn,
				currentTimeExpression,
				archivedAtColumn,
				idColumn, idColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "UpdateUserLastIndexedAt",
				Type: ExecRowsType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`UPDATE %s SET %s = %s WHERE %s = sqlc.arg(%s) AND %s IS NULL;`,
				usersTableName,
				lastIndexedAtColumn,
				currentTimeExpression,
				idColumn,
				idColumn,
				archivedAtColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "UpdateUserPassword",
				Type: ExecRowsType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`UPDATE %s SET
	%s = sqlc.arg(%s),
	%s = %s,
	%s = %s
WHERE %s IS NULL
	AND %s = sqlc.arg(%s);`,
				usersTableName,
				hashedPasswordColumn, hashedPasswordColumn,
				passwordLastChangedAtColumn, currentTimeExpression,
				lastUpdatedAtColumn, currentTimeExpression,
				archivedAtColumn,
				idColumn, idColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "UpdateUserTwoFactorSecret",
				Type: ExecRowsType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`UPDATE %s SET
	%s = NULL,
	%s = sqlc.arg(%s),
	%s = %s
WHERE %s IS NULL
	AND %s = sqlc.arg(%s);`,
				usersTableName,
				twoFactorSecretVerifiedAtColumn,
				twoFactorSecretColumn, twoFactorSecretColumn,
				lastUpdatedAtColumn, currentTimeExpression,
				archivedAtColumn,
				idColumn, idColumn,
			)),
		},
		{
			Annotation: QueryAnnotation{
				Name: "UpdateUserUsername",
				Type: ExecRowsType,
			},
			Content: buildRawQuery((&builq.Builder{}).Addf(`UPDATE %s SET
	%s = sqlc.arg(%s),
	%s = %s
WHERE %s IS NULL
	AND %s = sqlc.arg(%s);`,
				usersTableName,
				usernameColumn, usernameColumn,
				lastUpdatedAtColumn, currentTimeExpression,
				archivedAtColumn,
				idColumn, idColumn,
			)),
		},
	}
}
