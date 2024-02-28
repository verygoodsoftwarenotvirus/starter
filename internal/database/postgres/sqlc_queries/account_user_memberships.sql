-- name: AddUserToAccount :exec

INSERT INTO account_user_memberships (
	id,
	belongs_to_account,
	belongs_to_user,
	account_role
) VALUES (
	sqlc.arg(id),
	sqlc.arg(belongs_to_account),
	sqlc.arg(belongs_to_user),
	sqlc.arg(account_role)
);

-- name: CreateAccountUserMembershipForNewUser :exec

INSERT INTO account_user_memberships (
	id,
	belongs_to_account,
	belongs_to_user,
	default_account,
	account_role
) VALUES (
	sqlc.arg(id),
	sqlc.arg(belongs_to_account),
	sqlc.arg(belongs_to_user),
	sqlc.arg(default_account),
	sqlc.arg(account_role)
);

-- name: GetDefaultAccountIDForUser :one

SELECT accounts.id
FROM accounts
	JOIN account_user_memberships ON account_user_memberships.belongs_to_account = accounts.id
WHERE account_user_memberships.belongs_to_user = sqlc.arg(belongs_to_user)
	AND account_user_memberships.default_account = TRUE;

-- name: GetAccountUserMembershipsForUser :many

SELECT
	account_user_memberships.id,
	account_user_memberships.belongs_to_account,
	account_user_memberships.belongs_to_user,
	account_user_memberships.default_account,
	account_user_memberships.account_role,
	account_user_memberships.created_at,
	account_user_memberships.last_updated_at,
	account_user_memberships.archived_at
FROM account_user_memberships
	JOIN accounts ON accounts.id = account_user_memberships.belongs_to_account
WHERE account_user_memberships.archived_at IS NULL
	AND account_user_memberships.belongs_to_user = sqlc.arg(belongs_to_user);

-- name: MarkAccountUserMembershipAsUserDefault :exec

UPDATE account_user_memberships SET
	default_account = (belongs_to_user = sqlc.arg(belongs_to_user) AND belongs_to_account = sqlc.arg(belongs_to_account))
WHERE archived_at IS NULL
	AND belongs_to_user = sqlc.arg(belongs_to_user);

-- name: ModifyAccountUserPermissions :exec

UPDATE account_user_memberships SET
	account_role = sqlc.arg(account_role)
WHERE belongs_to_account = sqlc.arg(belongs_to_account)
	AND belongs_to_user = sqlc.arg(belongs_to_user);

-- name: RemoveUserFromAccount :exec

UPDATE account_user_memberships SET
	archived_at = NOW(),
	default_account = 'false'
WHERE account_user_memberships.archived_at IS NULL
	AND account_user_memberships.belongs_to_account = sqlc.arg(belongs_to_account)
	AND account_user_memberships.belongs_to_user = sqlc.arg(belongs_to_user);

-- name: TransferAccountMembership :exec

UPDATE account_user_memberships SET
	belongs_to_user = sqlc.arg(belongs_to_user)
WHERE archived_at IS NULL
	AND belongs_to_account = sqlc.arg(belongs_to_account)
	AND belongs_to_user = sqlc.arg(belongs_to_user);

-- name: TransferAccountOwnership :exec

UPDATE accounts SET
	belongs_to_user = sqlc.arg(new_owner)
WHERE archived_at IS NULL
	AND belongs_to_user = sqlc.arg(old_owner)
	AND id = sqlc.arg(account_id);

-- name: UserIsAccountMember :one

SELECT EXISTS (
	SELECT account_user_memberships.id
	FROM account_user_memberships
	WHERE account_user_memberships.archived_at IS NULL
		AND account_user_memberships.belongs_to_account = sqlc.arg(belongs_to_account)
		AND account_user_memberships.belongs_to_user = sqlc.arg(belongs_to_user)
);
