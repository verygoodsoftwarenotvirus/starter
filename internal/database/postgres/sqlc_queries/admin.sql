-- name: SetUserAccountStatus :execrows

UPDATE users SET
	last_updated_at = NOW(),
	user_account_status = sqlc.arg(user_account_status),
	user_account_status_explanation = sqlc.arg(user_account_status_explanation)
WHERE archived_at IS NULL
	AND id = sqlc.arg(id);
