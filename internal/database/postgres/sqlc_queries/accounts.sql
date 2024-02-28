-- name: AddToAccountDuringCreation :exec

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

-- name: ArchiveAccount :execrows

UPDATE accounts SET
	last_updated_at = NOW(),
	archived_at = NOW()
WHERE archived_at IS NULL
	AND belongs_to_user = sqlc.arg(belongs_to_user)
	AND id = sqlc.arg(id);

-- name: CreateAccount :exec

INSERT INTO accounts (
	id,
	name,
	billing_status,
	contact_phone,
	belongs_to_user,
	address_line_1,
	address_line_2,
	city,
	state,
	zip_code,
	country,
	latitude,
	longitude,
	webhook_hmac_secret
) VALUES (
	sqlc.arg(id),
	sqlc.arg(name),
	sqlc.arg(billing_status),
	sqlc.arg(contact_phone),
	sqlc.arg(belongs_to_user),
	sqlc.arg(address_line_1),
	sqlc.arg(address_line_2),
	sqlc.arg(city),
	sqlc.arg(state),
	sqlc.arg(zip_code),
	sqlc.arg(country),
	sqlc.arg(latitude),
	sqlc.arg(longitude),
	sqlc.arg(webhook_hmac_secret)
);

-- name: GetAccountByIDWithMemberships :many

SELECT
	accounts.id,
	accounts.name,
	accounts.billing_status,
	accounts.contact_phone,
	accounts.payment_processor_customer_id,
	accounts.subscription_plan_id,
	accounts.belongs_to_user,
	accounts.time_zone,
	accounts.address_line_1,
	accounts.address_line_2,
	accounts.city,
	accounts.state,
	accounts.zip_code,
	accounts.country,
	accounts.latitude,
	accounts.longitude,
	accounts.last_payment_provider_sync_occurred_at,
	accounts.webhook_hmac_secret,
	accounts.created_at,
	accounts.last_updated_at,
	accounts.archived_at,
	users.id as user_id,
	users.username as user_username,
	users.avatar_src as user_avatar_src,
	users.email_address as user_email_address,
	users.hashed_password as user_hashed_password,
	users.password_last_changed_at as user_password_last_changed_at,
	users.requires_password_change as user_requires_password_change,
	users.two_factor_secret as user_two_factor_secret,
	users.two_factor_secret_verified_at as user_two_factor_secret_verified_at,
	users.service_role as user_service_role,
	users.user_account_status as user_user_account_status,
	users.user_account_status_explanation as user_user_account_status_explanation,
	users.birthday as user_birthday,
	users.email_address_verification_token as user_email_address_verification_token,
	users.email_address_verified_at as user_email_address_verified_at,
	users.first_name as user_first_name,
	users.last_name as user_last_name,
	users.last_accepted_terms_of_service as user_last_accepted_terms_of_service,
	users.last_accepted_privacy_policy as user_last_accepted_privacy_policy,
	users.last_indexed_at as user_last_indexed_at,
	users.created_at as user_created_at,
	users.last_updated_at as user_last_updated_at,
	users.archived_at as user_archived_at,
	account_user_memberships.id as membership_id,
	account_user_memberships.belongs_to_account as membership_belongs_to_account,
	account_user_memberships.belongs_to_user as membership_belongs_to_user,
	account_user_memberships.default_account as membership_default_account,
	account_user_memberships.account_role as membership_account_role,
	account_user_memberships.created_at as membership_created_at,
	account_user_memberships.last_updated_at as membership_last_updated_at,
	account_user_memberships.archived_at as membership_archived_at
FROM accounts
	JOIN account_user_memberships ON account_user_memberships.belongs_to_account = accounts.id
	JOIN users ON account_user_memberships.belongs_to_user = users.id
WHERE accounts.archived_at IS NULL
	AND account_user_memberships.archived_at IS NULL
	AND accounts.id = sqlc.arg(id);

-- name: GetAccountsForUser :many

SELECT
	accounts.id,
	accounts.name,
	accounts.billing_status,
	accounts.contact_phone,
	accounts.payment_processor_customer_id,
	accounts.subscription_plan_id,
	accounts.belongs_to_user,
	accounts.time_zone,
	accounts.address_line_1,
	accounts.address_line_2,
	accounts.city,
	accounts.state,
	accounts.zip_code,
	accounts.country,
	accounts.latitude,
	accounts.longitude,
	accounts.last_payment_provider_sync_occurred_at,
	accounts.webhook_hmac_secret,
	accounts.created_at,
	accounts.last_updated_at,
	accounts.archived_at,
	(
		SELECT COUNT(accounts.id)
		FROM accounts
			JOIN account_user_memberships ON account_user_memberships.belongs_to_account = accounts.id
		WHERE accounts.archived_at IS NULL
			AND account_user_memberships.belongs_to_user = sqlc.arg(belongs_to_user)
			AND accounts.created_at > COALESCE(sqlc.narg(created_after), (SELECT NOW() - '999 years'::INTERVAL))
			AND accounts.created_at < COALESCE(sqlc.narg(created_before), (SELECT NOW() + '999 years'::INTERVAL))
			AND (
				accounts.last_updated_at IS NULL
				OR accounts.last_updated_at > COALESCE(sqlc.narg(updated_after), (SELECT NOW() - '999 years'::INTERVAL))
			)
			AND (
				accounts.last_updated_at IS NULL
				OR accounts.last_updated_at < COALESCE(sqlc.narg(updated_before), (SELECT NOW() + '999 years'::INTERVAL))
			)
	) as filtered_count,
	(
		SELECT COUNT(accounts.id)
		FROM accounts
		WHERE accounts.archived_at IS NULL
	) AS total_count
FROM accounts
	JOIN account_user_memberships ON account_user_memberships.belongs_to_account = accounts.id
	JOIN users ON account_user_memberships.belongs_to_user = users.id
WHERE accounts.archived_at IS NULL
	AND account_user_memberships.archived_at IS NULL
	AND account_user_memberships.belongs_to_user = sqlc.arg(belongs_to_user)
	AND accounts.created_at > COALESCE(sqlc.narg(created_after), (SELECT NOW() - '999 years'::INTERVAL))
	AND accounts.created_at < COALESCE(sqlc.narg(created_before), (SELECT NOW() + '999 years'::INTERVAL))
	AND (
		accounts.last_updated_at IS NULL
		OR accounts.last_updated_at > COALESCE(sqlc.narg(updated_after), (SELECT NOW() - '999 years'::INTERVAL))
	)
	AND (
		accounts.last_updated_at IS NULL
		OR accounts.last_updated_at < COALESCE(sqlc.narg(updated_before), (SELECT NOW() + '999 years'::INTERVAL))
	)
LIMIT sqlc.narg(query_limit)
OFFSET sqlc.narg(query_offset);

-- name: UpdateAccount :execrows

UPDATE accounts SET
	name = sqlc.arg(name),
	contact_phone = sqlc.arg(contact_phone),
	address_line_1 = sqlc.arg(address_line_1),
	address_line_2 = sqlc.arg(address_line_2),
	city = sqlc.arg(city),
	state = sqlc.arg(state),
	zip_code = sqlc.arg(zip_code),
	country = sqlc.arg(country),
	latitude = sqlc.arg(latitude),
	longitude = sqlc.arg(longitude),
	last_updated_at = NOW()
WHERE archived_at IS NULL
	AND belongs_to_user = sqlc.arg(belongs_to_user)
	AND id = sqlc.arg(id);

-- name: UpdateAccountWebhookEncryptionKey :execrows

UPDATE accounts SET
	webhook_hmac_secret = sqlc.arg(webhook_hmac_secret),
	last_updated_at = NOW()
WHERE archived_at IS NULL
	AND belongs_to_user = sqlc.arg(belongs_to_user)
	AND id = sqlc.arg(id);
