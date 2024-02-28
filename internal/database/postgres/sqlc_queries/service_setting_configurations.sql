-- name: ArchiveServiceSettingConfiguration :execrows

UPDATE service_setting_configurations SET
	archived_at = NOW()
WHERE archived_at IS NULL
	AND id = sqlc.arg(id);

-- name: CreateServiceSettingConfiguration :exec

INSERT INTO service_setting_configurations (
	id,
	value,
	notes,
	service_setting_id,
	belongs_to_user,
	belongs_to_account
) VALUES (
	sqlc.arg(id),
	sqlc.arg(value),
	sqlc.arg(notes),
	sqlc.arg(service_setting_id),
	sqlc.arg(belongs_to_user),
	sqlc.arg(belongs_to_account)
);

-- name: CheckServiceSettingConfigurationExistence :one

SELECT EXISTS (
	SELECT service_setting_configurations.id
	FROM service_setting_configurations
	WHERE service_setting_configurations.archived_at IS NULL
		AND service_setting_configurations.id = sqlc.arg(id)
);

-- name: GetServiceSettingConfigurationByID :one

SELECT
	service_setting_configurations.id,
	service_setting_configurations.value,
	service_setting_configurations.notes,
	service_settings.id as service_setting_id,
	service_settings.name as service_setting_name,
	service_settings.type as service_setting_type,
	service_settings.description as service_setting_description,
	service_settings.default_value as service_setting_default_value,
	service_settings.enumeration as service_setting_enumeration,
	service_settings.admins_only as service_setting_admins_only,
	service_settings.created_at as service_setting_created_at,
	service_settings.last_updated_at as service_setting_last_updated_at,
	service_settings.archived_at as service_setting_archived_at,
	service_setting_configurations.belongs_to_user,
	service_setting_configurations.belongs_to_account,
	service_setting_configurations.created_at,
	service_setting_configurations.last_updated_at,
	service_setting_configurations.archived_at
FROM service_setting_configurations
	JOIN service_settings ON service_setting_configurations.service_setting_id=service_settings.id
WHERE service_settings.archived_at IS NULL
	AND service_setting_configurations.archived_at IS NULL
	AND service_setting_configurations.id = sqlc.arg(id);

-- name: GetServiceSettingConfigurationForAccountBySettingName :one

SELECT
	service_setting_configurations.id,
	service_setting_configurations.value,
	service_setting_configurations.notes,
	service_settings.id as service_setting_id,
	service_settings.name as service_setting_name,
	service_settings.type as service_setting_type,
	service_settings.description as service_setting_description,
	service_settings.default_value as service_setting_default_value,
	service_settings.enumeration as service_setting_enumeration,
	service_settings.admins_only as service_setting_admins_only,
	service_settings.created_at as service_setting_created_at,
	service_settings.last_updated_at as service_setting_last_updated_at,
	service_settings.archived_at as service_setting_archived_at,
	service_setting_configurations.belongs_to_user,
	service_setting_configurations.belongs_to_account,
	service_setting_configurations.created_at,
	service_setting_configurations.last_updated_at,
	service_setting_configurations.archived_at
FROM service_setting_configurations
	JOIN service_settings ON service_setting_configurations.service_setting_id=service_settings.id
WHERE service_settings.archived_at IS NULL
	AND service_setting_configurations.archived_at IS NULL
	AND service_settings.name = sqlc.arg(name)
	AND service_setting_configurations.belongs_to_account = sqlc.arg(belongs_to_account);

-- name: GetServiceSettingConfigurationForUserBySettingName :one

SELECT
	service_setting_configurations.id,
	service_setting_configurations.value,
	service_setting_configurations.notes,
	service_settings.id as service_setting_id,
	service_settings.name as service_setting_name,
	service_settings.type as service_setting_type,
	service_settings.description as service_setting_description,
	service_settings.default_value as service_setting_default_value,
	service_settings.enumeration as service_setting_enumeration,
	service_settings.admins_only as service_setting_admins_only,
	service_settings.created_at as service_setting_created_at,
	service_settings.last_updated_at as service_setting_last_updated_at,
	service_settings.archived_at as service_setting_archived_at,
	service_setting_configurations.belongs_to_user,
	service_setting_configurations.belongs_to_account,
	service_setting_configurations.created_at,
	service_setting_configurations.last_updated_at,
	service_setting_configurations.archived_at
FROM service_setting_configurations
	JOIN service_settings ON service_setting_configurations.service_setting_id=service_settings.id
WHERE service_settings.archived_at IS NULL
	AND service_setting_configurations.archived_at IS NULL
	AND service_settings.name = sqlc.arg(name)
	AND service_setting_configurations.belongs_to_user = sqlc.arg(belongs_to_user);

-- name: GetServiceSettingConfigurationsForAccount :many

SELECT
	service_setting_configurations.id,
	service_setting_configurations.value,
	service_setting_configurations.notes,
	service_settings.id as service_setting_id,
	service_settings.name as service_setting_name,
	service_settings.type as service_setting_type,
	service_settings.description as service_setting_description,
	service_settings.default_value as service_setting_default_value,
	service_settings.enumeration as service_setting_enumeration,
	service_settings.admins_only as service_setting_admins_only,
	service_settings.created_at as service_setting_created_at,
	service_settings.last_updated_at as service_setting_last_updated_at,
	service_settings.archived_at as service_setting_archived_at,
	service_setting_configurations.belongs_to_user,
	service_setting_configurations.belongs_to_account,
	service_setting_configurations.created_at,
	service_setting_configurations.last_updated_at,
	service_setting_configurations.archived_at
FROM service_setting_configurations
	JOIN service_settings ON service_setting_configurations.service_setting_id=service_settings.id
WHERE service_settings.archived_at IS NULL
	AND service_setting_configurations.archived_at IS NULL
	AND service_setting_configurations.belongs_to_account = sqlc.arg(belongs_to_account);

-- name: GetServiceSettingConfigurationsForUser :many

SELECT
	service_setting_configurations.id,
	service_setting_configurations.value,
	service_setting_configurations.notes,
	service_settings.id as service_setting_id,
	service_settings.name as service_setting_name,
	service_settings.type as service_setting_type,
	service_settings.description as service_setting_description,
	service_settings.default_value as service_setting_default_value,
	service_settings.enumeration as service_setting_enumeration,
	service_settings.admins_only as service_setting_admins_only,
	service_settings.created_at as service_setting_created_at,
	service_settings.last_updated_at as service_setting_last_updated_at,
	service_settings.archived_at as service_setting_archived_at,
	service_setting_configurations.belongs_to_user,
	service_setting_configurations.belongs_to_account,
	service_setting_configurations.created_at,
	service_setting_configurations.last_updated_at,
	service_setting_configurations.archived_at
FROM service_setting_configurations
	JOIN service_settings ON service_setting_configurations.service_setting_id=service_settings.id
WHERE service_settings.archived_at IS NULL
	AND service_setting_configurations.archived_at IS NULL
	AND service_setting_configurations.belongs_to_user = sqlc.arg(belongs_to_user);

-- name: UpdateServiceSettingConfiguration :execrows

UPDATE service_setting_configurations SET
	value = sqlc.arg(value),
	notes = sqlc.arg(notes),
	service_setting_id = sqlc.arg(service_setting_id),
	belongs_to_user = sqlc.arg(belongs_to_user),
	belongs_to_account = sqlc.arg(belongs_to_account),
	last_updated_at = NOW()
WHERE archived_at IS NULL
	AND id = sqlc.arg(id);
