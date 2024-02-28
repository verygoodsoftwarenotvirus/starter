-- name: ArchiveWebhook :execrows

UPDATE webhooks SET
	archived_at = NOW()
WHERE archived_at IS NULL
	AND id = sqlc.arg(id)
	AND belongs_to_account = sqlc.arg(belongs_to_account);

-- name: ArchiveWebhookTriggerEvent :execrows

UPDATE webhook_trigger_events SET
	archived_at = NOW()
WHERE archived_at IS NULL
	AND id = sqlc.arg(id)
	AND belongs_to_webhook = sqlc.arg(belongs_to_webhook);

-- name: CreateWebhook :exec

INSERT INTO webhooks (
	id,
	name,
	content_type,
	url,
	method,
	belongs_to_account
) VALUES (
	sqlc.arg(id),
	sqlc.arg(name),
	sqlc.arg(content_type),
	sqlc.arg(url),
	sqlc.arg(method),
	sqlc.arg(belongs_to_account)
);

-- name: CheckWebhookExistence :one

SELECT EXISTS(
	SELECT webhooks.id
	FROM webhooks
	WHERE webhooks.archived_at IS NULL
	AND webhooks.id = sqlc.arg(id)
	AND webhooks.belongs_to_account = sqlc.arg(belongs_to_account)
);

-- name: GetWebhooksForAccount :many

SELECT
	webhooks.id,
	webhooks.name,
	webhooks.content_type,
	webhooks.url,
	webhooks.method,
	webhook_trigger_events.id,
	webhook_trigger_events.trigger_event,
	webhook_trigger_events.belongs_to_webhook,
	webhook_trigger_events.created_at,
	webhook_trigger_events.archived_at,
	webhooks.created_at,
	webhooks.last_updated_at,
	webhooks.archived_at,
	webhooks.belongs_to_account,
	(
		SELECT COUNT(webhooks.id)
		FROM webhooks
		WHERE webhooks.archived_at IS NULL
			AND webhooks.created_at > COALESCE(sqlc.narg(created_after), (SELECT NOW() - '999 years'::INTERVAL))
			AND webhooks.created_at < COALESCE(sqlc.narg(created_before), (SELECT NOW() + '999 years'::INTERVAL))
			AND (
				webhooks.last_updated_at IS NULL
				OR webhooks.last_updated_at > COALESCE(sqlc.narg(updated_before), (SELECT NOW() - '999 years'::INTERVAL))
			)
			AND (
				webhooks.last_updated_at IS NULL
				OR webhooks.last_updated_at < COALESCE(sqlc.narg(updated_after), (SELECT NOW() + '999 years'::INTERVAL))
			)
			AND webhooks.belongs_to_account = sqlc.arg(account_id)
	) AS filtered_count,
	(
		SELECT COUNT(webhooks.id)
		FROM webhooks
		WHERE webhooks.archived_at IS NULL
			AND webhooks.belongs_to_account = sqlc.arg(account_id)
			AND webhook_trigger_events.archived_at IS NULL
	) AS total_count
FROM webhooks
	JOIN webhook_trigger_events ON webhooks.id = webhook_trigger_events.belongs_to_webhook
WHERE webhooks.archived_at IS NULL
	AND webhooks.created_at > COALESCE(sqlc.narg(created_after), (SELECT NOW() - '999 years'::INTERVAL))
	AND webhooks.created_at < COALESCE(sqlc.narg(created_before), (SELECT NOW() + '999 years'::INTERVAL))
	AND (
		webhooks.last_updated_at IS NULL
		OR webhooks.last_updated_at > COALESCE(sqlc.narg(updated_after), (SELECT NOW() - '999 years'::INTERVAL))
	)
	AND (
		webhooks.last_updated_at IS NULL
		OR webhooks.last_updated_at < COALESCE(sqlc.narg(updated_before), (SELECT NOW() + '999 years'::INTERVAL))
	)
	AND webhooks.belongs_to_account = sqlc.arg(account_id)
	AND webhook_trigger_events.archived_at IS NULL
LIMIT sqlc.narg(query_limit)
OFFSET sqlc.narg(query_offset);

-- name: GetWebhooksForAccountAndEvent :many

SELECT
	webhooks.id,
	webhooks.name,
	webhooks.content_type,
	webhooks.url,
	webhooks.method,
	webhooks.created_at,
	webhooks.last_updated_at,
	webhooks.archived_at,
	webhooks.belongs_to_account
FROM webhooks
	JOIN webhook_trigger_events ON webhooks.id = webhook_trigger_events.belongs_to_webhook
WHERE webhook_trigger_events.archived_at IS NULL
	AND webhook_trigger_events.trigger_event = sqlc.arg(trigger_event)
	AND webhooks.belongs_to_account = sqlc.arg(belongs_to_account)
	AND webhooks.archived_at IS NULL;

-- name: GetWebhook :many

SELECT
	webhooks.id as webhook_id,
	webhooks.name as webhook_name,
	webhooks.content_type as webhook_content_type,
	webhooks.url as webhook_url,
	webhooks.method as webhook_method,
	webhook_trigger_events.id as webhook_trigger_event_id,
	webhook_trigger_events.trigger_event as webhook_trigger_event_trigger_event,
	webhook_trigger_events.belongs_to_webhook as webhook_trigger_event_belongs_to_webhook,
	webhook_trigger_events.created_at as webhook_trigger_event_created_at,
	webhook_trigger_events.archived_at as webhook_trigger_event_archived_at,
	webhooks.created_at as webhook_created_at,
	webhooks.last_updated_at as webhook_last_updated_at,
	webhooks.archived_at as webhook_archived_at,
	webhooks.belongs_to_account as webhook_belongs_to_account
FROM webhooks
	JOIN webhook_trigger_events ON webhooks.id = webhook_trigger_events.belongs_to_webhook
WHERE webhook_trigger_events.archived_at IS NULL
	AND webhooks.archived_at IS NULL
	AND webhooks.belongs_to_account = sqlc.arg(belongs_to_account)
	AND webhooks.id = sqlc.arg(id);
