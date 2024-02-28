-- name: CreateWebhookTriggerEvent :exec

INSERT INTO webhook_trigger_events (
	id,
	trigger_event,
	belongs_to_webhook
) VALUES (
	sqlc.arg(id),
	sqlc.arg(trigger_event),
	sqlc.arg(belongs_to_webhook)
);
