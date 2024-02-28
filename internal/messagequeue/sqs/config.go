package sqs

// Config configures a SQS-backed consumer.
type Config struct {
	QueueAddress string `json:"messageQueueAddress" toml:"message_queue_address,omitempty"`
}
