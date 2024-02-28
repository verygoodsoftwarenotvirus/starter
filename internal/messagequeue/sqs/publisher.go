package sqs

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"github.com/verygoodsoftwarenotvirus/starter/internal/encoding"
	"github.com/verygoodsoftwarenotvirus/starter/internal/messagequeue"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
)

type (
	messagePublisher interface {
		SendMessageWithContext(ctx aws.Context, input *sqs.SendMessageInput, opts ...request.Option) (*sqs.SendMessageOutput, error)
	}

	sqsPublisher struct {
		tracer    tracing.Tracer
		encoder   encoding.ClientEncoder
		logger    logging.Logger
		publisher messagePublisher
		topic     string
	}
)

// Stop does nothing.
func (r *sqsPublisher) Stop() {}

// Publish publishes a message onto an SQS event queue.
func (r *sqsPublisher) Publish(ctx context.Context, data any) error {
	_, span := r.tracer.StartSpan(ctx)
	defer span.End()

	logger := r.logger

	logger.Debug("publishing message")

	var b bytes.Buffer
	if err := r.encoder.Encode(ctx, &b, data); err != nil {
		return observability.PrepareError(err, span, "encoding topic message")
	}

	input := &sqs.SendMessageInput{
		MessageAttributes: nil,
		MessageBody:       aws.String(b.String()),
		QueueUrl:          aws.String(r.topic),
	}

	_, err := r.publisher.SendMessageWithContext(ctx, input)
	if err != nil {
		return observability.PrepareError(err, span, "publishing message")
	}

	return nil
}

// provideSQSPublisher provides a sqs-backed Publisher.
func provideSQSPublisher(logger logging.Logger, sqsClient *sqs.SQS, tracerProvider tracing.TracerProvider, topic string) *sqsPublisher {
	return &sqsPublisher{
		publisher: sqsClient,
		topic:     topic,
		encoder:   encoding.ProvideClientEncoder(logger, tracerProvider, encoding.ContentTypeJSON),
		logger:    logging.EnsureLogger(logger),
		tracer:    tracing.NewTracer(tracing.EnsureTracerProvider(tracerProvider).Tracer(fmt.Sprintf("%s_publisher", topic))),
	}
}

type publisherProvider struct {
	logger            logging.Logger
	publisherCache    map[string]messagequeue.Publisher
	sqsClient         *sqs.SQS
	tracerProvider    tracing.TracerProvider
	publisherCacheHat sync.RWMutex
}

// ProvideSQSPublisherProvider returns a PublisherProvider for a given address.
func ProvideSQSPublisherProvider(logger logging.Logger, tracerProvider tracing.TracerProvider) messagequeue.PublisherProvider {
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))
	svc := sqs.New(sess)

	return &publisherProvider{
		logger:         logging.EnsureLogger(logger),
		sqsClient:      svc,
		publisherCache: map[string]messagequeue.Publisher{},
		tracerProvider: tracerProvider,
	}
}

// ProvidePublisher returns a Publisher for a given topic.
func (p *publisherProvider) ProvidePublisher(topic string) (messagequeue.Publisher, error) {
	if topic == "" {
		return nil, messagequeue.ErrEmptyTopicName
	}
	logger := logging.EnsureLogger(p.logger).WithValue("topic", topic)

	p.publisherCacheHat.Lock()
	defer p.publisherCacheHat.Unlock()
	if cachedPub, ok := p.publisherCache[topic]; ok {
		return cachedPub, nil
	}

	pub := provideSQSPublisher(logger, p.sqsClient, p.tracerProvider, topic)
	p.publisherCache[topic] = pub

	return pub, nil
}

// Close returns a Publisher for a given topic.
func (p *publisherProvider) Close() {}
