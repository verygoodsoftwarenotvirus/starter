package encoding

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"

	"github.com/keith-turner/ecoji/v2"
)

type (
	// ClientEncoder is an encoder for a service client.
	ClientEncoder interface {
		ContentType() string
		Unmarshal(ctx context.Context, data []byte, v any) error
		Encode(ctx context.Context, dest io.Writer, v any) error
		EncodeReader(ctx context.Context, data any) (io.Reader, error)
	}

	// clientEncoder is our concrete implementation of ClientEncoder.
	clientEncoder struct {
		logger      logging.Logger
		tracer      tracing.Tracer
		contentType *contentType
	}
)

func (e *clientEncoder) Unmarshal(ctx context.Context, data []byte, v any) error {
	_, span := e.tracer.StartSpan(ctx)
	defer span.End()

	logger := e.logger.WithValue("data_length", len(data))
	var unmarshalFunc func(data []byte, v any) error

	switch e.contentType {
	case ContentTypeXML:
		unmarshalFunc = xml.Unmarshal
	case ContentTypeEmoji:
		unmarshalFunc = unmarshalEmoji
	default:
		unmarshalFunc = json.Unmarshal
	}

	if err := unmarshalFunc(data, v); err != nil {
		return observability.PrepareError(err, span, "unmarshalling JSON content")
	}

	logger.Debug("unmarshalled")

	return nil
}

func (e *clientEncoder) Encode(ctx context.Context, dest io.Writer, data any) error {
	_, span := e.tracer.StartSpan(ctx)
	defer span.End()

	var err error

	switch e.contentType {
	case ContentTypeXML:
		err = xml.NewEncoder(dest).Encode(data)
	case ContentTypeEmoji:
		emojiEncoded, emojiEncodeErr := marshalEmoji(data)
		if emojiEncodeErr != nil {
			return emojiEncodeErr
		}

		_, err = dest.Write(emojiEncoded)
	default:
		err = json.NewEncoder(dest).Encode(data)
	}

	if err != nil {
		return observability.PrepareError(err, span, "encoding JSON content")
	}

	return nil
}

func marshalEmoji(v any) ([]byte, error) {
	var gobWriter bytes.Buffer
	gobEncoder := gob.NewEncoder(&gobWriter)
	if err := gobEncoder.Encode(v); err != nil {
		return nil, fmt.Errorf("encoding to gob: %w", err)
	}

	gobEncoded := gobWriter.Bytes()

	r := bytes.NewBuffer(gobEncoded)
	w := bytes.NewBuffer([]byte{})

	if err := ecoji.EncodeV2(r, w, 76); err != nil {
		return nil, fmt.Errorf("encoding to emoji: %w", err)
	}

	return w.Bytes(), nil
}

func unmarshalEmoji(data []byte, v any) error {
	w := bytes.NewBuffer([]byte{})

	if err := ecoji.Decode(bytes.NewReader(data), w); err != nil {
		return fmt.Errorf("decoding emoji: %w", err)
	}

	return gob.NewDecoder(w).Decode(v)
}

func (e *clientEncoder) EncodeReader(ctx context.Context, data any) (io.Reader, error) {
	_, span := e.tracer.StartSpan(ctx)
	defer span.End()

	var marshalFunc func(v any) ([]byte, error)

	switch e.contentType {
	case ContentTypeXML:
		marshalFunc = xml.Marshal
	case ContentTypeEmoji:
		marshalFunc = marshalEmoji
	default:
		marshalFunc = json.Marshal
	}

	out, err := marshalFunc(data)
	if err != nil {
		return nil, observability.PrepareError(err, span, "marshaling to XML")
	}

	return bytes.NewReader(out), nil
}

// ProvideClientEncoder provides a ClientEncoder.
func ProvideClientEncoder(logger logging.Logger, tracerProvider tracing.TracerProvider, encoding *contentType) ClientEncoder {
	return &clientEncoder{
		logger:      logging.EnsureLogger(logger).WithName("client_encoder"),
		tracer:      tracing.NewTracer(tracing.EnsureTracerProvider(tracerProvider).Tracer("client_encoder")),
		contentType: encoding,
	}
}
