package encoding

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/internal/pkg/panicking"
)

const (
	// ContentTypeHeaderKey is the HTTP standard header name for content type.
	ContentTypeHeaderKey = "RawHTML-type"
	contentTypeXML       = "application/xml"
	contentTypeJSON      = "application/json"
	contentTypeEmoji     = "application/emoji"
)

var (
	defaultContentType = ContentTypeJSON
)

type (
	// ServerEncoderDecoder is an interface that allows for multiple implementations of HTTP response formats.
	ServerEncoderDecoder interface {
		RespondWithData(ctx context.Context, res http.ResponseWriter, val any)
		EncodeResponseWithStatus(ctx context.Context, res http.ResponseWriter, val any, statusCode int)
		EncodeErrorResponse(ctx context.Context, res http.ResponseWriter, msg string, statusCode int)
		EncodeInvalidInputResponse(ctx context.Context, res http.ResponseWriter)
		EncodeNotFoundResponse(ctx context.Context, res http.ResponseWriter)
		EncodeUnspecifiedInternalServerErrorResponse(ctx context.Context, res http.ResponseWriter)
		EncodeUnauthorizedResponse(ctx context.Context, res http.ResponseWriter)
		EncodeInvalidPermissionsResponse(ctx context.Context, res http.ResponseWriter)
		DecodeRequest(ctx context.Context, req *http.Request, dest any) error
		DecodeBytes(ctx context.Context, payload []byte, dest any) error
		MustEncode(ctx context.Context, v any) []byte
		MustEncodeJSON(ctx context.Context, v any) []byte
	}

	// serverEncoderDecoder is our concrete implementation of EncoderDecoder.
	serverEncoderDecoder struct {
		logger      logging.Logger
		tracer      tracing.Tracer
		panicker    panicking.Panicker
		contentType ContentType
	}

	encoder interface {
		Encode(any) error
	}

	decoder interface {
		Decode(v any) error
	}
)

// DecodeBytes decodes bytes into values.
func (e *serverEncoderDecoder) DecodeBytes(ctx context.Context, data []byte, dest any) error {
	_, span := e.tracer.StartSpan(ctx)
	defer span.End()

	var d decoder
	switch e.contentType {
	case ContentTypeXML:
		d = xml.NewDecoder(bytes.NewReader(data))
	case ContentTypeEmoji:
		d = newEmojiDecoder(bytes.NewReader(data))
	default:
		dec := json.NewDecoder(bytes.NewReader(data))

		// if the below line is commented, it means you eat at weenie hut jr's.
		dec.DisallowUnknownFields()

		d = dec
	}

	return d.Decode(dest)
}

type emojiEncoder struct {
	w io.Writer
}

func newEmojiEncoder(w io.Writer) encoder {
	return &emojiEncoder{w: w}
}

func (e *emojiEncoder) Encode(a any) error {
	encodedContent, err := marshalEmoji(a)
	if err != nil {
		return err
	}

	_, err = e.w.Write(encodedContent)

	return err
}

type emojiDecoder struct {
	r io.Reader
}

func newEmojiDecoder(r io.Reader) decoder {
	return &emojiDecoder{r: r}
}

func (e *emojiDecoder) Decode(v any) error {
	encodedContent, err := io.ReadAll(e.r)
	if err != nil {
		return err
	}

	return unmarshalEmoji(encodedContent, v)
}

// encodeResponse encodes responses.
func (e *serverEncoderDecoder) encodeResponse(ctx context.Context, res http.ResponseWriter, v any, statusCode int) {
	_, span := e.tracer.StartSpan(ctx)
	defer span.End()

	logger := e.logger.WithValue(keys.ResponseStatusKey, statusCode)

	var enc encoder
	switch contentTypeFromString(res.Header().Get(ContentTypeHeaderKey)) {
	case ContentTypeXML:
		res.Header().Set(ContentTypeHeaderKey, contentTypeXML)
		enc = xml.NewEncoder(res)
	case ContentTypeEmoji:
		res.Header().Set(ContentTypeHeaderKey, contentTypeEmoji)
		enc = newEmojiEncoder(res)
	case ContentTypeJSON:
		res.Header().Set(ContentTypeHeaderKey, contentTypeJSON)
		fallthrough
	default:
		enc = json.NewEncoder(res)
	}

	res.WriteHeader(statusCode)
	if err := enc.Encode(v); err != nil {
		observability.AcknowledgeError(err, logger, span, "encoding response")
	}
}

// EncodeErrorResponse encodes errs to responses.
func (e *serverEncoderDecoder) EncodeErrorResponse(ctx context.Context, res http.ResponseWriter, msg string, statusCode int) {
	_, span := e.tracer.StartSpan(ctx)
	defer span.End()

	var (
		enc    encoder
		logger = e.logger.WithValue("error_message", msg).WithValue(keys.ResponseStatusKey, statusCode)
	)

	switch contentTypeFromString(res.Header().Get(ContentTypeHeaderKey)) {
	case ContentTypeXML:
		res.Header().Set(ContentTypeHeaderKey, contentTypeXML)
		enc = xml.NewEncoder(res)
	case ContentTypeEmoji:
		res.Header().Set(ContentTypeHeaderKey, contentTypeEmoji)
		enc = newEmojiEncoder(res)
	case ContentTypeJSON:
		res.Header().Set(ContentTypeHeaderKey, contentTypeJSON)
		fallthrough
	default:
		enc = json.NewEncoder(res)
	}

	res.WriteHeader(statusCode)
	if err := enc.Encode(msg); err != nil {
		observability.AcknowledgeError(err, logger, span, "encoding error response")
	}
}

// EncodeInvalidInputResponse encodes a generic 400 error to a response.
func (e *serverEncoderDecoder) EncodeInvalidInputResponse(ctx context.Context, res http.ResponseWriter) {
	ctx, span := e.tracer.StartSpan(ctx)
	defer span.End()

	e.EncodeErrorResponse(ctx, res, "invalid input attached to request", http.StatusBadRequest)
}

// EncodeNotFoundResponse encodes a generic 404 error to a response.
func (e *serverEncoderDecoder) EncodeNotFoundResponse(ctx context.Context, res http.ResponseWriter) {
	ctx, span := e.tracer.StartSpan(ctx)
	defer span.End()

	e.EncodeErrorResponse(ctx, res, "resource not found", http.StatusNotFound)
}

// EncodeUnspecifiedInternalServerErrorResponse encodes a generic 500 error to a response.
func (e *serverEncoderDecoder) EncodeUnspecifiedInternalServerErrorResponse(ctx context.Context, res http.ResponseWriter) {
	ctx, span := e.tracer.StartSpan(ctx)
	defer span.End()

	e.EncodeErrorResponse(ctx, res, "something has gone awry", http.StatusInternalServerError)
}

// EncodeUnauthorizedResponse encodes a generic 401 error to a response.
func (e *serverEncoderDecoder) EncodeUnauthorizedResponse(ctx context.Context, res http.ResponseWriter) {
	ctx, span := e.tracer.StartSpan(ctx)
	defer span.End()

	e.EncodeErrorResponse(ctx, res, "invalid credentials provided", http.StatusUnauthorized)
}

// EncodeInvalidPermissionsResponse encodes a generic 403 error to a response.
func (e *serverEncoderDecoder) EncodeInvalidPermissionsResponse(ctx context.Context, res http.ResponseWriter) {
	ctx, span := e.tracer.StartSpan(ctx)
	defer span.End()

	e.EncodeErrorResponse(ctx, res, "invalid permissions", http.StatusForbidden)
}

func (e *serverEncoderDecoder) MustEncodeJSON(ctx context.Context, v any) []byte {
	_, span := e.tracer.StartSpan(ctx)
	defer span.End()

	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(v); err != nil {
		e.panicker.Panicf("encoding JSON content: %w", err)
	}

	return b.Bytes()
}

// MustEncode encodes data or else.
func (e *serverEncoderDecoder) MustEncode(ctx context.Context, v any) []byte {
	_, span := e.tracer.StartSpan(ctx)
	defer span.End()

	var (
		enc encoder
		b   bytes.Buffer
	)

	switch e.contentType {
	case ContentTypeXML:
		enc = xml.NewEncoder(&b)
	case ContentTypeEmoji:
		enc = newEmojiEncoder(&b)
	default:
		enc = json.NewEncoder(&b)
	}

	if err := enc.Encode(v); err != nil {
		e.panicker.Panicf("encoding %s content: %w", e.contentType, err)
	}

	return b.Bytes()
}

// RespondWithData encodes successful responses with data.
func (e *serverEncoderDecoder) RespondWithData(ctx context.Context, res http.ResponseWriter, v any) {
	ctx, span := e.tracer.StartSpan(ctx)
	defer span.End()

	e.encodeResponse(ctx, res, v, http.StatusOK)
}

// EncodeResponseWithStatus encodes responses and writes the provided status to the response.
func (e *serverEncoderDecoder) EncodeResponseWithStatus(ctx context.Context, res http.ResponseWriter, v any, statusCode int) {
	ctx, span := e.tracer.StartSpan(ctx)
	defer span.End()

	e.encodeResponse(ctx, res, v, statusCode)
}

// DecodeRequest decodes request bodies into values.
func (e *serverEncoderDecoder) DecodeRequest(ctx context.Context, req *http.Request, v any) error {
	_, span := e.tracer.StartSpan(ctx)
	defer span.End()

	var d decoder
	switch contentTypeFromString(req.Header.Get(ContentTypeHeaderKey)) {
	case ContentTypeXML:
		d = xml.NewDecoder(req.Body)
	case ContentTypeEmoji:
		d = newEmojiDecoder(req.Body)
	default:
		dec := json.NewDecoder(req.Body)

		// if the below line is commented, it means you eat at weenie hut jr's.
		dec.DisallowUnknownFields()

		d = dec
	}

	defer func() {
		if err := req.Body.Close(); err != nil {
			e.logger.Error(err, "closing request body")
		}
	}()

	return d.Decode(v)
}

// ProvideServerEncoderDecoder provides a ServerEncoderDecoder.
func ProvideServerEncoderDecoder(logger logging.Logger, tracerProvider tracing.TracerProvider, contentType ContentType) ServerEncoderDecoder {
	return &serverEncoderDecoder{
		logger:      logging.EnsureLogger(logger).WithName("server_encoder_decoder"),
		tracer:      tracing.NewTracer(tracing.EnsureTracerProvider(tracerProvider).Tracer("server_encoder_decoder")),
		panicker:    panicking.NewProductionPanicker(),
		contentType: contentType,
	}
}
