package apiclient

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"reflect"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
)

// errorFromResponse returns library errors according to a response's status code.
func errorFromResponse(res *http.Response) error {
	if res == nil {
		return ErrNilResponse
	}

	switch res.StatusCode {
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusBadRequest:
		return ErrInvalidRequestInput
	case http.StatusUnauthorized, http.StatusForbidden:
		return ErrUnauthorized
	case http.StatusInternalServerError:
		return ErrInternalServerError
	default:
		return nil
	}
}

// argIsNotPointer checks an argument and returns whether it is a pointer.
func argIsNotPointer(i any) (bool, error) {
	if i == nil || reflect.TypeOf(i).Kind() != reflect.Ptr {
		return true, ErrArgumentIsNotPointer
	}

	return false, nil
}

// argIsNotNil checks an argument and returns whether it is nil.
func argIsNotNil(i any) (bool, error) {
	if i == nil {
		return true, ErrNilInputProvided
	}

	return false, nil
}

// argIsNotPointerOrNil does what it says on the tin. This function is primarily useful for detecting
// if a destination value is valid before decoding an HTTP response, for instance.
func argIsNotPointerOrNil(i any) error {
	if nn, err := argIsNotNil(i); nn || err != nil {
		return err
	}

	if np, err := argIsNotPointer(i); np || err != nil {
		return err
	}

	return nil
}

// unmarshalBody takes an HTTP response and JSON decodes its body into a destination value. The error returned here
// should only ever be received in testing, and should never be encountered by an end-user.
func (c *Client) unmarshalBody(ctx context.Context, res *http.Response, dest any) error {
	_, span := c.tracer.StartSpan(ctx)
	defer span.End()

	logger := c.logger.WithResponse(res)

	if err := argIsNotPointerOrNil(dest); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "nil marshal target")
	}

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "unmarshalling error response")
	}

	if res.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("unexpected status: %d", res.StatusCode)
	}

	if err = c.encoder.Unmarshal(ctx, bodyBytes, &dest); err != nil {
		logger = logger.WithValue("raw_body", string(bodyBytes))
		return observability.PrepareAndLogError(err, logger, span, "unmarshalling response body")
	}

	return nil
}
