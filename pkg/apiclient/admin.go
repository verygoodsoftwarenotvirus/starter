package apiclient

import (
	"context"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

// UpdateUserAccountStatus updates a user's account status.
func (c *Client) UpdateUserAccountStatus(ctx context.Context, input *types.UserAccountStatusUpdateInput) error {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	if input == nil {
		return ErrNilInputProvided
	}

	tracing.AttachToSpan(span, keys.UserIDKey, input.TargetUserID)

	if err := input.ValidateWithContext(ctx); err != nil {
		return observability.PrepareError(err, span, "validating input")
	}

	req, err := c.requestBuilder.BuildUserAccountStatusUpdateInputRequest(ctx, input)
	if err != nil {
		return observability.PrepareError(err, span, "building user account status update request")
	}

	res, err := c.fetchResponseToRequest(ctx, c.authedClient, req)
	if err != nil {
		return observability.PrepareError(err, span, "updating user account status")
	}

	c.closeResponseBody(ctx, res)

	if err = errorFromResponse(res); err != nil {
		return observability.PrepareError(err, span, "invalid response status")
	}

	return nil
}
