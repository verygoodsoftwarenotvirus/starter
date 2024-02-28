package apiclient

import (
	"context"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

// GetUserNotification gets a user notification.
func (c *Client) GetUserNotification(ctx context.Context, userNotificationID string) (*types.UserNotification, error) {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	logger := c.logger.Clone()

	if userNotificationID == "" {
		return nil, ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.UserNotificationIDKey, userNotificationID)
	tracing.AttachToSpan(span, keys.UserNotificationIDKey, userNotificationID)

	req, err := c.requestBuilder.BuildGetUserNotificationRequest(ctx, userNotificationID)
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "building get user notification request")
	}

	var apiResponse *types.APIResponse[*types.UserNotification]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "retrieving user notification")
	}

	return apiResponse.Data, nil
}

// GetUserNotifications retrieves a list of user notifications.
func (c *Client) GetUserNotifications(ctx context.Context, filter *types.QueryFilter) (*types.QueryFilteredResult[types.UserNotification], error) {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	logger := c.logger.Clone()
	logger = filter.AttachToLogger(logger)
	tracing.AttachQueryFilterToSpan(span, filter)

	req, err := c.requestBuilder.BuildGetUserNotificationsRequest(ctx, filter)
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "building user notifications list request")
	}

	var apiResponse *types.APIResponse[[]*types.UserNotification]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "retrieving user notifications")
	}

	response := &types.QueryFilteredResult[types.UserNotification]{
		Data:       apiResponse.Data,
		Pagination: *apiResponse.Pagination,
	}

	return response, nil
}

// CreateUserNotification creates a user notification.
func (c *Client) CreateUserNotification(ctx context.Context, input *types.UserNotificationCreationRequestInput) (*types.UserNotification, error) {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	logger := c.logger.Clone()

	if input == nil {
		return nil, ErrNilInputProvided
	}

	if err := input.ValidateWithContext(ctx); err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "validating input")
	}

	req, err := c.requestBuilder.BuildCreateUserNotificationRequest(ctx, input)
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "building create user notification request")
	}

	var apiResponse *types.APIResponse[*types.UserNotification]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "retrieving user notification")
	}

	return apiResponse.Data, nil
}

// UpdateUserNotification updates a user notification.
func (c *Client) UpdateUserNotification(ctx context.Context, userNotification *types.UserNotification) error {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	logger := c.logger.Clone()

	if userNotification == nil {
		return ErrNilInputProvided
	}
	logger = logger.WithValue(keys.UserNotificationIDKey, userNotification.ID)
	tracing.AttachToSpan(span, keys.UserNotificationIDKey, userNotification.ID)

	req, err := c.requestBuilder.BuildUpdateUserNotificationRequest(ctx, userNotification)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "building update user notification request")
	}

	var apiResponse *types.APIResponse[*types.UserNotification]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "retrieving user notification")
	}

	return nil
}
