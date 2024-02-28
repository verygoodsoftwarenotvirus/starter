package requests

import (
	"context"
	"net/http"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/converters"
)

const (
	userNotificationsBasePath = "user_notifications"
)

// BuildGetUserNotificationRequest builds an HTTP request for fetching a user notification.
func (b *Builder) BuildGetUserNotificationRequest(ctx context.Context, userNotificationID string) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	if userNotificationID == "" {
		return nil, ErrInvalidIDProvided
	}
	tracing.AttachToSpan(span, keys.UserNotificationIDKey, userNotificationID)

	uri := b.BuildURL(
		ctx,
		nil,
		userNotificationsBasePath,
		userNotificationID,
	)
	tracing.AttachToSpan(span, keys.RequestURIKey, uri)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, http.NoBody)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building request")
	}

	return req, nil
}

// BuildGetUserNotificationsRequest builds an HTTP request for fetching a list of user notifications.
func (b *Builder) BuildGetUserNotificationsRequest(ctx context.Context, filter *types.QueryFilter) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	uri := b.BuildURL(
		ctx,
		filter.ToValues(),
		userNotificationsBasePath,
	)
	tracing.AttachToSpan(span, keys.RequestURIKey, uri)
	tracing.AttachQueryFilterToSpan(span, filter)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, http.NoBody)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building request")
	}

	return req, nil
}

// BuildCreateUserNotificationRequest builds an HTTP request for creating a user notification.
func (b *Builder) BuildCreateUserNotificationRequest(ctx context.Context, input *types.UserNotificationCreationRequestInput) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	if input == nil {
		return nil, ErrNilInputProvided
	}

	if err := input.ValidateWithContext(ctx); err != nil {
		return nil, observability.PrepareError(err, span, "validating input")
	}

	uri := b.BuildURL(
		ctx,
		nil,
		userNotificationsBasePath,
	)
	tracing.AttachToSpan(span, keys.RequestURIKey, uri)

	req, err := b.buildDataRequest(ctx, http.MethodPost, uri, input)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building request")
	}

	return req, nil
}

// BuildUpdateUserNotificationRequest builds an HTTP request for updating a user notification.
func (b *Builder) BuildUpdateUserNotificationRequest(ctx context.Context, userNotification *types.UserNotification) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	if userNotification == nil {
		return nil, ErrNilInputProvided
	}
	tracing.AttachToSpan(span, keys.UserNotificationIDKey, userNotification.ID)

	uri := b.BuildURL(
		ctx,
		nil,
		userNotificationsBasePath,
		userNotification.ID,
	)
	tracing.AttachToSpan(span, keys.RequestURIKey, uri)

	input := converters.ConvertUserNotificationToUserNotificationUpdateRequestInput(userNotification)

	req, err := b.buildDataRequest(ctx, http.MethodPatch, uri, input)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building request")
	}

	return req, nil
}
