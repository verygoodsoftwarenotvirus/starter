package requests

import (
	"context"
	"net/http"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

const (
	invitationsBasePath        = "invitations"
	accountInvitationsBasePath = "account_invitations"
)

// BuildGetAccountInvitationRequest builds an HTTP request for fetching a account invitation.
func (b *Builder) BuildGetAccountInvitationRequest(ctx context.Context, accountID, invitationID string) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	if accountID == "" || invitationID == "" {
		return nil, ErrInvalidIDProvided
	}

	tracing.AttachToSpan(span, keys.AccountInvitationIDKey, invitationID)

	uri := b.BuildURL(
		ctx,
		nil,
		accountsBasePath,
		accountID,
		invitationsBasePath,
		invitationID,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, http.NoBody)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building request")
	}

	return req, nil
}

// BuildGetPendingAccountInvitationsFromUserRequest builds an HTTP request that retrieves pending account invitations sent by a user.
func (b *Builder) BuildGetPendingAccountInvitationsFromUserRequest(ctx context.Context, filter *types.QueryFilter) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	uri := b.BuildURL(ctx, filter.ToValues(), accountInvitationsBasePath, "sent")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, http.NoBody)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building request")
	}

	return req, nil
}

// BuildGetPendingAccountInvitationsForUserRequest builds an HTTP request that retrieves pending account invitations received by a user.
func (b *Builder) BuildGetPendingAccountInvitationsForUserRequest(ctx context.Context, filter *types.QueryFilter) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	uri := b.BuildURL(ctx, filter.ToValues(), accountInvitationsBasePath, "received")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, http.NoBody)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building request")
	}

	return req, nil
}

// BuildAcceptAccountInvitationRequest builds an HTTP request that accepts a given account invitation.
func (b *Builder) BuildAcceptAccountInvitationRequest(ctx context.Context, invitationID, token, note string) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	uri := b.BuildURL(
		ctx,
		nil,
		accountInvitationsBasePath,
		invitationID,
		"accept",
	)

	input := &types.AccountInvitationUpdateRequestInput{
		Token: token,
		Note:  note,
	}
	req, err := b.buildDataRequest(ctx, http.MethodPut, uri, input)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building request")
	}

	return req, nil
}

// BuildCancelAccountInvitationRequest builds an HTTP request that cancels a given account invitation.
func (b *Builder) BuildCancelAccountInvitationRequest(ctx context.Context, invitationID, token, note string) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	uri := b.BuildURL(
		ctx,
		nil,
		accountInvitationsBasePath,
		invitationID,
		"cancel",
	)

	input := &types.AccountInvitationUpdateRequestInput{
		Token: token,
		Note:  note,
	}
	req, err := b.buildDataRequest(ctx, http.MethodPut, uri, input)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building request")
	}

	return req, nil
}

// BuildRejectAccountInvitationRequest builds an HTTP request that rejects a given account invitation.
func (b *Builder) BuildRejectAccountInvitationRequest(ctx context.Context, invitationID, token, note string) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	uri := b.BuildURL(
		ctx,
		nil,
		accountInvitationsBasePath,
		invitationID,
		"reject",
	)

	input := &types.AccountInvitationUpdateRequestInput{
		Token: token,
		Note:  note,
	}
	req, err := b.buildDataRequest(ctx, http.MethodPut, uri, input)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building request")
	}

	return req, nil
}
