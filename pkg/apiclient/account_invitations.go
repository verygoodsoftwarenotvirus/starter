package apiclient

import (
	"context"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

// GetAccountInvitation retrieves a account invitation.
func (c *Client) GetAccountInvitation(ctx context.Context, accountID, accountInvitationID string) (*types.AccountInvitation, error) {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	logger := c.logger.Clone()

	if accountID == "" {
		return nil, ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.AccountIDKey, accountID)

	if accountInvitationID == "" {
		return nil, ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.AccountInvitationIDKey, accountInvitationID)

	req, err := c.requestBuilder.BuildGetAccountInvitationRequest(ctx, accountID, accountInvitationID)
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "building get invitation request")
	}

	var apiResponse *types.APIResponse[*types.AccountInvitation]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "retrieving invitation")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return nil, err
	}

	return apiResponse.Data, nil
}

// GetPendingAccountInvitationsFromUser retrieves account invitations sent by the user.
func (c *Client) GetPendingAccountInvitationsFromUser(ctx context.Context, filter *types.QueryFilter) (*types.QueryFilteredResult[types.AccountInvitation], error) {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	logger := c.logger.Clone()
	filter.AttachToLogger(logger)

	req, err := c.requestBuilder.BuildGetPendingAccountInvitationsFromUserRequest(ctx, filter)
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "building reject invitation request")
	}

	var apiResponse *types.APIResponse[[]*types.AccountInvitation]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "rejecting invitation")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return nil, err
	}

	response := &types.QueryFilteredResult[types.AccountInvitation]{
		Data:       apiResponse.Data,
		Pagination: *apiResponse.Pagination,
	}

	return response, nil
}

// GetPendingAccountInvitationsForUser retrieves account invitations received by the user.
func (c *Client) GetPendingAccountInvitationsForUser(ctx context.Context, filter *types.QueryFilter) (*types.QueryFilteredResult[types.AccountInvitation], error) {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	logger := c.logger.Clone()
	filter.AttachToLogger(logger)

	req, err := c.requestBuilder.BuildGetPendingAccountInvitationsForUserRequest(ctx, filter)
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "building reject invitation request")
	}

	var apiResponse *types.APIResponse[[]*types.AccountInvitation]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "rejecting invitation")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return nil, err
	}

	response := &types.QueryFilteredResult[types.AccountInvitation]{
		Data:       apiResponse.Data,
		Pagination: *apiResponse.Pagination,
	}

	return response, nil
}

// AcceptAccountInvitation accepts a given account invitation.
func (c *Client) AcceptAccountInvitation(ctx context.Context, accountInvitationID, token, note string) error {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	logger := c.logger.Clone()

	if accountInvitationID == "" {
		return ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.AccountInvitationIDKey, accountInvitationID)

	if token == "" {
		return ErrInvalidIDProvided
	}

	req, err := c.requestBuilder.BuildAcceptAccountInvitationRequest(ctx, accountInvitationID, token, note)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "building reject invitation request")
	}

	var apiResponse *types.APIResponse[*types.AccountInvitation]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "rejecting invitation")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return err
	}

	return nil
}

// CancelAccountInvitation cancels a given account invitation.
func (c *Client) CancelAccountInvitation(ctx context.Context, accountInvitationID, token, note string) error {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	logger := c.logger.Clone()

	if accountInvitationID == "" {
		return ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.AccountInvitationIDKey, accountInvitationID)

	if token == "" {
		return ErrInvalidIDProvided
	}

	req, err := c.requestBuilder.BuildCancelAccountInvitationRequest(ctx, accountInvitationID, token, note)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "building reject invitation request")
	}

	var apiResponse *types.APIResponse[*types.AccountInvitation]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "rejecting invitation")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return err
	}

	return nil
}

// RejectAccountInvitation rejects a given account invitation.
func (c *Client) RejectAccountInvitation(ctx context.Context, accountInvitationID, token, note string) error {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	logger := c.logger.Clone()

	if accountInvitationID == "" {
		return ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.AccountInvitationIDKey, accountInvitationID)

	if token == "" {
		return ErrInvalidIDProvided
	}

	req, err := c.requestBuilder.BuildRejectAccountInvitationRequest(ctx, accountInvitationID, token, note)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "building reject invitation request")
	}

	var apiResponse *types.APIResponse[*types.AccountInvitation]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "rejecting invitation")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return err
	}

	return nil
}
