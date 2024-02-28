package apiclient

import (
	"context"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

// GetOAuth2Client gets an OAuth2 client.
func (c *Client) GetOAuth2Client(ctx context.Context, oauth2ClientDatabaseID string) (*types.OAuth2Client, error) {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	if oauth2ClientDatabaseID == "" {
		return nil, ErrInvalidIDProvided
	}

	req, err := c.requestBuilder.BuildGetOAuth2ClientRequest(ctx, oauth2ClientDatabaseID)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building retrieve OAuth2 client request")
	}

	var apiResponse *types.APIResponse[*types.OAuth2Client]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return nil, observability.PrepareError(err, span, "fetching oauth2 client")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return nil, err
	}

	return apiResponse.Data, nil
}

// GetOAuth2Clients gets a list of OAuth2 clients.
func (c *Client) GetOAuth2Clients(ctx context.Context, filter *types.QueryFilter) (*types.QueryFilteredResult[types.OAuth2Client], error) {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	tracing.AttachQueryFilterToSpan(span, filter)

	req, err := c.requestBuilder.BuildGetOAuth2ClientsRequest(ctx, filter)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building OAuth2 clients list request")
	}

	var apiResponse *types.APIResponse[[]*types.OAuth2Client]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return nil, observability.PrepareError(err, span, "fetching api clients")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return nil, err
	}

	response := &types.QueryFilteredResult[types.OAuth2Client]{
		Data:       apiResponse.Data,
		Pagination: *apiResponse.Pagination,
	}

	return response, nil
}

// CreateOAuth2Client creates an OAuth2 client.
func (c *Client) CreateOAuth2Client(ctx context.Context, input *types.OAuth2ClientCreationRequestInput) (*types.OAuth2ClientCreationResponse, error) {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	if c.authMethod != cookieAuthMethod {
		return nil, ErrCookieRequired
	}

	if input == nil {
		return nil, ErrNilInputProvided
	}

	req, err := c.requestBuilder.BuildCreateOAuth2ClientRequest(ctx, input)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building create OAuth2 client request")
	}

	var apiResponse *types.APIResponse[*types.OAuth2ClientCreationResponse]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return nil, observability.PrepareError(err, span, "creating oauth2 client")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return nil, err
	}

	return apiResponse.Data, nil
}

// ArchiveOAuth2Client archives an OAuth2 client.
func (c *Client) ArchiveOAuth2Client(ctx context.Context, oauth2ClientDatabaseID string) error {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	if oauth2ClientDatabaseID == "" {
		return ErrInvalidIDProvided
	}

	req, err := c.requestBuilder.BuildArchiveOAuth2ClientRequest(ctx, oauth2ClientDatabaseID)
	if err != nil {
		return observability.PrepareError(err, span, "building archive OAuth2 client request")
	}

	var apiResponse *types.APIResponse[*types.OAuth2Client]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return observability.PrepareError(err, span, "archiving oauth2 client")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return err
	}

	return nil
}
