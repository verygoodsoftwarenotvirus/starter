package apiclient

import (
	"context"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

// GetSelf retrieves a user.
func (c *Client) GetSelf(ctx context.Context) (*types.User, error) {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	req, err := c.requestBuilder.BuildGetSelfRequest(ctx)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building get self request")
	}

	var apiResponse *types.APIResponse[*types.User]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return nil, observability.PrepareError(err, span, "fetching self")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return nil, err
	}

	return apiResponse.Data, nil
}

// GetUser retrieves a user.
func (c *Client) GetUser(ctx context.Context, userID string) (*types.User, error) {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	if userID == "" {
		return nil, ErrInvalidIDProvided
	}

	req, err := c.requestBuilder.BuildGetUserRequest(ctx, userID)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building get user request")
	}

	var apiResponse *types.APIResponse[*types.User]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return nil, observability.PrepareError(err, span, "fetching user")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return nil, err
	}

	return apiResponse.Data, nil
}

// GetUsers retrieves a list of users.
func (c *Client) GetUsers(ctx context.Context, filter *types.QueryFilter) (*types.QueryFilteredResult[types.User], error) {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	tracing.AttachQueryFilterToSpan(span, filter)

	req, err := c.requestBuilder.BuildGetUsersRequest(ctx, filter)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building users list request")
	}

	var apiResponse *types.APIResponse[[]*types.User]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return nil, observability.PrepareError(err, span, "retrieving users")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return nil, err
	}

	response := &types.QueryFilteredResult[types.User]{
		Data:       apiResponse.Data,
		Pagination: *apiResponse.Pagination,
	}

	return response, nil
}

// SearchForUsersByUsername searches for a user from a list of users by their username.
func (c *Client) SearchForUsersByUsername(ctx context.Context, username string) ([]*types.User, error) {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	if username == "" {
		return nil, ErrEmptyUsernameProvided
	}

	req, err := c.requestBuilder.BuildSearchForUsersByUsernameRequest(ctx, username)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building username search request")
	}

	var apiResponse *types.APIResponse[[]*types.User]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return nil, observability.PrepareError(err, span, "searching for users")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return nil, err
	}

	return apiResponse.Data, nil
}

// CreateUser creates a new user.
func (c *Client) CreateUser(ctx context.Context, input *types.UserRegistrationInput) (*types.UserCreationResponse, error) {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	if input == nil {
		return nil, ErrNilInputProvided
	}

	// deliberately not validating here
	// maybe I should make a client-side validate method vs a server-side?

	req, err := c.requestBuilder.BuildCreateUserRequest(ctx, input)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building create user request")
	}

	var apiResponse *types.APIResponse[*types.UserCreationResponse]
	if err = c.fetchAndUnmarshalWithoutAuthentication(ctx, req, &apiResponse); err != nil {
		return nil, observability.PrepareError(err, span, "creating user")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return nil, err
	}

	return apiResponse.Data, nil
}

// ArchiveUser archives a user.
func (c *Client) ArchiveUser(ctx context.Context, userID string) error {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	if userID == "" {
		return ErrInvalidIDProvided
	}

	req, err := c.requestBuilder.BuildArchiveUserRequest(ctx, userID)
	if err != nil {
		return observability.PrepareError(err, span, "building archive user request")
	}

	var apiResponse *types.APIResponse[*types.User]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return observability.PrepareError(err, span, "archiving user")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return err
	}

	return nil
}

// UploadNewAvatar uploads a new avatar.
func (c *Client) UploadNewAvatar(ctx context.Context, input *types.AvatarUpdateInput) error {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	if input == nil {
		return ErrNilInputProvided
	}

	req, err := c.requestBuilder.BuildAvatarUploadRequest(ctx, input)
	if err != nil {
		return observability.PrepareError(err, span, "building avatar upload request")
	}

	var apiResponse *types.APIResponse[*types.User]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return observability.PrepareError(err, span, "uploading avatar")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return err
	}

	return nil
}

// CheckUserPermissions checks if a user has certain permissions.
func (c *Client) CheckUserPermissions(ctx context.Context, permissions ...string) (*types.UserPermissionsResponse, error) {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	if permissions == nil {
		return nil, ErrNilInputProvided
	}

	req, err := c.requestBuilder.BuildCheckUserPermissionsRequests(ctx, permissions...)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building permission check request")
	}

	var apiResponse *types.APIResponse[*types.UserPermissionsResponse]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return nil, observability.PrepareError(err, span, "checking permission")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return nil, err
	}

	return apiResponse.Data, nil
}

// UpdateUserEmailAddress updates a user's email address.
func (c *Client) UpdateUserEmailAddress(ctx context.Context, input *types.UserEmailAddressUpdateInput) error {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	if input == nil {
		return ErrNilInputProvided
	}

	req, err := c.requestBuilder.BuildUpdateUserEmailAddressRequest(ctx, input)
	if err != nil {
		return observability.PrepareError(err, span, "building archive user request")
	}

	var apiResponse *types.APIResponse[*types.User]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return observability.PrepareError(err, span, "archiving user")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return err
	}

	return nil
}

// UpdateUserUsername updates a user's username.
func (c *Client) UpdateUserUsername(ctx context.Context, input *types.UsernameUpdateInput) error {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	if input == nil {
		return ErrNilInputProvided
	}

	req, err := c.requestBuilder.BuildUpdateUserUsernameRequest(ctx, input)
	if err != nil {
		return observability.PrepareError(err, span, "building archive user request")
	}

	var apiResponse *types.APIResponse[*types.User]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return observability.PrepareError(err, span, "archiving user")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return err
	}

	return nil
}

// UpdateUserDetails updates a user's details.
func (c *Client) UpdateUserDetails(ctx context.Context, input *types.UserDetailsUpdateRequestInput) error {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	if input == nil {
		return ErrNilInputProvided
	}

	req, err := c.requestBuilder.BuildUpdateUserDetailsRequest(ctx, input)
	if err != nil {
		return observability.PrepareError(err, span, "building archive user request")
	}

	var apiResponse *types.APIResponse[*types.User]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return observability.PrepareError(err, span, "archiving user")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return err
	}

	return nil
}
