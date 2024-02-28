package apiclient

import (
	"context"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

// SwitchActiveAccount will switch the account on whose behalf requests are made.
func (c *Client) SwitchActiveAccount(ctx context.Context, accountID string) error {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	if accountID == "" {
		return ErrInvalidIDProvided
	}

	tracing.AttachToSpan(span, keys.AccountIDKey, accountID)

	if c.authMethod == cookieAuthMethod {
		req, err := c.requestBuilder.BuildSwitchActiveAccountRequest(ctx, accountID)
		if err != nil {
			return observability.PrepareError(err, span, "building account switch request")
		}

		var apiResponse *types.APIResponse[*types.Account]
		if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
			return observability.PrepareError(err, span, "executing account switch request")
		}

		if err = apiResponse.Error.AsError(); err != nil {
			return err
		}
	}

	c.accountID = accountID

	return nil
}

// GetCurrentAccount retrieves a account.
func (c *Client) GetCurrentAccount(ctx context.Context) (*types.Account, error) {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	req, err := c.requestBuilder.BuildGetCurrentAccountRequest(ctx)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building account retrieval request")
	}

	var apiResponse *types.APIResponse[*types.Account]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return nil, observability.PrepareError(err, span, "retrieving account")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return nil, err
	}

	return apiResponse.Data, nil
}

// GetAccount retrieves a account.
func (c *Client) GetAccount(ctx context.Context, accountID string) (*types.Account, error) {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	if accountID == "" {
		return nil, ErrInvalidIDProvided
	}

	tracing.AttachToSpan(span, keys.AccountIDKey, accountID)

	req, err := c.requestBuilder.BuildGetAccountRequest(ctx, accountID)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building account retrieval request")
	}

	var apiResponse *types.APIResponse[*types.Account]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return nil, observability.PrepareError(err, span, "retrieving account")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return nil, err
	}

	return apiResponse.Data, nil
}

// GetAccounts retrieves a list of accounts.
func (c *Client) GetAccounts(ctx context.Context, filter *types.QueryFilter) (*types.QueryFilteredResult[types.Account], error) {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	tracing.AttachQueryFilterToSpan(span, filter)

	req, err := c.requestBuilder.BuildGetAccountsRequest(ctx, filter)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building account list request")
	}

	var apiResponse *types.APIResponse[[]*types.Account]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return nil, observability.PrepareError(err, span, "retrieving accounts")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return nil, err
	}

	result := &types.QueryFilteredResult[types.Account]{
		Data:       apiResponse.Data,
		Pagination: *apiResponse.Pagination,
	}

	return result, nil
}

// CreateAccount creates a account.
func (c *Client) CreateAccount(ctx context.Context, input *types.AccountCreationRequestInput) (*types.Account, error) {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	if input == nil {
		return nil, ErrNilInputProvided
	}

	if err := input.ValidateWithContext(ctx); err != nil {
		return nil, observability.PrepareError(err, span, "validating input")
	}

	req, err := c.requestBuilder.BuildCreateAccountRequest(ctx, input)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building account creation request")
	}

	var apiResponse *types.APIResponse[*types.Account]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return nil, observability.PrepareError(err, span, "creating account")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return nil, err
	}

	return apiResponse.Data, nil
}

// UpdateAccount updates a account.
func (c *Client) UpdateAccount(ctx context.Context, account *types.Account) error {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	if account == nil {
		return ErrNilInputProvided
	}

	tracing.AttachToSpan(span, keys.AccountIDKey, account.ID)

	req, err := c.requestBuilder.BuildUpdateAccountRequest(ctx, account)
	if err != nil {
		return observability.PrepareError(err, span, "building account update request")
	}

	var apiResponse *types.APIResponse[*types.Account]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return observability.PrepareError(err, span, "updating account")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return err
	}

	return nil
}

// ArchiveAccount archives a account.
func (c *Client) ArchiveAccount(ctx context.Context, accountID string) error {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	if accountID == "" {
		return ErrInvalidIDProvided
	}

	tracing.AttachToSpan(span, keys.AccountIDKey, accountID)

	req, err := c.requestBuilder.BuildArchiveAccountRequest(ctx, accountID)
	if err != nil {
		return observability.PrepareError(err, span, "building account archive request")
	}

	var apiResponse *types.APIResponse[*types.Account]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return observability.PrepareError(err, span, "archiving account")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return err
	}

	return nil
}

// InviteUserToAccount adds a user to a account.
func (c *Client) InviteUserToAccount(ctx context.Context, destinationAccountID string, input *types.AccountInvitationCreationRequestInput) (*types.AccountInvitation, error) {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	if input == nil {
		return nil, ErrNilInputProvided
	}

	tracing.AttachToSpan(span, keys.AccountIDKey, destinationAccountID)

	// we don't validate here because it needs to have the user ID

	req, err := c.requestBuilder.BuildInviteUserToAccountRequest(ctx, destinationAccountID, input)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building add user to account request")
	}

	var apiResponse *types.APIResponse[*types.AccountInvitation]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return nil, observability.PrepareError(err, span, "adding user to account")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return nil, err
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return nil, err
	}

	return apiResponse.Data, nil
}

// MarkAsDefault marks a given account as the default for a given user.
func (c *Client) MarkAsDefault(ctx context.Context, accountID string) error {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	if accountID == "" {
		return ErrInvalidIDProvided
	}

	tracing.AttachToSpan(span, keys.AccountIDKey, accountID)

	req, err := c.requestBuilder.BuildMarkAsDefaultRequest(ctx, accountID)
	if err != nil {
		return observability.PrepareError(err, span, "building mark account as default request")
	}

	var apiResponse *types.APIResponse[*types.Account]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return observability.PrepareError(err, span, "marking account as default")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return err
	}

	return nil
}

// RemoveUserFromAccount removes a user from a account.
func (c *Client) RemoveUserFromAccount(ctx context.Context, accountID, userID string) error {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	if accountID == "" {
		return ErrInvalidIDProvided
	}

	if userID == "" {
		return ErrInvalidIDProvided
	}

	tracing.AttachToSpan(span, keys.AccountIDKey, accountID)
	tracing.AttachToSpan(span, keys.UserIDKey, userID)

	req, err := c.requestBuilder.BuildRemoveUserRequest(ctx, accountID, userID, "")
	if err != nil {
		return observability.PrepareError(err, span, "building remove user from account request")
	}

	var apiResponse *types.APIResponse[*types.Account]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return observability.PrepareError(err, span, "removing user from account")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return err
	}

	return nil
}

// ModifyMemberPermissions modifies a given user's permissions for a given account.
func (c *Client) ModifyMemberPermissions(ctx context.Context, accountID, userID string, input *types.ModifyUserPermissionsInput) error {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	if accountID == "" {
		return ErrInvalidIDProvided
	}

	if userID == "" {
		return ErrInvalidIDProvided
	}

	if input == nil {
		return ErrNilInputProvided
	}

	tracing.AttachToSpan(span, keys.AccountIDKey, accountID)
	tracing.AttachToSpan(span, keys.UserIDKey, userID)

	if err := input.ValidateWithContext(ctx); err != nil {
		return observability.PrepareError(err, span, "validating input")
	}

	req, err := c.requestBuilder.BuildModifyMemberPermissionsRequest(ctx, accountID, userID, input)
	if err != nil {
		return observability.PrepareError(err, span, "building modify account member permissions request")
	}

	var apiResponse *types.APIResponse[*types.Account]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return observability.PrepareError(err, span, "modifying user account permissions")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return err
	}

	return nil
}

// TransferAccountOwnership transfers ownership of a account to a given user.
func (c *Client) TransferAccountOwnership(ctx context.Context, accountID string, input *types.AccountOwnershipTransferInput) error {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	if accountID == "" {
		return ErrInvalidIDProvided
	}

	if input == nil {
		return ErrNilInputProvided
	}

	tracing.AttachToSpan(span, "old_owner", input.CurrentOwner)
	tracing.AttachToSpan(span, "new_owner", input.NewOwner)

	if err := input.ValidateWithContext(ctx); err != nil {
		return observability.PrepareError(err, span, "validating input")
	}

	req, err := c.requestBuilder.BuildTransferAccountOwnershipRequest(ctx, accountID, input)
	if err != nil {
		return observability.PrepareError(err, span, "building transfer account ownership request")
	}

	var apiResponse *types.APIResponse[*types.Account]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return observability.PrepareError(err, span, "transferring account to user")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return err
	}

	return nil
}
