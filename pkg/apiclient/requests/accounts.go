package requests

import (
	"context"
	"fmt"
	"net/http"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/converters"
)

const (
	accountsBasePath = "accounts"
)

// BuildSwitchActiveAccountRequest builds an HTTP request for switching active accounts.
func (b *Builder) BuildSwitchActiveAccountRequest(ctx context.Context, accountID string) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	if accountID == "" {
		return nil, ErrInvalidIDProvided
	}

	tracing.AttachToSpan(span, keys.AccountIDKey, accountID)

	uri := b.buildAPIV1URL(ctx, nil, usersBasePath, "account", "select").String()

	input := &types.ChangeActiveAccountInput{
		AccountID: accountID,
	}

	return b.buildDataRequest(ctx, http.MethodPost, uri, input)
}

// BuildGetCurrentAccountRequest builds an HTTP request for fetching a account.
func (b *Builder) BuildGetCurrentAccountRequest(ctx context.Context) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	uri := b.BuildURL(
		ctx,
		nil,
		accountsBasePath,
		"current",
	)
	tracing.AttachToSpan(span, keys.RequestURIKey, uri)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, http.NoBody)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building request")
	}

	return req, nil
}

// BuildGetAccountRequest builds an HTTP request for fetching a account.
func (b *Builder) BuildGetAccountRequest(ctx context.Context, accountID string) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	if accountID == "" {
		return nil, ErrInvalidIDProvided
	}

	tracing.AttachToSpan(span, keys.AccountIDKey, accountID)

	uri := b.BuildURL(
		ctx,
		nil,
		accountsBasePath,
		accountID,
	)
	tracing.AttachToSpan(span, keys.RequestURIKey, uri)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, http.NoBody)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building request")
	}

	return req, nil
}

// BuildGetAccountsRequest builds an HTTP request for fetching a list of accounts.
func (b *Builder) BuildGetAccountsRequest(ctx context.Context, filter *types.QueryFilter) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	uri := b.BuildURL(ctx, filter.ToValues(), accountsBasePath)

	tracing.AttachToSpan(span, keys.RequestURIKey, uri)
	tracing.AttachQueryFilterToSpan(span, filter)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, http.NoBody)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building request")
	}

	return req, nil
}

// BuildCreateAccountRequest builds an HTTP request for creating a account.
func (b *Builder) BuildCreateAccountRequest(ctx context.Context, input *types.AccountCreationRequestInput) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	if input == nil {
		return nil, ErrNilInputProvided
	}

	if err := input.ValidateWithContext(ctx); err != nil {
		return nil, observability.PrepareError(err, span, "validating input")
	}

	uri := b.BuildURL(ctx, nil, accountsBasePath)
	tracing.AttachToSpan(span, keys.RequestURIKey, uri)

	return b.buildDataRequest(ctx, http.MethodPost, uri, input)
}

// BuildUpdateAccountRequest builds an HTTP request for updating a account.
func (b *Builder) BuildUpdateAccountRequest(ctx context.Context, account *types.Account) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	if account == nil {
		return nil, ErrNilInputProvided
	}

	uri := b.BuildURL(
		ctx,
		nil,
		accountsBasePath,
		account.ID,
	)
	tracing.AttachToSpan(span, keys.RequestURIKey, uri)

	input := converters.ConvertAccountToAccountUpdateRequestInput(account)

	return b.buildDataRequest(ctx, http.MethodPut, uri, input)
}

// BuildArchiveAccountRequest builds an HTTP request for archiving a account.
func (b *Builder) BuildArchiveAccountRequest(ctx context.Context, accountID string) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	if accountID == "" {
		return nil, ErrInvalidIDProvided
	}

	uri := b.BuildURL(
		ctx,
		nil,
		accountsBasePath,
		accountID,
	)
	tracing.AttachToSpan(span, keys.RequestURIKey, uri)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, uri, http.NoBody)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building request")
	}

	return req, nil
}

// BuildInviteUserToAccountRequest builds a request that adds a user to a account.
func (b *Builder) BuildInviteUserToAccountRequest(ctx context.Context, destinationAccountID string, input *types.AccountInvitationCreationRequestInput) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	if destinationAccountID == "" {
		return nil, ErrInvalidIDProvided
	}

	if input == nil {
		return nil, ErrNilInputProvided
	}

	// we don't validate here because it needs to have the user ID

	uri := b.BuildURL(ctx, nil, accountsBasePath, destinationAccountID, "invite")
	tracing.AttachToSpan(span, keys.RequestURIKey, uri)

	return b.buildDataRequest(ctx, http.MethodPost, uri, input)
}

// BuildMarkAsDefaultRequest builds a request that marks a given account as the default for a given user.
func (b *Builder) BuildMarkAsDefaultRequest(ctx context.Context, accountID string) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	if accountID == "" {
		return nil, ErrInvalidIDProvided
	}

	uri := b.BuildURL(ctx, nil, accountsBasePath, accountID, "default")
	tracing.AttachToSpan(span, keys.RequestURIKey, uri)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, http.NoBody)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building request")
	}

	return req, nil
}

// BuildRemoveUserRequest builds a request that removes a user from a account.
func (b *Builder) BuildRemoveUserRequest(ctx context.Context, accountID, userID, reason string) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	if accountID == "" || userID == "" {
		return nil, ErrInvalidIDProvided
	}

	u := b.buildAPIV1URL(ctx, nil, accountsBasePath, accountID, "members", userID)

	if reason != "" {
		q := u.Query()
		q.Set("reason", reason)
		u.RawQuery = q.Encode()
	}

	tracing.AttachToSpan(span, keys.RequestURIKey, u.String())

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u.String(), http.NoBody)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building request")
	}

	return req, nil
}

// BuildModifyMemberPermissionsRequest builds a request that modifies a given user's permissions for a given account.
func (b *Builder) BuildModifyMemberPermissionsRequest(ctx context.Context, accountID, userID string, input *types.ModifyUserPermissionsInput) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	if accountID == "" || userID == "" {
		return nil, ErrInvalidIDProvided
	}

	if input == nil {
		return nil, ErrNilInputProvided
	}

	if err := input.ValidateWithContext(ctx); err != nil {
		return nil, observability.PrepareError(err, span, "validating input")
	}

	uri := b.BuildURL(ctx, nil, accountsBasePath, accountID, "members", userID, "permissions")
	tracing.AttachToSpan(span, keys.RequestURIKey, uri)

	return b.buildDataRequest(ctx, http.MethodPatch, uri, input)
}

// BuildTransferAccountOwnershipRequest builds a request that transfers ownership of a account to a given user.
func (b *Builder) BuildTransferAccountOwnershipRequest(ctx context.Context, accountID string, input *types.AccountOwnershipTransferInput) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	if accountID == "" {
		return nil, fmt.Errorf("accountID: %w", ErrInvalidIDProvided)
	}

	if input == nil {
		return nil, ErrNilInputProvided
	}

	if err := input.ValidateWithContext(ctx); err != nil {
		return nil, observability.PrepareError(err, span, "validating input")
	}

	uri := b.BuildURL(ctx, nil, accountsBasePath, accountID, "transfer")
	tracing.AttachToSpan(span, keys.RequestURIKey, uri)

	return b.buildDataRequest(ctx, http.MethodPost, uri, input)
}
