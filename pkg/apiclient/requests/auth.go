package requests

import (
	"context"
	"net/http"
	"strconv"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

const (
	authBasePath = "auth"
)

// BuildUserStatusRequest builds an HTTP request that fetches a user's status.
func (b *Builder) BuildUserStatusRequest(ctx context.Context) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	uri := b.buildUnversionedURL(ctx, nil, authBasePath, "status")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, http.NoBody)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building request")
	}

	return req, nil
}

// BuildLoginRequest builds an HTTP request that fetches a login cookie.
func (b *Builder) BuildLoginRequest(ctx context.Context, input *types.UserLoginInput) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	if input == nil {
		return nil, ErrNilInputProvided
	}

	tracing.AttachToSpan(span, keys.UsernameKey, input.Username)

	// validating here requires settings knowledge, so we do not do it

	uri := b.buildUnversionedURL(ctx, nil, usersBasePath, "login")

	return b.buildDataRequest(ctx, http.MethodPost, uri, input)
}

// BuildLogoutRequest builds an HTTP request that clears the user's session.
func (b *Builder) BuildLogoutRequest(ctx context.Context) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	uri := b.buildUnversionedURL(ctx, nil, usersBasePath, "logout")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, http.NoBody)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building request")
	}

	return req, nil
}

// BuildChangePasswordRequest builds a request to change a user's password.
func (b *Builder) BuildChangePasswordRequest(ctx context.Context, cookie *http.Cookie, input *types.PasswordUpdateInput) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	if input == nil {
		return nil, ErrNilInputProvided
	}

	// validating here requires settings knowledge, so we do not do it.

	uri := b.buildAPIV1URL(ctx, nil, usersBasePath, "password", "new").String()

	req, err := b.buildDataRequest(ctx, http.MethodPut, uri, input)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building request")
	}

	req.AddCookie(cookie)

	return req, nil
}

// BuildCycleTwoFactorSecretRequest builds a request to change a user's 2FA secret.
func (b *Builder) BuildCycleTwoFactorSecretRequest(ctx context.Context, cookie *http.Cookie, input *types.TOTPSecretRefreshInput) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	if cookie == nil {
		return nil, ErrCookieRequired
	}

	if input == nil {
		return nil, ErrNilInputProvided
	}

	if err := input.ValidateWithContext(ctx); err != nil {
		return nil, observability.PrepareError(err, span, "validating input")
	}

	uri := b.buildAPIV1URL(ctx, nil, usersBasePath, "totp_secret", "new").String()

	req, err := b.buildDataRequest(ctx, http.MethodPost, uri, input)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building request")
	}

	req.AddCookie(cookie)

	return req, nil
}

// BuildVerifyTOTPSecretRequest builds a request to validate a 2FA secret.
func (b *Builder) BuildVerifyTOTPSecretRequest(ctx context.Context, userID, token string) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	if userID == "" {
		return nil, ErrInvalidIDProvided
	}

	if _, err := strconv.ParseUint(token, 10, 64); token == "" || err != nil {
		return nil, observability.PrepareError(err, span, "invalid token provided")
	}

	uri := b.buildUnversionedURL(ctx, nil, usersBasePath, "totp_secret", "verify")

	return b.buildDataRequest(ctx, http.MethodPost, uri, &types.TOTPSecretVerificationInput{
		TOTPToken: token,
		UserID:    userID,
	})
}

// BuildPasswordResetTokenRequest builds a request for requesting a password reset token.
func (b *Builder) BuildPasswordResetTokenRequest(ctx context.Context, emailAddress string) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	if emailAddress == "" {
		return nil, ErrEmptyEmailAddressProvided
	}

	uri := b.buildUnversionedURL(ctx, nil, usersBasePath, "password", "reset")

	return b.buildDataRequest(ctx, http.MethodPost, uri, &types.PasswordResetTokenCreationRequestInput{EmailAddress: emailAddress})
}

// BuildPasswordResetTokenRedemptionRequest builds a request for redeeming a password reset token.
func (b *Builder) BuildPasswordResetTokenRedemptionRequest(ctx context.Context, input *types.PasswordResetTokenRedemptionRequestInput) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	if input == nil {
		return nil, ErrNilInputProvided
	}

	uri := b.buildUnversionedURL(ctx, nil, usersBasePath, "password", "reset", "redeem")

	return b.buildDataRequest(ctx, http.MethodPost, uri, input)
}
