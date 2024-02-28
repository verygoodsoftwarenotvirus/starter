package apiclient

import (
	"context"
	"net/http"
	"strconv"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

// UserStatus fetches a user's status.
func (c *Client) UserStatus(ctx context.Context) (*types.UserStatusResponse, error) {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	req, err := c.requestBuilder.BuildUserStatusRequest(ctx)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building user status request")
	}

	var apiResponse *types.APIResponse[*types.UserStatusResponse]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return nil, observability.PrepareError(err, span, "retrieving user status")
	}

	return apiResponse.Data, nil
}

// BeginSession fetches a login cookie.
func (c *Client) BeginSession(ctx context.Context, input *types.UserLoginInput) (*http.Cookie, error) {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	if input == nil {
		return nil, ErrNilInputProvided
	}

	// validating here requires settings knowledge, so we do not do it

	req, err := c.requestBuilder.BuildLoginRequest(ctx, input)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building login request")
	}

	res, err := c.fetchResponseToRequest(ctx, c.unauthenticatedClient, req)
	if err != nil {
		return nil, observability.PrepareError(err, span, "executing login request")
	}

	c.closeResponseBody(ctx, res)

	if cookies := res.Cookies(); len(cookies) > 0 {
		return cookies[0], nil
	}

	return nil, ErrNoCookiesReturned
}

// EndSession logs a user out.
func (c *Client) EndSession(ctx context.Context) error {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	req, err := c.requestBuilder.BuildLogoutRequest(ctx)
	if err != nil {
		return observability.PrepareError(err, span, "building logout request")
	}

	res, err := c.fetchResponseToRequest(ctx, c.authedClient, req)
	if err != nil {
		return observability.PrepareError(err, span, "executing logout request")
	}

	c.authedClient.Transport = newDefaultRoundTripper(c.authedClient.Timeout)
	c.closeResponseBody(ctx, res)

	return nil
}

// ChangePassword changes a user's password.
func (c *Client) ChangePassword(ctx context.Context, cookie *http.Cookie, input *types.PasswordUpdateInput) error {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	if cookie == nil {
		return ErrCookieRequired
	}

	if input == nil {
		return ErrNilInputProvided
	}

	// validating here requires settings knowledge, so we do not do it.

	req, err := c.requestBuilder.BuildChangePasswordRequest(ctx, cookie, input)
	if err != nil {
		return observability.PrepareError(err, span, "building change password request")
	}

	res, err := c.fetchResponseToRequest(ctx, c.unauthenticatedClient, req)
	if err != nil {
		return observability.PrepareError(err, span, "changing password")
	}

	c.closeResponseBody(ctx, res)

	if res.StatusCode != http.StatusAccepted {
		return observability.PrepareError(errInvalidResponseCode, span, "invalid response code: %d", res.StatusCode)
	}

	return nil
}

// CycleTwoFactorSecret cycles a user's 2FA secret.
func (c *Client) CycleTwoFactorSecret(ctx context.Context, cookie *http.Cookie, input *types.TOTPSecretRefreshInput) (*types.TOTPSecretRefreshResponse, error) {
	ctx, span := c.tracer.StartSpan(ctx)
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

	req, err := c.requestBuilder.BuildCycleTwoFactorSecretRequest(ctx, cookie, input)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building cycle two factor secret request")
	}

	var apiResponse *types.APIResponse[*types.TOTPSecretRefreshResponse]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return nil, observability.PrepareError(err, span, "cycling two factor secret")
	}

	return apiResponse.Data, nil
}

// VerifyTOTPSecret verifies a 2FA secret.
func (c *Client) VerifyTOTPSecret(ctx context.Context, userID, token string) error {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	if userID == "" {
		return ErrInvalidIDProvided
	}

	if _, err := strconv.ParseUint(token, 10, 64); token == "" || err != nil {
		return observability.PrepareError(err, span, "invalid token provided: %q", token)
	}

	req, err := c.requestBuilder.BuildVerifyTOTPSecretRequest(ctx, userID, token)
	if err != nil {
		return observability.PrepareError(err, span, "building verify two factor secret request")
	}

	res, err := c.fetchResponseToRequest(ctx, c.unauthenticatedClient, req)
	if err != nil {
		return observability.PrepareError(err, span, "verifying two factor secret")
	}

	c.closeResponseBody(ctx, res)

	if res.StatusCode == http.StatusBadRequest {
		return ErrInvalidTOTPToken
	} else if res.StatusCode != http.StatusAccepted {
		return observability.PrepareError(errInvalidResponseCode, span, "erroneous response code when validating TOTP secret: %d", res.StatusCode)
	}

	return nil
}

// RequestPasswordResetToken requests a password reset token.
func (c *Client) RequestPasswordResetToken(ctx context.Context, emailAddress string) error {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	if emailAddress == "" {
		return ErrEmptyEmailAddressProvided
	}

	req, err := c.requestBuilder.BuildPasswordResetTokenRequest(ctx, emailAddress)
	if err != nil {
		return observability.PrepareError(err, span, "building password reset token request")
	}

	res, err := c.fetchResponseToRequest(ctx, c.unauthenticatedClient, req)
	if err != nil {
		return observability.PrepareError(err, span, "requesting password reset token")
	}

	c.closeResponseBody(ctx, res)

	if res.StatusCode != http.StatusAccepted {
		return observability.PrepareError(errInvalidResponseCode, span, "erroneous response code when requesting password reset token: %d", res.StatusCode)
	}

	return nil
}

// RedeemPasswordResetToken redeems a password reset token.
func (c *Client) RedeemPasswordResetToken(ctx context.Context, input *types.PasswordResetTokenRedemptionRequestInput) error {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	if input == nil {
		return ErrNilInputProvided
	}

	req, err := c.requestBuilder.BuildPasswordResetTokenRedemptionRequest(ctx, input)
	if err != nil {
		return observability.PrepareError(err, span, "building password reset token redemption request")
	}

	res, err := c.fetchResponseToRequest(ctx, c.unauthenticatedClient, req)
	if err != nil {
		return observability.PrepareError(err, span, "requesting password reset token redemption")
	}

	c.closeResponseBody(ctx, res)

	if res.StatusCode != http.StatusAccepted {
		return observability.PrepareError(errInvalidResponseCode, span, "erroneous response code when redeeming password reset token: %d", res.StatusCode)
	}

	return nil
}
