package testutils

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/apiclient"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"

	"github.com/pquerna/otp/totp"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

var (
	errEmptyAddressUnallowed = errors.New("empty address not allowed")
)

// CreateServiceUser creates a user.
func CreateServiceUser(ctx context.Context, address string, in *types.UserRegistrationInput) (*types.User, error) {
	if address == "" {
		return nil, errEmptyAddressUnallowed
	}

	parsedAddress, err := url.Parse(address)
	if err != nil {
		return nil, err
	}

	c, err := apiclient.NewClient(
		parsedAddress,
		tracing.NewNoopTracerProvider(),
		apiclient.UsingTracingProvider(tracing.NewNoopTracerProvider()),
		apiclient.UsingURL(address),
	)
	if err != nil {
		return nil, fmt.Errorf("initializing client: %w", err)
	}

	ucr, err := c.CreateUser(ctx, in)
	if err != nil {
		return nil, err
	}

	token, tokenErr := totp.GenerateCode(ucr.TwoFactorSecret, time.Now().UTC())
	if tokenErr != nil {
		return nil, fmt.Errorf("generating totp code: %w", tokenErr)
	}

	if validationErr := c.VerifyTOTPSecret(ctx, ucr.CreatedUserID, token); validationErr != nil {
		return nil, fmt.Errorf("verifying totp code: %w", validationErr)
	}

	u := &types.User{
		ID:              ucr.CreatedUserID,
		Username:        ucr.Username,
		EmailAddress:    ucr.EmailAddress,
		TwoFactorSecret: ucr.TwoFactorSecret,
		CreatedAt:       ucr.CreatedAt,
		// this is a dirty trick to reuse most of this model,
		HashedPassword: in.Password,
	}

	return u, nil
}

// GetLoginCookie fetches a login cookie for a given user.
func GetLoginCookie(ctx context.Context, serviceURL string, u *types.User) (*http.Cookie, error) {
	tu, err := url.Parse(serviceURL)
	if err != nil {
		panic(err)
	}

	lu, err := url.Parse("users/login")
	if err != nil {
		panic(err)
	}

	uri := tu.ResolveReference(lu).String()

	code, err := totp.GenerateCode(strings.ToUpper(u.TwoFactorSecret), time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("generating totp token: %w", err)
	}

	body, err := json.Marshal(&types.UserLoginInput{
		Username:  u.Username,
		Password:  u.HashedPassword,
		TOTPToken: code,
	})
	if err != nil {
		return nil, fmt.Errorf("generating login request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}

	res, err := otelhttp.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}

	if err = res.Body.Close(); err != nil {
		log.Println("error closing body")
	}

	cookies := res.Cookies()
	if len(cookies) > 0 {
		return cookies[0], nil
	}

	return nil, http.ErrNoCookie
}
