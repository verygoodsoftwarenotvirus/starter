package authentication

import (
	"time"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"

	"github.com/go-oauth2/oauth2/v4"
)

type tokenImpl struct {
	types.OAuth2ClientToken
}

func (t *tokenImpl) New() oauth2.TokenInfo {
	// TODO: huh?
	return &tokenImpl{}
}

func (t *tokenImpl) GetClientID() string {
	return t.ClientID
}

func (t *tokenImpl) SetClientID(s string) {
	t.ClientID = s
}

func (t *tokenImpl) GetUserID() string {
	return t.BelongsToUser
}

func (t *tokenImpl) SetUserID(s string) {
	t.BelongsToUser = s
}

func (t *tokenImpl) GetRedirectURI() string {
	return t.RedirectURI
}

func (t *tokenImpl) SetRedirectURI(s string) {
	t.RedirectURI = s
}

func (t *tokenImpl) GetScope() string {
	return t.Scope
}

func (t *tokenImpl) SetScope(s string) {
	t.Scope = s
}

func (t *tokenImpl) GetCode() string {
	return t.Code
}

func (t *tokenImpl) SetCode(s string) {
	t.Code = s
}

func (t *tokenImpl) GetCodeCreateAt() time.Time {
	return t.CodeCreatedAt
}

func (t *tokenImpl) SetCodeCreateAt(x time.Time) {
	t.CodeCreatedAt = x
}

func (t *tokenImpl) GetCodeExpiresIn() time.Duration {
	return t.CodeExpiresAt
}

func (t *tokenImpl) SetCodeExpiresIn(duration time.Duration) {
	t.CodeExpiresAt = duration
}

func (t *tokenImpl) GetCodeChallenge() string {
	return t.CodeChallenge
}

func (t *tokenImpl) SetCodeChallenge(s string) {
	t.CodeChallenge = s
}

func (t *tokenImpl) GetCodeChallengeMethod() oauth2.CodeChallengeMethod {
	return oauth2.CodeChallengeMethod(t.CodeChallengeMethod)
}

func (t *tokenImpl) SetCodeChallengeMethod(method oauth2.CodeChallengeMethod) {
	t.CodeChallengeMethod = method.String()
}

func (t *tokenImpl) GetAccess() string {
	return t.Access
}

func (t *tokenImpl) SetAccess(s string) {
	t.Access = s
}

func (t *tokenImpl) GetAccessCreateAt() time.Time {
	return t.AccessCreatedAt
}

func (t *tokenImpl) SetAccessCreateAt(x time.Time) {
	t.AccessCreatedAt = x
}

func (t *tokenImpl) GetAccessExpiresIn() time.Duration {
	return t.AccessExpiresAt
}

func (t *tokenImpl) SetAccessExpiresIn(duration time.Duration) {
	t.AccessExpiresAt = duration
}

func (t *tokenImpl) GetRefresh() string {
	return t.Refresh
}

func (t *tokenImpl) SetRefresh(s string) {
	t.Refresh = s
}

func (t *tokenImpl) GetRefreshCreateAt() time.Time {
	return t.RefreshCreatedAt
}

func (t *tokenImpl) SetRefreshCreateAt(x time.Time) {
	t.RefreshCreatedAt = x
}

func (t *tokenImpl) GetRefreshExpiresIn() time.Duration {
	return t.RefreshExpiresAt
}

func (t *tokenImpl) SetRefreshExpiresIn(duration time.Duration) {
	t.RefreshExpiresAt = duration
}

func convertTokenToImpl(t *types.OAuth2ClientToken) oauth2.TokenInfo {
	return &tokenImpl{OAuth2ClientToken: *t}
}
