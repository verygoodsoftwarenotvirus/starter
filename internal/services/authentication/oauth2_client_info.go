package authentication

import (
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"

	"github.com/go-oauth2/oauth2/v4"
)

var _ oauth2.ClientInfo = &oauth2ClientInfoImpl{}

type oauth2ClientInfoImpl struct {
	client *types.OAuth2Client
	domain string
}

func (i *oauth2ClientInfoImpl) GetID() string {
	return i.client.ID
}

func (i *oauth2ClientInfoImpl) GetSecret() string {
	return i.client.ClientSecret
}

func (i *oauth2ClientInfoImpl) GetDomain() string {
	return i.domain
}

func (i *oauth2ClientInfoImpl) IsPublic() bool {
	return false
}

func (i *oauth2ClientInfoImpl) GetUserID() string {
	// AFAICT this isn't used anywhere
	return ""
}
