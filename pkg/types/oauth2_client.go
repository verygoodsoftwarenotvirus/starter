package types

import (
	"context"
	"net/http"
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

const (
	// OAuth2ClientCreatedCustomerEventType indicates an OAuth2 client was created.
	OAuth2ClientCreatedCustomerEventType ServiceEventType = "oauth2_client_created"
	// OAuth2ClientArchivedCustomerEventType indicates an OAuth2 client was archived.
	OAuth2ClientArchivedCustomerEventType ServiceEventType = "oauth2_client_archived"
)

type (
	// OAuth2Client represents a user-authorized OAuth2 client.
	OAuth2Client struct {
		_ struct{} `json:"-"`

		CreatedAt    time.Time  `json:"createdAt"`
		ArchivedAt   *time.Time `json:"archivedAt"`
		Name         string     `json:"name"`
		Description  string     `json:"description"`
		ClientID     string     `json:"clientID"`
		ID           string     `json:"id"`
		ClientSecret string     `json:"clientSecret"`
	}

	// OAuth2ClientCreationRequestInput is a struct for use when creating OAuth2 clients.
	OAuth2ClientCreationRequestInput struct {
		_ struct{} `json:"-"`

		Name        string `json:"name"`
		Description string `json:"description"`
	}

	// OAuth2ClientDatabaseCreationInput is a struct for use when creating OAuth2 clients.
	OAuth2ClientDatabaseCreationInput struct {
		_ struct{} `json:"-"`

		ID           string
		Name         string
		Description  string
		ClientID     string
		ClientSecret string
	}

	// OAuth2ClientCreationResponse is a struct for informing users of what their OAuth2 client's secret key is.
	OAuth2ClientCreationResponse struct {
		_ struct{} `json:"-"`

		ClientID     string `json:"clientID"`
		ClientSecret string `json:"clientSecret"`
		Name         string `json:"name"`
		Description  string `json:"description"`
		ID           string `json:"id"`
	}

	// OAuth2ClientDataManager handles OAuth2 clients.
	OAuth2ClientDataManager interface {
		GetOAuth2ClientByClientID(ctx context.Context, clientID string) (*OAuth2Client, error)
		GetOAuth2ClientByDatabaseID(ctx context.Context, id string) (*OAuth2Client, error)
		GetOAuth2Clients(ctx context.Context, filter *QueryFilter) (*QueryFilteredResult[OAuth2Client], error)
		CreateOAuth2Client(ctx context.Context, input *OAuth2ClientDatabaseCreationInput) (*OAuth2Client, error)
		ArchiveOAuth2Client(ctx context.Context, clientID string) error
	}

	// OAuth2ClientDataService describes a structure capable of serving traffic related to OAuth2 clients.
	OAuth2ClientDataService interface {
		ListHandler(http.ResponseWriter, *http.Request)
		CreateHandler(http.ResponseWriter, *http.Request)
		ReadHandler(http.ResponseWriter, *http.Request)
		ArchiveHandler(http.ResponseWriter, *http.Request)
	}

	OAuth2Service interface {
		AuthorizeHandler(res http.ResponseWriter, req *http.Request)
		TokenHandler(res http.ResponseWriter, req *http.Request)
	}
)

// ValidateWithContext validates an APICreationInput.
func (x *OAuth2ClientCreationRequestInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(ctx, x,
		validation.Field(&x.Name, validation.Required),
	)
}
