package requests

import (
	"context"
	"net/http"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

const (
	oauth2ClientsBasePath = "oauth2_clients"
)

// BuildGetOAuth2ClientRequest builds an HTTP request for fetching an OAuth2 client.
func (b *Builder) BuildGetOAuth2ClientRequest(ctx context.Context, clientID string) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	if clientID == "" {
		return nil, ErrInvalidIDProvided
	}

	uri := b.BuildURL(
		ctx,
		nil,
		oauth2ClientsBasePath,
		clientID,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, http.NoBody)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building request")
	}

	return req, nil
}

// BuildGetOAuth2ClientsRequest builds an HTTP request for fetching a list of OAuth2 clients.
func (b *Builder) BuildGetOAuth2ClientsRequest(ctx context.Context, filter *types.QueryFilter) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	tracing.AttachQueryFilterToSpan(span, filter)

	uri := b.BuildURL(ctx, filter.ToValues(), oauth2ClientsBasePath)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, http.NoBody)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building request")
	}

	return req, nil
}

// BuildCreateOAuth2ClientRequest builds an HTTP request for creating an OAuth2 client.
func (b *Builder) BuildCreateOAuth2ClientRequest(ctx context.Context, input *types.OAuth2ClientCreationRequestInput) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	if input == nil {
		return nil, ErrNilInputProvided
	}

	uri := b.BuildURL(ctx, nil, oauth2ClientsBasePath)

	req, err := b.buildDataRequest(ctx, http.MethodPost, uri, input)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building request")
	}

	return req, nil
}

// BuildArchiveOAuth2ClientRequest builds an HTTP request for archiving an OAuth2 client.
func (b *Builder) BuildArchiveOAuth2ClientRequest(ctx context.Context, clientID string) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	if clientID == "" {
		return nil, ErrInvalidIDProvided
	}

	uri := b.BuildURL(
		ctx,
		nil,
		oauth2ClientsBasePath,
		clientID,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, uri, http.NoBody)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building request")
	}

	return req, nil
}
