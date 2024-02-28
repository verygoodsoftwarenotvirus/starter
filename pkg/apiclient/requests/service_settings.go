package requests

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

const (
	serviceSettingsBasePath = "settings"
)

// BuildGetServiceSettingRequest builds an HTTP request for fetching a service setting.
func (b *Builder) BuildGetServiceSettingRequest(ctx context.Context, serviceSettingID string) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	if serviceSettingID == "" {
		return nil, ErrInvalidIDProvided
	}
	tracing.AttachToSpan(span, keys.ServiceSettingIDKey, serviceSettingID)

	uri := b.BuildURL(
		ctx,
		nil,
		serviceSettingsBasePath,
		serviceSettingID,
	)
	tracing.AttachToSpan(span, keys.RequestURIKey, uri)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, http.NoBody)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building request")
	}

	return req, nil
}

// BuildSearchServiceSettingsRequest builds an HTTP request for querying service settings.
func (b *Builder) BuildSearchServiceSettingsRequest(ctx context.Context, query string, limit uint8) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	logger := b.logger.WithValue(types.SearchQueryKey, query).WithValue(types.LimitQueryKey, limit)

	params := url.Values{}
	params.Set(types.SearchQueryKey, query)
	params.Set(types.LimitQueryKey, strconv.FormatUint(uint64(limit), 10))

	uri := b.BuildURL(
		ctx,
		params,
		serviceSettingsBasePath,
		"search",
	)
	tracing.AttachToSpan(span, keys.RequestURIKey, uri)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, http.NoBody)
	if err != nil {
		logger.Error(err, "building request")
		return nil, observability.PrepareError(err, span, "building request")
	}

	return req, nil
}

// BuildGetServiceSettingsRequest builds an HTTP request for fetching a list of service settings.
func (b *Builder) BuildGetServiceSettingsRequest(ctx context.Context, filter *types.QueryFilter) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	logger := filter.AttachToLogger(b.logger)

	uri := b.BuildURL(
		ctx,
		filter.ToValues(),
		serviceSettingsBasePath,
	)
	tracing.AttachToSpan(span, keys.RequestURIKey, uri)
	tracing.AttachQueryFilterToSpan(span, filter)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, http.NoBody)
	if err != nil {
		logger.Error(err, "building request")
		return nil, observability.PrepareError(err, span, "building request")
	}

	return req, nil
}

// BuildCreateServiceSettingRequest builds an HTTP request for creating a service setting.
func (b *Builder) BuildCreateServiceSettingRequest(ctx context.Context, input *types.ServiceSettingCreationRequestInput) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	if input == nil {
		return nil, ErrNilInputProvided
	}

	if err := input.ValidateWithContext(ctx); err != nil {
		return nil, observability.PrepareError(err, span, "validating input")
	}

	uri := b.BuildURL(
		ctx,
		nil,
		serviceSettingsBasePath,
	)
	tracing.AttachToSpan(span, keys.RequestURIKey, uri)

	req, err := b.buildDataRequest(ctx, http.MethodPost, uri, input)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building request")
	}

	return req, nil
}

// BuildArchiveServiceSettingRequest builds an HTTP request for archiving a service setting.
func (b *Builder) BuildArchiveServiceSettingRequest(ctx context.Context, serviceSettingID string) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	if serviceSettingID == "" {
		return nil, ErrInvalidIDProvided
	}
	tracing.AttachToSpan(span, keys.ServiceSettingIDKey, serviceSettingID)

	uri := b.BuildURL(
		ctx,
		nil,
		serviceSettingsBasePath,
		serviceSettingID,
	)
	tracing.AttachToSpan(span, keys.RequestURIKey, uri)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, uri, http.NoBody)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building request")
	}

	return req, nil
}
