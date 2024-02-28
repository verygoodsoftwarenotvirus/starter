package requests

import (
	"context"
	"net/http"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/converters"
)

const (
	serviceSettingConfigurationsBasePath = "configurations"
)

// BuildGetServiceSettingConfigurationForUserByNameRequest builds an HTTP request for fetching a list of service settings.
func (b *Builder) BuildGetServiceSettingConfigurationForUserByNameRequest(ctx context.Context, settingName string, filter *types.QueryFilter) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	logger := filter.AttachToLogger(b.logger)

	uri := b.BuildURL(
		ctx,
		filter.ToValues(),
		serviceSettingsBasePath,
		serviceSettingConfigurationsBasePath,
		"user",
		settingName,
	)
	tracing.AttachToSpan(span, keys.RequestURIKey, uri)
	tracing.AttachQueryFilterToSpan(span, filter)
	tracing.AttachToSpan(span, keys.ServiceSettingNameKey, settingName)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, http.NoBody)
	if err != nil {
		logger.Error(err, "building request")
		return nil, observability.PrepareError(err, span, "building request")
	}

	return req, nil
}

// BuildGetServiceSettingConfigurationsForUserRequest builds an HTTP request for fetching a list of service settings.
func (b *Builder) BuildGetServiceSettingConfigurationsForUserRequest(ctx context.Context, filter *types.QueryFilter) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	logger := filter.AttachToLogger(b.logger)

	uri := b.BuildURL(
		ctx,
		filter.ToValues(),
		serviceSettingsBasePath,
		serviceSettingConfigurationsBasePath,
		"user",
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

// BuildGetServiceSettingConfigurationsForAccountRequest builds an HTTP request for fetching a list of service settings.
func (b *Builder) BuildGetServiceSettingConfigurationsForAccountRequest(ctx context.Context, filter *types.QueryFilter) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	logger := filter.AttachToLogger(b.logger)

	uri := b.BuildURL(
		ctx,
		filter.ToValues(),
		serviceSettingsBasePath,
		serviceSettingConfigurationsBasePath,
		"account",
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

// BuildCreateServiceSettingConfigurationRequest builds an HTTP request for creating a service setting.
func (b *Builder) BuildCreateServiceSettingConfigurationRequest(ctx context.Context, input *types.ServiceSettingConfigurationCreationRequestInput) (*http.Request, error) {
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
		serviceSettingConfigurationsBasePath,
	)
	tracing.AttachToSpan(span, keys.RequestURIKey, uri)

	req, err := b.buildDataRequest(ctx, http.MethodPost, uri, input)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building request")
	}

	return req, nil
}

// BuildUpdateServiceSettingConfigurationRequest builds an HTTP request for updating a service setting.
func (b *Builder) BuildUpdateServiceSettingConfigurationRequest(ctx context.Context, serviceSettingConfiguration *types.ServiceSettingConfiguration) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	if serviceSettingConfiguration == nil {
		return nil, ErrNilInputProvided
	}
	tracing.AttachToSpan(span, keys.ServiceSettingConfigurationIDKey, serviceSettingConfiguration.ID)

	uri := b.BuildURL(
		ctx,
		nil,
		serviceSettingsBasePath,
		serviceSettingConfigurationsBasePath,
		serviceSettingConfiguration.ID,
	)
	tracing.AttachToSpan(span, keys.RequestURIKey, uri)

	input := converters.ConvertServiceSettingConfigurationToServiceSettingConfigurationUpdateRequestInput(serviceSettingConfiguration)

	req, err := b.buildDataRequest(ctx, http.MethodPut, uri, input)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building request")
	}

	return req, nil
}

// BuildArchiveServiceSettingConfigurationRequest builds an HTTP request for archiving a service setting.
func (b *Builder) BuildArchiveServiceSettingConfigurationRequest(ctx context.Context, serviceSettingConfigurationID string) (*http.Request, error) {
	ctx, span := b.tracer.StartSpan(ctx)
	defer span.End()

	if serviceSettingConfigurationID == "" {
		return nil, ErrInvalidIDProvided
	}
	tracing.AttachToSpan(span, keys.ServiceSettingConfigurationIDKey, serviceSettingConfigurationID)

	uri := b.BuildURL(
		ctx,
		nil,
		serviceSettingsBasePath,
		serviceSettingConfigurationsBasePath,
		serviceSettingConfigurationID,
	)
	tracing.AttachToSpan(span, keys.RequestURIKey, uri)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, uri, http.NoBody)
	if err != nil {
		return nil, observability.PrepareError(err, span, "building request")
	}

	return req, nil
}
