package apiclient

import (
	"context"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/keys"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
)

// GetServiceSettingConfigurationForUserByName retrieves a list of service settings.
func (c *Client) GetServiceSettingConfigurationForUserByName(ctx context.Context, settingName string, filter *types.QueryFilter) (*types.ServiceSettingConfiguration, error) {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	logger := c.logger.WithValue(keys.ServiceSettingNameKey, settingName)
	logger = filter.AttachToLogger(logger)
	tracing.AttachQueryFilterToSpan(span, filter)
	tracing.AttachToSpan(span, keys.ServiceSettingNameKey, settingName)

	req, err := c.requestBuilder.BuildGetServiceSettingConfigurationForUserByNameRequest(ctx, settingName, filter)
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "building service settings list request")
	}

	var apiResponse *types.APIResponse[*types.ServiceSettingConfiguration]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "retrieving service settings")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return nil, err
	}

	return apiResponse.Data, nil
}

// GetServiceSettingConfigurationsForUser retrieves a list of service settings.
func (c *Client) GetServiceSettingConfigurationsForUser(ctx context.Context, filter *types.QueryFilter) (*types.QueryFilteredResult[types.ServiceSettingConfiguration], error) {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	logger := c.logger.Clone()
	logger = filter.AttachToLogger(logger)
	tracing.AttachQueryFilterToSpan(span, filter)

	req, err := c.requestBuilder.BuildGetServiceSettingConfigurationsForUserRequest(ctx, filter)
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "building service settings list request")
	}

	var apiResponse *types.APIResponse[[]*types.ServiceSettingConfiguration]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "retrieving service settings")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return nil, err
	}

	response := &types.QueryFilteredResult[types.ServiceSettingConfiguration]{
		Data:       apiResponse.Data,
		Pagination: *apiResponse.Pagination,
	}

	return response, nil
}

// GetServiceSettingConfigurationsForAccount retrieves a list of service settings.
func (c *Client) GetServiceSettingConfigurationsForAccount(ctx context.Context, filter *types.QueryFilter) (*types.QueryFilteredResult[types.ServiceSettingConfiguration], error) {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	logger := c.logger.Clone()
	logger = filter.AttachToLogger(logger)
	tracing.AttachQueryFilterToSpan(span, filter)

	req, err := c.requestBuilder.BuildGetServiceSettingConfigurationsForAccountRequest(ctx, filter)
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "building service settings list request")
	}

	var apiResponse *types.APIResponse[[]*types.ServiceSettingConfiguration]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "retrieving service settings")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return nil, err
	}

	response := &types.QueryFilteredResult[types.ServiceSettingConfiguration]{
		Data:       apiResponse.Data,
		Pagination: *apiResponse.Pagination,
	}

	return response, nil
}

// CreateServiceSettingConfiguration creates a service setting.
func (c *Client) CreateServiceSettingConfiguration(ctx context.Context, input *types.ServiceSettingConfigurationCreationRequestInput) (*types.ServiceSettingConfiguration, error) {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	logger := c.logger.Clone()

	if input == nil {
		return nil, ErrNilInputProvided
	}

	if err := input.ValidateWithContext(ctx); err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "validating input")
	}

	req, err := c.requestBuilder.BuildCreateServiceSettingConfigurationRequest(ctx, input)
	if err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "building create service setting request")
	}

	var apiResponse *types.APIResponse[*types.ServiceSettingConfiguration]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return nil, observability.PrepareAndLogError(err, logger, span, "creating service setting")
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return nil, err
	}

	return apiResponse.Data, nil
}

// UpdateServiceSettingConfiguration updates a service setting.
func (c *Client) UpdateServiceSettingConfiguration(ctx context.Context, serviceSettingConfiguration *types.ServiceSettingConfiguration) error {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	logger := c.logger.Clone()

	if serviceSettingConfiguration == nil {
		return ErrNilInputProvided
	}
	logger = logger.WithValue(keys.ServiceSettingConfigurationIDKey, serviceSettingConfiguration.ID)
	tracing.AttachToSpan(span, keys.ServiceSettingConfigurationIDKey, serviceSettingConfiguration.ID)

	req, err := c.requestBuilder.BuildUpdateServiceSettingConfigurationRequest(ctx, serviceSettingConfiguration)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "building update service setting request")
	}

	var apiResponse *types.APIResponse[*types.ServiceSettingConfiguration]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "updating service setting %s", serviceSettingConfiguration.ID)
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return err
	}

	return nil
}

// ArchiveServiceSettingConfiguration archives a service setting.
func (c *Client) ArchiveServiceSettingConfiguration(ctx context.Context, serviceSettingConfigurationID string) error {
	ctx, span := c.tracer.StartSpan(ctx)
	defer span.End()

	logger := c.logger.Clone()

	if serviceSettingConfigurationID == "" {
		return ErrInvalidIDProvided
	}
	logger = logger.WithValue(keys.ServiceSettingConfigurationIDKey, serviceSettingConfigurationID)
	tracing.AttachToSpan(span, keys.ServiceSettingConfigurationIDKey, serviceSettingConfigurationID)

	req, err := c.requestBuilder.BuildArchiveServiceSettingConfigurationRequest(ctx, serviceSettingConfigurationID)
	if err != nil {
		return observability.PrepareAndLogError(err, logger, span, "building archive service setting request")
	}

	var apiResponse *types.APIResponse[*types.ServiceSettingConfiguration]
	if err = c.fetchAndUnmarshal(ctx, req, &apiResponse); err != nil {
		return observability.PrepareAndLogError(err, logger, span, "archiving service setting %s", serviceSettingConfigurationID)
	}

	if err = apiResponse.Error.AsError(); err != nil {
		return err
	}

	return nil
}
