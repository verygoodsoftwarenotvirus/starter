package types

import (
	"context"
	"encoding/gob"
	"net/http"
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

const (
	// ServiceSettingConfigurationCreatedCustomerEventType indicates a service setting was created.
	ServiceSettingConfigurationCreatedCustomerEventType ServiceEventType = "service_setting_configuration_created"
	// ServiceSettingConfigurationUpdatedCustomerEventType indicates a service setting was updated.
	ServiceSettingConfigurationUpdatedCustomerEventType ServiceEventType = "service_setting_configuration_updated"
	// ServiceSettingConfigurationArchivedCustomerEventType indicates a service setting was archived.
	ServiceSettingConfigurationArchivedCustomerEventType ServiceEventType = "service_setting_configuration_archived"
)

func init() {
	gob.Register(new(ServiceSetting))
	gob.Register(new(ServiceSettingCreationRequestInput))
	gob.Register(new(ServiceSettingUpdateRequestInput))
}

type (
	// ServiceSettingConfiguration represents a configured service setting configurations.
	ServiceSettingConfiguration struct {
		_ struct{} `json:"-"`

		CreatedAt        time.Time      `json:"createdAt"`
		LastUpdatedAt    *time.Time     `json:"lastUpdatedAt"`
		ArchivedAt       *time.Time     `json:"archivedAt"`
		ID               string         `json:"id"`
		Value            string         `json:"value"`
		Notes            string         `json:"notes"`
		BelongsToUser    string         `json:"belongsToUser"`
		BelongsToAccount string         `json:"belongsToAccount"`
		ServiceSetting   ServiceSetting `json:"serviceSetting"`
	}

	// ServiceSettingConfigurationCreationRequestInput represents what a user could set as input for creating settings configurations.
	ServiceSettingConfigurationCreationRequestInput struct {
		_ struct{} `json:"-"`

		Value            string `json:"value"`
		Notes            string `json:"notes"`
		ServiceSettingID string `json:"serviceSettingID"`
		BelongsToUser    string `json:"belongsToUser"`
		BelongsToAccount string `json:"belongsToAccount"`
	}

	// ServiceSettingConfigurationDatabaseCreationInput represents what a user could set as input for creating service settings configurations.
	ServiceSettingConfigurationDatabaseCreationInput struct {
		_ struct{} `json:"-"`

		ID               string
		Value            string
		Notes            string
		ServiceSettingID string
		BelongsToUser    string
		BelongsToAccount string
	}

	// ServiceSettingConfigurationUpdateRequestInput represents what a user could set as input for updating service settings configurations.
	ServiceSettingConfigurationUpdateRequestInput struct {
		_ struct{} `json:"-"`

		Value            *string `json:"value"`
		Notes            *string `json:"notes"`
		ServiceSettingID *string `json:"serviceSettingID"`
		BelongsToUser    *string `json:"belongsToUser"`
		BelongsToAccount *string `json:"belongsToAccount"`
	}

	// ServiceSettingConfigurationDataManager describes a structure capable of storing settings permanently.
	ServiceSettingConfigurationDataManager interface {
		ServiceSettingConfigurationExists(ctx context.Context, serviceSettingConfigurationID string) (bool, error)
		GetServiceSettingConfiguration(ctx context.Context, serviceSettingConfigurationID string) (*ServiceSettingConfiguration, error)
		GetServiceSettingConfigurationForUserByName(ctx context.Context, userID, serviceSettingConfigurationName string) (*ServiceSettingConfiguration, error)
		GetServiceSettingConfigurationForAccountByName(ctx context.Context, accountID, serviceSettingConfigurationName string) (*ServiceSettingConfiguration, error)
		GetServiceSettingConfigurationsForUser(ctx context.Context, userID string, filter *QueryFilter) (*QueryFilteredResult[ServiceSettingConfiguration], error)
		GetServiceSettingConfigurationsForAccount(ctx context.Context, accountID string, filter *QueryFilter) (*QueryFilteredResult[ServiceSettingConfiguration], error)
		CreateServiceSettingConfiguration(ctx context.Context, input *ServiceSettingConfigurationDatabaseCreationInput) (*ServiceSettingConfiguration, error)
		UpdateServiceSettingConfiguration(ctx context.Context, updated *ServiceSettingConfiguration) error
		ArchiveServiceSettingConfiguration(ctx context.Context, serviceSettingConfigurationID string) error
	}

	// ServiceSettingConfigurationDataService describes a structure capable of serving traffic related to service settings.
	ServiceSettingConfigurationDataService interface {
		CreateHandler(http.ResponseWriter, *http.Request)
		ForUserHandler(http.ResponseWriter, *http.Request)
		ForAccountHandler(http.ResponseWriter, *http.Request)
		ForUserByNameHandler(http.ResponseWriter, *http.Request)
		UpdateHandler(http.ResponseWriter, *http.Request)
		ArchiveHandler(http.ResponseWriter, *http.Request)
	}
)

// Update merges an ServiceSettingConfigurationUpdateRequestInput with a service setting.
func (x *ServiceSettingConfiguration) Update(input *ServiceSettingConfigurationUpdateRequestInput) {
	if input.Value != nil && *input.Value != x.Value {
		x.Value = *input.Value
	}

	if input.Notes != nil && *input.Notes != x.Notes {
		x.Notes = *input.Notes
	}

	if input.ServiceSettingID != nil && *input.ServiceSettingID != x.ServiceSetting.ID {
		x.ServiceSetting.ID = *input.ServiceSettingID
	}

	if input.BelongsToUser != nil && *input.BelongsToUser != x.BelongsToUser {
		x.BelongsToUser = *input.BelongsToUser
	}

	if input.BelongsToAccount != nil && *input.BelongsToAccount != x.BelongsToAccount {
		x.BelongsToAccount = *input.BelongsToAccount
	}
}

var _ validation.ValidatableWithContext = (*ServiceSettingConfigurationCreationRequestInput)(nil)

// ValidateWithContext validates a ServiceSettingCreationRequestInput.
func (x *ServiceSettingConfigurationCreationRequestInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(
		ctx,
		x,
		validation.Field(&x.Value, validation.Required),
		validation.Field(&x.BelongsToUser, validation.Required),
	)
}

var _ validation.ValidatableWithContext = (*ServiceSettingConfigurationDatabaseCreationInput)(nil)

// ValidateWithContext validates a ServiceSettingConfigurationDatabaseCreationInput.
func (x *ServiceSettingConfigurationDatabaseCreationInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(
		ctx,
		x,
		validation.Field(&x.ID, validation.Required),
		validation.Field(&x.Value, validation.Required),
		validation.Field(&x.BelongsToUser, validation.Required),
	)
}

var _ validation.ValidatableWithContext = (*ServiceSettingConfigurationUpdateRequestInput)(nil)

// ValidateWithContext validates a ServiceSettingConfigurationUpdateRequestInput.
func (x *ServiceSettingConfigurationUpdateRequestInput) ValidateWithContext(ctx context.Context) error {
	return validation.ValidateStructWithContext(
		ctx,
		x,
		validation.Field(&x.Value, validation.Required),
		validation.Field(&x.ServiceSettingID, validation.Required),
	)
}
