package fakes

import (
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/converters"
)

// BuildFakeServiceSettingConfiguration builds a faked service setting.
func BuildFakeServiceSettingConfiguration() *types.ServiceSettingConfiguration {
	return &types.ServiceSettingConfiguration{
		ID:               BuildFakeID(),
		Value:            buildUniqueString(),
		Notes:            buildUniqueString(),
		ServiceSetting:   *BuildFakeServiceSetting(),
		BelongsToUser:    buildUniqueString(),
		BelongsToAccount: buildUniqueString(),
		CreatedAt:        BuildFakeTime(),
	}
}

// BuildFakeServiceSettingConfigurationList builds a faked ServiceSettingConfigurationList.
func BuildFakeServiceSettingConfigurationList() *types.QueryFilteredResult[types.ServiceSettingConfiguration] {
	var examples []*types.ServiceSettingConfiguration
	for i := 0; i < exampleQuantity; i++ {
		examples = append(examples, BuildFakeServiceSettingConfiguration())
	}

	return &types.QueryFilteredResult[types.ServiceSettingConfiguration]{
		Pagination: types.Pagination{
			Page:          1,
			Limit:         50,
			FilteredCount: exampleQuantity / 2,
			TotalCount:    exampleQuantity,
		},
		Data: examples,
	}
}

// BuildFakeServiceSettingConfigurationUpdateRequestInput builds a faked ServiceSettingConfigurationUpdateRequestInput from a service setting.
func BuildFakeServiceSettingConfigurationUpdateRequestInput() *types.ServiceSettingConfigurationUpdateRequestInput {
	serviceSetting := BuildFakeServiceSettingConfiguration()
	return converters.ConvertServiceSettingConfigurationToServiceSettingConfigurationUpdateRequestInput(serviceSetting)
}

// BuildFakeServiceSettingConfigurationCreationRequestInput builds a faked ServiceSettingConfigurationCreationRequestInput.
func BuildFakeServiceSettingConfigurationCreationRequestInput() *types.ServiceSettingConfigurationCreationRequestInput {
	serviceSetting := BuildFakeServiceSettingConfiguration()
	return converters.ConvertServiceSettingConfigurationToServiceSettingConfigurationCreationRequestInput(serviceSetting)
}
