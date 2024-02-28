package fakes

import (
	"github.com/verygoodsoftwarenotvirus/starter/internal/pkg/pointer"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/converters"
)

// BuildFakeServiceSetting builds a faked service setting.
func BuildFakeServiceSetting() *types.ServiceSetting {
	defaultValue := buildUniqueString()

	return &types.ServiceSetting{
		ID:           BuildFakeID(),
		Name:         buildUniqueString(),
		Type:         "user",
		Description:  buildUniqueString(),
		Enumeration:  []string{defaultValue},
		DefaultValue: pointer.To(defaultValue),
		AdminsOnly:   true,
		CreatedAt:    BuildFakeTime(),
	}
}

// BuildFakeServiceSettingList builds a faked ServiceSettingList.
func BuildFakeServiceSettingList() *types.QueryFilteredResult[types.ServiceSetting] {
	var examples []*types.ServiceSetting
	for i := 0; i < exampleQuantity; i++ {
		examples = append(examples, BuildFakeServiceSetting())
	}

	return &types.QueryFilteredResult[types.ServiceSetting]{
		Pagination: types.Pagination{
			Page:          1,
			Limit:         50,
			FilteredCount: exampleQuantity / 2,
			TotalCount:    exampleQuantity,
		},
		Data: examples,
	}
}

// BuildFakeServiceSettingUpdateRequestInput builds a faked ServiceSettingUpdateRequestInput.
func BuildFakeServiceSettingUpdateRequestInput() *types.ServiceSettingUpdateRequestInput {
	serviceSetting := BuildFakeServiceSetting()
	return converters.ConvertServiceSettingToServiceSettingUpdateRequestInput(serviceSetting)
}

// BuildFakeServiceSettingCreationRequestInput builds a faked ServiceSettingCreationRequestInput.
func BuildFakeServiceSettingCreationRequestInput() *types.ServiceSettingCreationRequestInput {
	serviceSetting := BuildFakeServiceSetting()
	return converters.ConvertServiceSettingToServiceSettingCreationRequestInput(serviceSetting)
}
