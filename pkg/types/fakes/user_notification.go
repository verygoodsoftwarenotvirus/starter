package fakes

import (
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/converters"
)

// BuildFakeUserNotification builds a faked UserNotification.
func BuildFakeUserNotification() *types.UserNotification {
	return &types.UserNotification{
		CreatedAt:     BuildFakeTime(),
		ID:            BuildFakeID(),
		Content:       buildUniqueString(),
		Status:        types.UserNotificationStatusTypeUnread,
		BelongsToUser: BuildFakeID(),
	}
}

// BuildFakeUserNotificationList builds a faked UserNotificationList.
func BuildFakeUserNotificationList() *types.QueryFilteredResult[types.UserNotification] {
	var examples []*types.UserNotification
	for i := 0; i < exampleQuantity; i++ {
		examples = append(examples, BuildFakeUserNotification())
	}

	return &types.QueryFilteredResult[types.UserNotification]{
		Pagination: types.Pagination{
			Page:          1,
			Limit:         50,
			FilteredCount: exampleQuantity / 2,
			TotalCount:    exampleQuantity,
		},
		Data: examples,
	}
}

// BuildFakeUserNotificationUpdateRequestInput builds a faked UserNotificationUpdateRequestInput.
func BuildFakeUserNotificationUpdateRequestInput() *types.UserNotificationUpdateRequestInput {
	userNotification := BuildFakeUserNotification()
	return converters.ConvertUserNotificationToUserNotificationUpdateRequestInput(userNotification)
}

// BuildFakeUserNotificationCreationRequestInput builds a faked UserNotificationCreationRequestInput.
func BuildFakeUserNotificationCreationRequestInput() *types.UserNotificationCreationRequestInput {
	userNotification := BuildFakeUserNotification()
	return converters.ConvertUserNotificationToUserNotificationCreationRequestInput(userNotification)
}
