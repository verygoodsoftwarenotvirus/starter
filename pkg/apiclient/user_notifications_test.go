package apiclient

import (
	"context"
	"net/http"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/converters"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func TestUserNotifications(t *testing.T) {
	t.Parallel()

	suite.Run(t, new(userNotificationsTestSuite))
}

type userNotificationsBaseSuite struct {
	suite.Suite
	ctx                                 context.Context
	exampleUserNotification             *types.UserNotification
	exampleUserNotificationResponse     *types.APIResponse[*types.UserNotification]
	exampleUserNotificationListResponse *types.APIResponse[[]*types.UserNotification]
	exampleUserNotificationList         []*types.UserNotification
}

var _ suite.SetupTestSuite = (*userNotificationsBaseSuite)(nil)

func (s *userNotificationsBaseSuite) SetupTest() {
	s.ctx = context.Background()
	s.exampleUserNotification = fakes.BuildFakeUserNotification()
	exampleUserNotificationList := fakes.BuildFakeUserNotificationList()
	s.exampleUserNotificationList = exampleUserNotificationList.Data
	s.exampleUserNotificationResponse = &types.APIResponse[*types.UserNotification]{
		Data: s.exampleUserNotification,
	}
	s.exampleUserNotificationListResponse = &types.APIResponse[[]*types.UserNotification]{
		Data:       s.exampleUserNotificationList,
		Pagination: &exampleUserNotificationList.Pagination,
	}
}

type userNotificationsTestSuite struct {
	suite.Suite
	userNotificationsBaseSuite
}

func (s *userNotificationsTestSuite) TestClient_GetUserNotification() {
	const expectedPathFormat = "/api/v1/user_notifications/%s"

	s.Run("standard", func() {
		t := s.T()

		spec := newRequestSpec(true, http.MethodGet, "", expectedPathFormat, s.exampleUserNotification.ID)
		c, _ := buildTestClientWithJSONResponse(t, spec, s.exampleUserNotificationResponse)
		actual, err := c.GetUserNotification(s.ctx, s.exampleUserNotification.ID)

		require.NotNil(t, actual)
		assert.NoError(t, err)
		assert.Equal(t, s.exampleUserNotification, actual)
	})

	s.Run("with invalid user notification ID", func() {
		t := s.T()

		c, _ := buildSimpleTestClient(t)
		actual, err := c.GetUserNotification(s.ctx, "")

		require.Nil(t, actual)
		assert.Error(t, err)
	})

	s.Run("with error building request", func() {
		t := s.T()

		c := buildTestClientWithInvalidURL(t)
		actual, err := c.GetUserNotification(s.ctx, s.exampleUserNotification.ID)

		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	s.Run("with error executing request", func() {
		t := s.T()

		spec := newRequestSpec(true, http.MethodGet, "", expectedPathFormat, s.exampleUserNotification.ID)
		c := buildTestClientWithInvalidResponse(t, spec)
		actual, err := c.GetUserNotification(s.ctx, s.exampleUserNotification.ID)

		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func (s *userNotificationsTestSuite) TestClient_GetUserNotifications() {
	const expectedPath = "/api/v1/user_notifications"

	s.Run("standard", func() {
		t := s.T()

		filter := (*types.QueryFilter)(nil)

		spec := newRequestSpec(true, http.MethodGet, "limit=50&page=1&sortBy=asc", expectedPath)
		c, _ := buildTestClientWithJSONResponse(t, spec, s.exampleUserNotificationListResponse)
		actual, err := c.GetUserNotifications(s.ctx, filter)

		require.NotNil(t, actual)
		assert.NoError(t, err)
		assert.Equal(t, s.exampleUserNotificationList, actual.Data)
	})

	s.Run("with error building request", func() {
		t := s.T()

		filter := (*types.QueryFilter)(nil)

		c := buildTestClientWithInvalidURL(t)
		actual, err := c.GetUserNotifications(s.ctx, filter)

		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	s.Run("with error executing request", func() {
		t := s.T()

		filter := (*types.QueryFilter)(nil)

		spec := newRequestSpec(true, http.MethodGet, "limit=50&page=1&sortBy=asc", expectedPath)
		c := buildTestClientWithInvalidResponse(t, spec)
		actual, err := c.GetUserNotifications(s.ctx, filter)

		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func (s *userNotificationsTestSuite) TestClient_CreateUserNotification() {
	const expectedPath = "/api/v1/user_notifications"

	s.Run("standard", func() {
		t := s.T()

		exampleInput := fakes.BuildFakeUserNotificationCreationRequestInput()

		spec := newRequestSpec(false, http.MethodPost, "", expectedPath)
		c, _ := buildTestClientWithJSONResponse(t, spec, s.exampleUserNotificationResponse)

		actual, err := c.CreateUserNotification(s.ctx, exampleInput)
		require.NotEmpty(t, actual)
		assert.NoError(t, err)

		assert.Equal(t, s.exampleUserNotification, actual)
	})

	s.Run("with nil input", func() {
		t := s.T()

		c, _ := buildSimpleTestClient(t)

		actual, err := c.CreateUserNotification(s.ctx, nil)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	s.Run("with invalid input", func() {
		t := s.T()

		c, _ := buildSimpleTestClient(t)
		exampleInput := &types.UserNotificationCreationRequestInput{}

		actual, err := c.CreateUserNotification(s.ctx, exampleInput)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	s.Run("with error building request", func() {
		t := s.T()

		exampleInput := converters.ConvertUserNotificationToUserNotificationCreationRequestInput(s.exampleUserNotification)

		c := buildTestClientWithInvalidURL(t)

		actual, err := c.CreateUserNotification(s.ctx, exampleInput)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})

	s.Run("with error executing request", func() {
		t := s.T()

		exampleInput := converters.ConvertUserNotificationToUserNotificationCreationRequestInput(s.exampleUserNotification)
		c, _ := buildTestClientThatWaitsTooLong(t)

		actual, err := c.CreateUserNotification(s.ctx, exampleInput)
		assert.Nil(t, actual)
		assert.Error(t, err)
	})
}

func (s *userNotificationsTestSuite) TestClient_UpdateUserNotification() {
	const expectedPathFormat = "/api/v1/user_notifications/%s"

	s.Run("standard", func() {
		t := s.T()

		spec := newRequestSpec(false, http.MethodPatch, "", expectedPathFormat, s.exampleUserNotification.ID)
		c, _ := buildTestClientWithJSONResponse(t, spec, s.exampleUserNotificationResponse)

		err := c.UpdateUserNotification(s.ctx, s.exampleUserNotification)
		assert.NoError(t, err)
	})

	s.Run("with nil input", func() {
		t := s.T()

		c, _ := buildSimpleTestClient(t)

		err := c.UpdateUserNotification(s.ctx, nil)
		assert.Error(t, err)
	})

	s.Run("with error building request", func() {
		t := s.T()

		c := buildTestClientWithInvalidURL(t)

		err := c.UpdateUserNotification(s.ctx, s.exampleUserNotification)
		assert.Error(t, err)
	})

	s.Run("with error executing request", func() {
		t := s.T()

		c, _ := buildTestClientThatWaitsTooLong(t)

		err := c.UpdateUserNotification(s.ctx, s.exampleUserNotification)
		assert.Error(t, err)
	})
}
