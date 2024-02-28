package integration

import (
	"context"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/apiclient"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/converters"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func checkUserNotificationEquality(t *testing.T, expected, actual *types.UserNotification) {
	t.Helper()

	assert.NotZero(t, actual.ID)
	assert.Equal(t, expected.Content, actual.Content, "expected Content for user notification %s to be %v, but it was %v", expected.ID, expected.Content, actual.Content)
	assert.Equal(t, expected.Status, actual.Status, "expected Status for user notification %s to be %v, but it was %v", expected.ID, expected.Status, actual.Status)
	assert.NotZero(t, actual.CreatedAt)
}

func createUserNotificationForTest(t *testing.T, ctx context.Context, forUser *types.User, userClient *apiclient.Client, adminClient *apiclient.Client) *types.UserNotification {
	t.Helper()

	exampleUserNotification := fakes.BuildFakeUserNotification()
	exampleUserNotification.BelongsToUser = forUser.ID
	exampleUserNotificationInput := converters.ConvertUserNotificationToUserNotificationCreationRequestInput(exampleUserNotification)
	createdUserNotification, err := adminClient.CreateUserNotification(ctx, exampleUserNotificationInput)
	require.NoError(t, err)
	checkUserNotificationEquality(t, exampleUserNotification, createdUserNotification)

	createdUserNotification, err = userClient.GetUserNotification(ctx, createdUserNotification.ID)
	requireNotNilAndNoProblems(t, createdUserNotification, err)
	checkUserNotificationEquality(t, exampleUserNotification, createdUserNotification)

	return createdUserNotification
}

func (s *TestSuite) TestUserNotifications_CompleteLifecycle() {
	s.runForEachClient("should be creatable and readable and updatable and deletable", func(testClients *testClientWrapper) func() {
		return func() {
			t := s.T()

			ctx, span := tracing.StartCustomSpan(s.ctx, t.Name())
			defer span.End()

			user, _, userClient, _ := createUserAndClientForTest(ctx, t, nil)

			exampleUserNotification := fakes.BuildFakeUserNotification()
			exampleUserNotification.BelongsToUser = user.ID
			exampleUserNotificationInput := converters.ConvertUserNotificationToUserNotificationCreationRequestInput(exampleUserNotification)
			_, err := userClient.CreateUserNotification(ctx, exampleUserNotificationInput)
			require.Error(t, err)

			createdUserNotification := createUserNotificationForTest(t, ctx, user, userClient, testClients.admin)

			createdUserNotification.Status = types.UserNotificationStatusTypeRead
			createdUserNotification.Update(converters.ConvertUserNotificationToUserNotificationUpdateRequestInput(createdUserNotification))
			require.NoError(t, userClient.UpdateUserNotification(ctx, createdUserNotification))

			actual, err := userClient.GetUserNotification(ctx, createdUserNotification.ID)
			requireNotNilAndNoProblems(t, actual, err)

			// assert user notification equality
			checkUserNotificationEquality(t, createdUserNotification, actual)
			assert.NotNil(t, actual.LastUpdatedAt)

			createdUserNotification.Status = types.UserNotificationStatusTypeRead
			assert.NoError(t, userClient.UpdateUserNotification(ctx, createdUserNotification))
		}
	})
}

func (s *TestSuite) TestUserNotifications_Listing() {
	s.runForEachClient("should be readable in paginated form", func(testClients *testClientWrapper) func() {
		return func() {
			t := s.T()

			ctx, span := tracing.StartCustomSpan(s.ctx, t.Name())
			defer span.End()

			user, _, userClient, _ := createUserAndClientForTest(ctx, t, nil)

			var expected []*types.UserNotification
			for i := 0; i < 5; i++ {
				exampleUserNotification := fakes.BuildFakeUserNotification()
				exampleUserNotification.BelongsToUser = user.ID
				exampleUserNotificationInput := converters.ConvertUserNotificationToUserNotificationCreationRequestInput(exampleUserNotification)
				createdUserNotification, createdUserNotificationErr := testClients.admin.CreateUserNotification(ctx, exampleUserNotificationInput)
				require.NoError(t, createdUserNotificationErr)

				checkUserNotificationEquality(t, exampleUserNotification, createdUserNotification)

				expected = append(expected, createdUserNotification)
			}

			// assert user notification list equality
			actual, err := userClient.GetUserNotifications(ctx, nil)
			requireNotNilAndNoProblems(t, actual, err)
			assert.True(
				t,
				len(expected) <= len(actual.Data),
				"expected %d to be <= %d",
				len(expected),
				len(actual.Data),
			)

			for _, createdUserNotification := range expected {
				createdUserNotification.Status = types.UserNotificationStatusTypeRead
				assert.NoError(t, userClient.UpdateUserNotification(ctx, createdUserNotification))
			}
		}
	})
}
