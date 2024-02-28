package integration

import (
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func (s *TestSuite) TestAdmin_Returns404WhenModifyingUserAccountStatus() {
	s.runForEachClient("should not be possible to ban a user that does not exist", func(testClients *testClientWrapper) func() {
		return func() {
			t := s.T()

			ctx, span := tracing.StartCustomSpan(s.ctx, t.Name())
			defer span.End()

			input := fakes.BuildFakeUserAccountStatusUpdateInput()
			input.TargetUserID = nonexistentID

			// Ban user.
			assert.Error(t, testClients.admin.UpdateUserAccountStatus(ctx, input))
		}
	})
}

func (s *TestSuite) TestAdmin_BanningUsers() {
	s.runForEachClient("should be possible to ban users", func(testClients *testClientWrapper) func() {
		return func() {
			t := s.T()

			ctx, span := tracing.StartCustomSpan(s.ctx, t.Name())
			defer span.End()

			user, _, userClient, _ := createUserAndClientForTest(ctx, t, nil)

			// Assert that user can access service
			_, err := userClient.GetWebhooks(ctx, nil)
			require.NoError(t, err)

			input := &types.UserAccountStatusUpdateInput{
				TargetUserID: user.ID,
				NewStatus:    string(types.BannedUserAccountStatus),
				Reason:       "testing",
			}

			assert.NoError(t, testClients.admin.UpdateUserAccountStatus(ctx, input))

			// Assert user can no longer access service
			_, err = userClient.GetWebhooks(ctx, nil)
			assert.Error(t, err)

			// Clean up.
			assert.NoError(t, testClients.admin.ArchiveUser(ctx, user.ID))
		}
	})
}
