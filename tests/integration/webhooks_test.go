package integration

import (
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/converters"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func checkWebhookEquality(t *testing.T, expected, actual *types.Webhook) {
	t.Helper()

	assert.NotZero(t, actual.ID)
	assert.Equal(t, expected.Name, actual.Name)
	assert.Equal(t, expected.ContentType, actual.ContentType)
	assert.Equal(t, expected.URL, actual.URL)
	assert.Equal(t, expected.Method, actual.Method)
	assert.NotZero(t, actual.CreatedAt)
}

func (s *TestSuite) TestWebhooks_Creating() {
	s.runForEachClient("should be creatable and readable and deletable", func(testClients *testClientWrapper) func() {
		return func() {
			t := s.T()

			ctx, span := tracing.StartCustomSpan(s.ctx, t.Name())
			defer span.End()

			// Create webhook.
			exampleWebhook := fakes.BuildFakeWebhook()
			exampleWebhookInput := converters.ConvertWebhookToWebhookCreationRequestInput(exampleWebhook)

			createdWebhook, err := testClients.user.CreateWebhook(ctx, exampleWebhookInput)
			require.NoError(t, err)

			createdWebhook, err = testClients.user.GetWebhook(ctx, createdWebhook.ID)
			requireNotNilAndNoProblems(t, createdWebhook, err)

			// assert webhook equality
			checkWebhookEquality(t, exampleWebhook, createdWebhook)

			actual, err := testClients.user.GetWebhook(ctx, createdWebhook.ID)
			requireNotNilAndNoProblems(t, actual, err)
			checkWebhookEquality(t, exampleWebhook, actual)

			// Archive trigger event
			assert.NoError(t, testClients.user.ArchiveWebhookTriggerEvent(ctx, createdWebhook.ID, actual.Events[0].ID))

			// Clean up.
			assert.NoError(t, testClients.user.ArchiveWebhook(ctx, createdWebhook.ID))
		}
	})
}

func (s *TestSuite) TestWebhooks_Reading_Returns404ForNonexistentWebhook() {
	s.runForEachClient("should error when reading non-existent webhook", func(testClients *testClientWrapper) func() {
		return func() {
			t := s.T()

			ctx, span := tracing.StartCustomSpan(s.ctx, t.Name())
			defer span.End()

			// Fetch webhook.
			_, err := testClients.user.GetWebhook(ctx, nonexistentID)
			assert.Error(t, err)
		}
	})
}

func (s *TestSuite) TestWebhooks_Listing() {
	s.runForEachClient("should be able to be read in a list", func(testClients *testClientWrapper) func() {
		return func() {
			t := s.T()

			ctx, span := tracing.StartCustomSpan(s.ctx, t.Name())
			defer span.End()

			// Create webhooks.
			var expected []*types.Webhook
			for i := 0; i < 5; i++ {
				// Create webhook.
				exampleWebhook := fakes.BuildFakeWebhook()
				exampleWebhookInput := converters.ConvertWebhookToWebhookCreationRequestInput(exampleWebhook)
				createdWebhook, webhookCreationErr := testClients.user.CreateWebhook(ctx, exampleWebhookInput)
				requireNotNilAndNoProblems(t, createdWebhook, webhookCreationErr)

				expected = append(expected, createdWebhook)
			}

			// Assert webhook list equality.
			actual, err := testClients.user.GetWebhooks(ctx, nil)
			requireNotNilAndNoProblems(t, actual, err)

			assert.GreaterOrEqual(t, len(actual.Data), len(expected))

			// Clean up.
			for _, webhook := range actual.Data {
				assert.NoError(t, testClients.user.ArchiveWebhook(ctx, webhook.ID))
			}
		}
	})
}

func (s *TestSuite) TestWebhooks_Archiving_Returns404ForNonexistentWebhook() {
	s.runForEachClient("should error when archiving a non-existent webhook", func(testClients *testClientWrapper) func() {
		return func() {
			t := s.T()

			ctx, span := tracing.StartCustomSpan(s.ctx, t.Name())
			defer span.End()

			assert.Error(t, testClients.user.ArchiveWebhook(ctx, nonexistentID))
		}
	})
}
