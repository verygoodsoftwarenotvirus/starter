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

func checkOAuth2ClientEquality(t *testing.T, expected, actual *types.OAuth2Client) {
	t.Helper()

	assert.NotZero(t, actual.ID)
	assert.Equal(t, expected.Name, actual.Name, "expected Name for OAuth2 client %s to be %q, but it was %q ", actual.ID, expected.Name, actual.Name)
	assert.Equal(t, expected.Description, actual.Description, "expected Description for OAuth2 client %s to be %q, but it was %q ", actual.ID, expected.Description, actual.Description)
	assert.NotEmpty(t, actual.ClientID, "expected ClientID for OAuth2 client %s to not be empty, but it was", actual.ID)
	assert.NotEmpty(t, actual.ClientSecret, "expected ClientSecret for OAuth2 client %s to not be empty, but it was", actual.ID)
	assert.NotZero(t, actual.CreatedAt)
}

func (s *TestSuite) TestOAuth2Clients_Creating() {
	s.runForCookieClient("should be possible to create OAuth2 clients", func(testClients *testClientWrapper) func() {
		return func() {
			t := s.T()

			ctx, span := tracing.StartCustomSpan(s.ctx, t.Name())
			defer span.End()

			// Create OAuth2 client.
			exampleOAuth2Client := fakes.BuildFakeOAuth2Client()
			exampleOAuth2ClientInput := converters.ConvertOAuth2ClientToOAuth2ClientCreationInput(exampleOAuth2Client)

			createdOAuth2Client, err := testClients.admin.CreateOAuth2Client(ctx, exampleOAuth2ClientInput)
			requireNotNilAndNoProblems(t, createdOAuth2Client, err)

			// Assert OAuth2 client equality.
			assert.NotEmpty(t, createdOAuth2Client.ClientID, "expected ClientID for OAuth2 client %s to not be empty, but it was", createdOAuth2Client.ID)
			assert.NotEmpty(t, createdOAuth2Client.ClientSecret, "expected ClientSecret for OAuth2 client %s to not be empty, but it was", createdOAuth2Client.ID)

			// Clean up.
			assert.NoError(t, testClients.admin.ArchiveOAuth2Client(ctx, createdOAuth2Client.ID))
		}
	})

	s.runForCookieClient("cannot create OAuth2 clients as plain user", func(testClients *testClientWrapper) func() {
		return func() {
			t := s.T()

			ctx, span := tracing.StartCustomSpan(s.ctx, t.Name())
			defer span.End()

			// Create OAuth2 client.
			exampleOAuth2Client := fakes.BuildFakeOAuth2Client()
			exampleOAuth2ClientInput := converters.ConvertOAuth2ClientToOAuth2ClientCreationInput(exampleOAuth2Client)

			createdOAuth2Client, err := testClients.user.CreateOAuth2Client(ctx, exampleOAuth2ClientInput)
			require.Nil(t, createdOAuth2Client)
			require.Error(t, err)
		}
	})
}

func (s *TestSuite) TestOAuth2Clients_Listing() {
	s.runForCookieClient("should be possible to read OAuth2 clients in a list", func(testClients *testClientWrapper) func() {
		return func() {
			t := s.T()

			const clientsToMake = 1

			ctx, span := tracing.StartCustomSpan(s.ctx, t.Name())
			defer span.End()

			// Create OAuth2 clients.
			var expected []string
			for i := 0; i < clientsToMake; i++ {
				// Create OAuth2 client.
				exampleOAuth2Client := fakes.BuildFakeOAuth2Client()
				exampleOAuth2ClientInput := converters.ConvertOAuth2ClientToOAuth2ClientCreationInput(exampleOAuth2Client)
				createdOAuth2Client, err := testClients.admin.CreateOAuth2Client(ctx, exampleOAuth2ClientInput)
				requireNotNilAndNoProblems(t, createdOAuth2Client, err)

				expected = append(expected, createdOAuth2Client.ID)
			}

			// Assert OAuth2 client list equality.
			actual, err := testClients.user.GetOAuth2Clients(ctx, nil)
			requireNotNilAndNoProblems(t, actual, err)
			assert.True(
				t,
				len(expected) <= len(actual.Data),
				"expected %d to be <= %d",
				len(expected),
				len(actual.Data),
			)

			// Clean up.
			for _, createdOAuth2ClientID := range expected {
				assert.NoError(t, testClients.admin.ArchiveOAuth2Client(ctx, createdOAuth2ClientID))
			}
		}
	})
}

func (s *TestSuite) TestOAuth2Clients_Reading_Returns404ForNonexistentOAuth2Client() {
	s.runForCookieClient("should not be possible to read non-existent OAuth2 clients", func(testClients *testClientWrapper) func() {
		return func() {
			t := s.T()

			ctx, span := tracing.StartCustomSpan(s.ctx, t.Name())
			defer span.End()

			// Attempt to fetch nonexistent OAuth2 client.
			_, err := testClients.user.GetOAuth2Client(ctx, nonexistentID)
			assert.Error(t, err)
		}
	})
}

func (s *TestSuite) TestOAuth2Clients_Reading() {
	s.runForCookieClient("should be possible to read OAuth2 clients", func(testClients *testClientWrapper) func() {
		return func() {
			t := s.T()

			ctx, span := tracing.StartCustomSpan(s.ctx, t.Name())
			defer span.End()

			// Create OAuth2 client.
			exampleOAuth2Client := fakes.BuildFakeOAuth2Client()
			exampleOAuth2ClientInput := converters.ConvertOAuth2ClientToOAuth2ClientCreationInput(exampleOAuth2Client)

			createdOAuth2Client, err := testClients.admin.CreateOAuth2Client(ctx, exampleOAuth2ClientInput)
			requireNotNilAndNoProblems(t, createdOAuth2Client, err)

			// Fetch OAuth2 client.
			actual, err := testClients.user.GetOAuth2Client(ctx, createdOAuth2Client.ID)
			requireNotNilAndNoProblems(t, actual, err)

			// Assert OAuth2 client equality.
			checkOAuth2ClientEquality(t, exampleOAuth2Client, actual)

			// Clean up OAuth2 client.
			assert.NoError(t, testClients.admin.ArchiveOAuth2Client(ctx, createdOAuth2Client.ID))
		}
	})
}

func (s *TestSuite) TestOAuth2Clients_Archiving() {
	s.runForCookieClient("should be possible to archive OAuth2 clients", func(testClients *testClientWrapper) func() {
		return func() {
			t := s.T()

			ctx, span := tracing.StartCustomSpan(s.ctx, t.Name())
			defer span.End()

			// Create OAuth2 client.
			exampleOAuth2Client := fakes.BuildFakeOAuth2Client()
			exampleOAuth2ClientInput := converters.ConvertOAuth2ClientToOAuth2ClientCreationInput(exampleOAuth2Client)

			createdOAuth2Client, err := testClients.admin.CreateOAuth2Client(ctx, exampleOAuth2ClientInput)
			requireNotNilAndNoProblems(t, createdOAuth2Client, err)

			// Clean up OAuth2 client.
			assert.NoError(t, testClients.admin.ArchiveOAuth2Client(ctx, createdOAuth2Client.ID))
		}
	})
}
