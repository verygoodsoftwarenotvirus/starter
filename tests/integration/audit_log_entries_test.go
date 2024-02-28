package integration

import (
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"

	"github.com/stretchr/testify/assert"
)

func (s *TestSuite) TestAuditLogEntries_Listing() {
	s.runForEachClient("should be able to be read in a list", func(testClients *testClientWrapper) func() {
		return func() {
			t := s.T()

			ctx, span := tracing.StartCustomSpan(s.ctx, t.Name())
			defer span.End()

			actual, err := testClients.user.GetAuditLogEntriesForUser(ctx)
			requireNotNilAndNoProblems(t, actual, err)

			assert.Equal(t, 4, len(actual.Data))

			actual, err = testClients.user.GetAuditLogEntriesForAccount(ctx)
			requireNotNilAndNoProblems(t, actual, err)

			assert.Equal(t, 2, len(actual.Data))
		}
	})
}

func (s *TestSuite) TestWebhooks_Retrieving_Returns404ForNonexistentAuditLogEntry() {
	s.runForEachClient("should error when archiving a non-existent auditLogEntry", func(testClients *testClientWrapper) func() {
		return func() {
			t := s.T()

			ctx, span := tracing.StartCustomSpan(s.ctx, t.Name())
			defer span.End()

			actual, err := testClients.user.GetAuditLogEntry(ctx, nonexistentID)
			assert.Nil(t, actual)
			assert.Error(t, err)
		}
	})
}
