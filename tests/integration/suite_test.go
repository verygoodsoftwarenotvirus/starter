package integration

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/apiclient"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

const (
	cookieAuthType = "cookie"
	oauth2AuthType = "oauth2"
)

var (
	globalClientExceptions []string
)

type testClientWrapper struct {
	user     *apiclient.Client
	admin    *apiclient.Client
	authType string
}

func TestIntegration(t *testing.T) {
	t.Parallel()

	suite.Run(t, new(TestSuite))
}

type TestSuite struct {
	suite.Suite

	ctx    context.Context
	user   *types.User
	cookie *http.Cookie
	cookieClient,
	oauthedClient,
	adminCookieClient,
	adminOAuthedClient *apiclient.Client
}

var _ suite.SetupTestSuite = (*TestSuite)(nil)

func (s *TestSuite) SetupTest() {
	t := s.T()
	testName := t.Name()

	ctx, span := tracing.StartCustomSpan(context.Background(), testName)
	defer span.End()

	s.ctx, _ = tracing.StartCustomSpan(ctx, testName)
	s.user, s.cookie, s.cookieClient, s.oauthedClient = createUserAndClientForTest(s.ctx, t, nil)
	s.adminCookieClient, s.adminOAuthedClient = buildAdminCookieAndOAuthedClients(s.ctx, t)
}

func (s *TestSuite) runForCookieClient(name string, subtestBuilder func(*testClientWrapper) func()) {
	s.runForEachClientExcept(name, subtestBuilder, oauth2AuthType)
}

func (s *TestSuite) runForOAuth2Client(name string, subtestBuilder func(*testClientWrapper) func()) {
	s.runForEachClientExcept(name, subtestBuilder, cookieAuthType)
}

func (s *TestSuite) runForEachClient(name string, subtestBuilder func(*testClientWrapper) func()) {
	s.runForEachClientExcept(name, subtestBuilder)
}

func (s *TestSuite) runForEachClientExcept(name string, subtestBuilder func(*testClientWrapper) func(), exceptions ...string) {
	for a, c := range s.eachClientExcept(exceptions...) {
		authType, testClients := a, c
		s.Run(fmt.Sprintf("%s via %s", name, authType), subtestBuilder(testClients))
	}
}

func (s *TestSuite) eachClientExcept(exceptions ...string) map[string]*testClientWrapper {
	t := s.T()

	clients := map[string]*testClientWrapper{
		cookieAuthType: {authType: cookieAuthType, user: s.cookieClient, admin: s.adminCookieClient},
		oauth2AuthType: {authType: oauth2AuthType, user: s.oauthedClient, admin: s.adminOAuthedClient},
	}

	for _, name := range exceptions {
		delete(clients, name)
	}

	for _, name := range globalClientExceptions {
		delete(clients, name)
	}

	require.NotEmpty(t, clients)

	return clients
}
