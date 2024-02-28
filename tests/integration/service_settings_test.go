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

func checkServiceSettingEquality(t *testing.T, expected, actual *types.ServiceSetting) {
	t.Helper()

	assert.NotZero(t, actual.ID)
	assert.Equal(t, expected.Name, actual.Name, "expected Name for service setting %s to be %v, but it was %v", expected.ID, expected.Name, actual.Name)
	assert.Equal(t, expected.Description, actual.Description, "expected Description for service setting %s to be %v, but it was %v", expected.ID, expected.Description, actual.Description)
	assert.Equal(t, expected.Type, actual.Type, "expected Type for service setting %s to be %v, but it was %v", expected.ID, expected.Type, actual.Type)
	assert.Equal(t, expected.Enumeration, actual.Enumeration, "expected Enumeration for service setting %s to be %v, but it was %v", expected.ID, expected.Enumeration, actual.Enumeration)
	assert.Equal(t, expected.AdminsOnly, actual.AdminsOnly, "expected AdminsOnly for service setting %s to be %v, but it was %v", expected.ID, expected.AdminsOnly, actual.AdminsOnly)
	assert.NotZero(t, actual.CreatedAt)
}

func createServiceSettingForTest(t *testing.T, ctx context.Context, adminClient *apiclient.Client) *types.ServiceSetting {
	t.Helper()

	exampleServiceSetting := fakes.BuildFakeServiceSetting()
	exampleServiceSettingInput := converters.ConvertServiceSettingToServiceSettingCreationRequestInput(exampleServiceSetting)
	createdServiceSetting, err := adminClient.CreateServiceSetting(ctx, exampleServiceSettingInput)
	require.NoError(t, err)
	checkServiceSettingEquality(t, exampleServiceSetting, createdServiceSetting)

	createdServiceSetting, err = adminClient.GetServiceSetting(ctx, createdServiceSetting.ID)
	requireNotNilAndNoProblems(t, createdServiceSetting, err)
	checkServiceSettingEquality(t, exampleServiceSetting, createdServiceSetting)

	return createdServiceSetting
}

func (s *TestSuite) TestServiceSettings_CompleteLifecycle() {
	s.runForEachClient("should be creatable and readable and updatable and deletable", func(testClients *testClientWrapper) func() {
		return func() {
			t := s.T()

			ctx, span := tracing.StartCustomSpan(s.ctx, t.Name())
			defer span.End()

			createdServiceSetting := createServiceSettingForTest(t, ctx, testClients.admin)

			assert.NoError(t, testClients.admin.ArchiveServiceSetting(ctx, createdServiceSetting.ID))
		}
	})
}

func (s *TestSuite) TestServiceSettings_Listing() {
	s.runForEachClient("should be readable in paginated form", func(testClients *testClientWrapper) func() {
		return func() {
			t := s.T()

			ctx, span := tracing.StartCustomSpan(s.ctx, t.Name())
			defer span.End()

			var expected []*types.ServiceSetting
			for i := 0; i < 5; i++ {
				exampleServiceSetting := fakes.BuildFakeServiceSetting()
				exampleServiceSettingInput := converters.ConvertServiceSettingToServiceSettingCreationRequestInput(exampleServiceSetting)
				createdServiceSetting, createdServiceSettingErr := testClients.admin.CreateServiceSetting(ctx, exampleServiceSettingInput)
				require.NoError(t, createdServiceSettingErr)

				checkServiceSettingEquality(t, exampleServiceSetting, createdServiceSetting)

				expected = append(expected, createdServiceSetting)
			}

			// assert service setting list equality
			actual, err := testClients.admin.GetServiceSettings(ctx, nil)
			requireNotNilAndNoProblems(t, actual, err)
			assert.True(
				t,
				len(expected) <= len(actual.Data),
				"expected %d to be <= %d",
				len(expected),
				len(actual.Data),
			)

			for _, createdServiceSetting := range expected {
				assert.NoError(t, testClients.admin.ArchiveServiceSetting(ctx, createdServiceSetting.ID))
			}
		}
	})
}
