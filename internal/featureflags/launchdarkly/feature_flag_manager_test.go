package launchdarkly

import (
	"context"
	"net/http"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"

	"github.com/launchdarkly/go-sdk-common/v3/ldcontext"
	ld "github.com/launchdarkly/go-server-sdk/v6"
	"github.com/launchdarkly/go-server-sdk/v6/subsystems"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeLaunchDarklyDataSource struct{}

func (f *fakeLaunchDarklyDataSource) Close() error {
	return nil
}

func (f *fakeLaunchDarklyDataSource) IsInitialized() bool {
	return true
}

func (f *fakeLaunchDarklyDataSource) Start(closeWhenReady chan<- struct{}) {
	close(closeWhenReady)
}

type fakeLaunchDarklyDataSourceBuilder struct{}

// Build is called internally by the SDK.
func (b *fakeLaunchDarklyDataSourceBuilder) Build(subsystems.ClientContext) (subsystems.DataSource, error) {
	return &fakeLaunchDarklyDataSource{}, nil
}

func TestNewFeatureFlagManager(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{SDKKey: t.Name()}

		actual, err := NewFeatureFlagManager(cfg, logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), http.DefaultClient, func(config ld.Config) ld.Config {
			config.DataSource = &fakeLaunchDarklyDataSourceBuilder{}
			return config
		})
		require.NoError(t, err)
		require.NotNil(t, actual)
	})

	T.Run("with missing http launchDarklyClient", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{SDKKey: t.Name()}

		actual, err := NewFeatureFlagManager(cfg, logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), nil)
		require.Error(t, err)
		require.Nil(t, actual)
	})

	T.Run("with nil config", func(t *testing.T) {
		t.Parallel()

		actual, err := NewFeatureFlagManager(nil, logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), http.DefaultClient)
		require.Error(t, err)
		require.Nil(t, actual)
	})

	T.Run("with missing SDK key", func(t *testing.T) {
		t.Parallel()

		cfg := &Config{}

		actual, err := NewFeatureFlagManager(cfg, logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), http.DefaultClient, func(config ld.Config) ld.Config {
			config.DataSource = &fakeLaunchDarklyDataSourceBuilder{}
			return config
		})
		require.Error(t, err)
		require.Nil(t, actual)
	})
}

func TestFeatureFlagManager_CanUseFeature(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		exampleUsername := fakes.BuildFakeUser().Username

		cfg := &Config{SDKKey: t.Name()}

		ffm, err := NewFeatureFlagManager(cfg, logging.NewNoopLogger(), tracing.NewNoopTracerProvider(), http.DefaultClient, func(config ld.Config) ld.Config {
			config.DataSource = &fakeLaunchDarklyDataSourceBuilder{}
			return config
		})
		require.NoError(t, err)

		fakeClient := &mockClient{}
		fakeClient.On("BoolVariation", t.Name(), ldcontext.New(exampleUsername), false).Return(true, nil)
		ffm.(*featureFlagManager).launchDarklyClient = fakeClient

		actual, err := ffm.CanUseFeature(ctx, exampleUsername, t.Name())
		assert.NoError(t, err)
		assert.True(t, actual)
	})
}
