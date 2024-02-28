package launchdarkly

import (
	"github.com/launchdarkly/go-sdk-common/v3/ldcontext"
	"github.com/stretchr/testify/mock"
)

var _ launchDarklyClient = (*mockClient)(nil)

type mockClient struct {
	mock.Mock
}

// BoolVariation satisfies the launchDarklyClient interface.
func (m *mockClient) BoolVariation(key string, context ldcontext.Context, defaultVal bool) (bool, error) {
	args := m.Called(key, context, defaultVal)
	return args.Bool(0), args.Error(1)
}

// Identify satisfies the launchDarklyClient interface.
func (m *mockClient) Identify(ctx ldcontext.Context) error {
	return m.Called(ctx).Error(0)
}

// Close satisfies the launchDarklyClient interface.
func (m *mockClient) Close() error {
	return m.Called().Error(0)
}
