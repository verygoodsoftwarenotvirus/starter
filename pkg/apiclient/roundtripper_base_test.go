package apiclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_newDefaultRoundTripper(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		rt := newDefaultRoundTripper(0)
		assert.NotNil(t, rt)
	})
}

func Test_defaultRoundTripper_RoundTrip(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()

		ts := httptest.NewServer(http.HandlerFunc(
			func(res http.ResponseWriter, req *http.Request) {
				res.WriteHeader(http.StatusOK)
			},
		))

		transport := newDefaultRoundTripper(0)
		assert.NotNil(t, transport)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL, http.NoBody)
		assert.NotNil(t, req)
		assert.NoError(t, err)

		_, err = transport.RoundTrip(req)
		assert.NoError(t, err)
	})
}

func Test_buildRequestLogHook(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		l := logging.NewNoopLogger()

		actual := buildRequestLogHook(l)

		actual(nil, &http.Request{}, 0)
	})
}

func Test_buildResponseLogHook(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		l := logging.NewNoopLogger()

		actual := buildResponseLogHook(l)

		actual(nil, &http.Response{})
	})
}

func Test_buildCheckRetryFunc(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		f := buildCheckRetryFunc(tracing.NewTracerForTest(t.Name()))

		actual, err := f(ctx, &http.Response{}, nil)
		assert.True(t, actual)
		assert.NoError(t, err)
	})
}

func Test_buildErrorHandler(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		l := logging.NewNoopLogger()

		actual := buildErrorHandler(l)

		res, err := actual(&http.Response{}, nil, 0)
		assert.NoError(t, err)
		assert.NotNil(t, res)
	})
}

func Test_buildRetryingClient(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		actual := buildRetryingClient(http.DefaultClient, nil, tracing.NewTracerForTest(t.Name()))
		require.NotNil(t, actual)
	})
}
