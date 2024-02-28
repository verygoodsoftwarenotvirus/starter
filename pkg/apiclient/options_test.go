package apiclient

import (
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_SetOptions(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		expectedURL, err := url.Parse("https://notarealplace.lol")
		require.NoError(t, err)

		c, _ := buildSimpleTestClient(t)
		assert.NotEqual(t, expectedURL, c.URL(), "expected and actual URLs match somehow")

		exampleOption := func(client *Client) error {
			client.url = expectedURL
			return nil
		}

		require.NoError(t, c.SetOptions(exampleOption))

		assert.Equal(t, expectedURL, c.URL(), "expected and actual URLs do not match")
	})

	T.Run("with error", func(t *testing.T) {
		t.Parallel()

		c, _ := buildSimpleTestClient(t)

		exampleOption := func(client *Client) error {
			return errors.New("blah")
		}

		assert.Error(t, c.SetOptions(exampleOption))
	})
}

func TestUsingJSON(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		c, err := NewClient(mustParseURL(exampleURI), tracing.NewNoopTracerProvider(), UsingJSON())
		assert.NoError(t, err)
		assert.NotNil(t, c)

		assert.Equal(t, "application/json", c.encoder.ContentType())
	})
}

func TestUsingXML(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		c, err := NewClient(mustParseURL(exampleURI), tracing.NewNoopTracerProvider(), UsingXML())
		assert.NoError(t, err)
		assert.NotNil(t, c)

		assert.Equal(t, "application/xml", c.encoder.ContentType())
	})
}

func TestUsingLogger(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		expectedURL, err := url.Parse("https://whatever.whocares.gov")
		require.NoError(t, err)

		c, err := NewClient(expectedURL, tracing.NewNoopTracerProvider(), UsingLogger(logging.NewNoopLogger()))
		assert.NotNil(t, c)
		assert.NoError(t, err)
	})
}

func TestUsingDebug(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		c, err := NewClient(mustParseURL(exampleURI), tracing.NewNoopTracerProvider(), UsingDebug(true))
		assert.NoError(t, err)
		assert.NotNil(t, c)

		assert.Equal(t, true, c.debug, "REPLACE ME")
	})
}

func TestUsingTimeout(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		expected := time.Minute

		c, err := NewClient(mustParseURL(exampleURI), tracing.NewNoopTracerProvider(), UsingTimeout(expected))
		assert.NoError(t, err)
		assert.NotNil(t, c)

		assert.Equal(t, expected, c.authedClient.Timeout)
	})

	T.Run("with fallback to default timeout", func(t *testing.T) {
		t.Parallel()

		c, err := NewClient(mustParseURL(exampleURI), tracing.NewNoopTracerProvider(), UsingTimeout(0))

		assert.NoError(t, err)
		assert.NotNil(t, c)

		assert.Equal(t, defaultTimeout, c.authedClient.Timeout)
	})
}

func TestUsingCookie(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		exampleInput := &http.Cookie{Name: t.Name()}

		c, err := NewClient(mustParseURL(exampleURI), tracing.NewNoopTracerProvider(), UsingCookie(exampleInput))
		assert.NoError(t, err)
		assert.NotNil(t, c)

		assert.True(t, c.authMethod == cookieAuthMethod)
	})

	T.Run("with nil cooki9e", func(t *testing.T) {
		t.Parallel()

		c, err := NewClient(mustParseURL(exampleURI), tracing.NewNoopTracerProvider(), UsingCookie(nil))
		assert.Error(t, err)
		assert.Nil(t, c)
	})
}
