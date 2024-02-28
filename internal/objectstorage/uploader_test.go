package objectstorage

import (
	"context"
	"net/http"
	"os"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/tracing"
	mockrouting "github.com/verygoodsoftwarenotvirus/starter/internal/routing/mock"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestConfig_ValidateWithContext(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		cfg := &Config{
			BucketName:       t.Name(),
			Provider:         FilesystemProvider,
			FilesystemConfig: &FilesystemConfig{RootDirectory: t.Name()},
		}

		assert.NoError(t, cfg.ValidateWithContext(ctx))
	})
}

func TestNewUploadManager(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		l := logging.NewNoopLogger()
		cfg := &Config{
			BucketName: t.Name(),
			Provider:   MemoryProvider,
		}
		rpm := &mockrouting.RouteParamManager{}
		rpm.On("BuildRouteParamStringIDFetcher", cfg.UploadFilenameKey).Return(func(*http.Request) string { return t.Name() })

		x, err := NewUploadManager(ctx, l, tracing.NewNoopTracerProvider(), cfg, rpm)
		assert.NotNil(t, x)
		assert.NoError(t, err)

		mock.AssertExpectationsForObjects(t, rpm)
	})

	T.Run("with nil config", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		l := logging.NewNoopLogger()
		rpm := &mockrouting.RouteParamManager{}

		x, err := NewUploadManager(ctx, l, tracing.NewNoopTracerProvider(), nil, rpm)
		assert.Nil(t, x)
		assert.Error(t, err)

		mock.AssertExpectationsForObjects(t, rpm)
	})

	T.Run("with invalid config", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		l := logging.NewNoopLogger()
		cfg := &Config{}
		rpm := &mockrouting.RouteParamManager{}
		rpm.On("BuildRouteParamStringIDFetcher", cfg.UploadFilenameKey).Return(func(*http.Request) string { return t.Name() })

		x, err := NewUploadManager(ctx, l, tracing.NewNoopTracerProvider(), cfg, rpm)
		assert.Nil(t, x)
		assert.Error(t, err)

		mock.AssertExpectationsForObjects(t, rpm)
	})
}

func TestUploader_selectBucket(T *testing.T) {
	T.Parallel()

	T.Run("s3 happy path", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		u := &Uploader{}
		cfg := &Config{
			Provider: S3Provider,
			S3Config: &S3Config{
				BucketName: t.Name(),
			},
		}

		assert.NoError(t, u.selectBucket(ctx, cfg))
	})

	T.Run("s3 with nil config", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		u := &Uploader{}
		cfg := &Config{
			Provider: S3Provider,
			S3Config: nil,
		}

		assert.Error(t, u.selectBucket(ctx, cfg))
	})

	T.Run("memory provider", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		u := &Uploader{}
		cfg := &Config{
			Provider: MemoryProvider,
		}

		assert.NoError(t, u.selectBucket(ctx, cfg))
	})

	T.Run("filesystem happy path", func(t *testing.T) {
		t.Parallel()

		tempDir := os.TempDir()

		ctx := context.Background()
		u := &Uploader{}
		cfg := &Config{
			Provider: FilesystemProvider,
			FilesystemConfig: &FilesystemConfig{
				RootDirectory: tempDir,
			},
		}

		assert.NoError(t, u.selectBucket(ctx, cfg))
	})

	T.Run("filesystem with nil config", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		u := &Uploader{}
		cfg := &Config{
			Provider:         FilesystemProvider,
			FilesystemConfig: nil,
		}

		assert.Error(t, u.selectBucket(ctx, cfg))
	})
}
