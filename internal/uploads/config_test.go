package uploads

import (
	"context"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/internal/objectstorage"

	"github.com/stretchr/testify/assert"
)

func TestConfig_ValidateWithContext(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		cfg := &Config{
			Storage: objectstorage.Config{
				FilesystemConfig:  &objectstorage.FilesystemConfig{RootDirectory: "/blah"},
				S3Config:          &objectstorage.S3Config{BucketName: "blahs"},
				BucketName:        "blahs",
				UploadFilenameKey: "blahs",
				Provider:          "blahs",
			},
			Debug: false,
		}

		assert.NoError(t, cfg.ValidateWithContext(ctx))
	})
}
