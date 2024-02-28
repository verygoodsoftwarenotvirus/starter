package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestQuerier_Migrate(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		exampleCreationTime := fakes.BuildFakeTime()

		exampleUser := fakes.BuildFakeUser()
		exampleUser.TwoFactorSecretVerifiedAt = nil
		exampleUser.CreatedAt = exampleCreationTime

		ctx := context.Background()
		c, db := buildTestClient(t)

		c.timeFunc = func() time.Time {
			return exampleCreationTime
		}

		// called by c.IsReady()
		db.ExpectPing()

		c.migrateOnce.Do(func() {})

		err := c.Migrate(ctx, time.Second, 1)
		assert.NoError(t, err)

		mock.AssertExpectationsForObjects(t, db)
	})
}
