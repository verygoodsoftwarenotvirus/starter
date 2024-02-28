package types

import (
	"context"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/internal/pkg/pointer"

	fake "github.com/brianvoe/gofakeit/v7"
	"github.com/stretchr/testify/assert"
)

func TestServiceSettingConfiguration_Update(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		x := &ServiceSettingConfiguration{}
		input := &ServiceSettingConfigurationUpdateRequestInput{}

		assert.NoError(t, fake.Struct(&input))

		x.Update(input)
	})
}

func TestServiceSettingConfigurationCreationRequestInput_ValidateWithContext(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		x := &ServiceSettingConfigurationCreationRequestInput{
			Value:         t.Name(),
			BelongsToUser: t.Name(),
		}

		actual := x.ValidateWithContext(ctx)

		assert.NoError(t, actual)
	})

	T.Run("with invalid struct", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		x := &ServiceSettingConfigurationCreationRequestInput{}

		actual := x.ValidateWithContext(ctx)

		assert.Error(t, actual)
	})
}

func TestServiceSettingConfigurationDatabaseCreationInput_ValidateWithContext(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		x := &ServiceSettingConfigurationDatabaseCreationInput{
			ID:            t.Name(),
			Value:         t.Name(),
			BelongsToUser: t.Name(),
		}

		actual := x.ValidateWithContext(ctx)

		assert.NoError(t, actual)
	})

	T.Run("with invalid struct", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		x := &ServiceSettingConfigurationDatabaseCreationInput{}

		actual := x.ValidateWithContext(ctx)

		assert.Error(t, actual)
	})
}

func TestServiceSettingConfigurationUpdateRequestInput_ValidateWithContext(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		x := &ServiceSettingConfigurationUpdateRequestInput{
			Value:            pointer.To(t.Name()),
			ServiceSettingID: pointer.To(t.Name()),
		}

		actual := x.ValidateWithContext(ctx)

		assert.NoError(t, actual)
	})

	T.Run("with invalid struct", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		x := &ServiceSettingConfigurationUpdateRequestInput{}

		actual := x.ValidateWithContext(ctx)

		assert.Error(t, actual)
	})
}
