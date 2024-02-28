package requests

import (
	"net/http"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/pkg/types"
	"github.com/verygoodsoftwarenotvirus/starter/pkg/types/fakes"

	"github.com/stretchr/testify/assert"
)

func TestBuilder_BuildUserAccountStatusUpdateInputRequest(T *testing.T) {
	T.Parallel()

	const expectedPathFormat = "/api/v1/admin/users/status"

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		exampleInput := fakes.BuildFakeUserAccountStatusUpdateInputFromUser(helper.exampleUser)
		spec := newRequestSpec(false, http.MethodPost, "", expectedPathFormat)

		actual, err := helper.builder.BuildUserAccountStatusUpdateInputRequest(helper.ctx, exampleInput)
		assert.NoError(t, err)

		assertRequestQuality(t, actual, spec)
	})

	T.Run("with nil input", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		actual, err := helper.builder.BuildUserAccountStatusUpdateInputRequest(helper.ctx, nil)
		assert.Error(t, err)
		assert.Nil(t, actual)
	})

	T.Run("with invalid input", func(t *testing.T) {
		t.Parallel()

		helper := buildTestHelper()

		actual, err := helper.builder.BuildUserAccountStatusUpdateInputRequest(helper.ctx, &types.UserAccountStatusUpdateInput{})
		assert.Error(t, err)
		assert.Nil(t, actual)
	})
}
