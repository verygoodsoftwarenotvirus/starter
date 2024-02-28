package types

import (
	"context"
	"testing"

	"github.com/verygoodsoftwarenotvirus/starter/internal/authorization"
	"github.com/verygoodsoftwarenotvirus/starter/internal/observability/logging"

	"github.com/stretchr/testify/assert"
)

func TestChangeActiveAccountInput_ValidateWithContext(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		x := &ChangeActiveAccountInput{
			AccountID: "123",
		}

		assert.NoError(t, x.ValidateWithContext(ctx))
	})
}

func TestSessionContextData_AttachToLogger(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		x := &SessionContextData{
			Requester: RequesterInfo{ServicePermissions: authorization.NewServiceRolePermissionChecker(t.Name())},
		}

		assert.NotNil(t, x.AttachToLogger(logging.NewNoopLogger()))
	})
}

func TestSessionContextData_AccountRolePermissionsChecker(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		x := &SessionContextData{
			ActiveAccountID: t.Name(),
			AccountPermissions: map[string]authorization.AccountRolePermissionsChecker{
				t.Name(): authorization.NewAccountRolePermissionChecker(t.Name()),
			},
		}

		assert.NotNil(t, x.AccountRolePermissionsChecker())
	})
}

func TestSessionContextData_ServiceRolePermissionChecker(T *testing.T) {
	T.Parallel()

	T.Run("standard", func(t *testing.T) {
		t.Parallel()

		x := &SessionContextData{
			ActiveAccountID: t.Name(),
			Requester: RequesterInfo{
				ServicePermissions: authorization.NewServiceRolePermissionChecker(t.Name()),
			},
		}

		assert.NotNil(t, x.ServiceRolePermissionChecker())
	})
}
