package authorization

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestServiceRoles(T *testing.T) {
	T.Parallel()

	T.Run("service user", func(t *testing.T) {
		t.Parallel()

		r := NewServiceRolePermissionChecker(ServiceUserRole.String())

		assert.False(t, r.IsServiceAdmin())
	})

	T.Run("service admin", func(t *testing.T) {
		t.Parallel()

		r := NewServiceRolePermissionChecker(ServiceAdminRole.String())

		assert.True(t, r.IsServiceAdmin())
	})

	T.Run("both", func(t *testing.T) {
		t.Parallel()

		r := NewServiceRolePermissionChecker(ServiceUserRole.String(), ServiceAdminRole.String())

		assert.True(t, r.IsServiceAdmin())
	})
}
