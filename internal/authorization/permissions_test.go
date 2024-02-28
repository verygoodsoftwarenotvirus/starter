package authorization

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPermissions(T *testing.T) {
	T.Parallel()

	T.Run("account admin", func(t *testing.T) {
		t.Parallel()

		permissionChecker := NewAccountRolePermissionChecker(accountAdminRoleName)

		assert.False(t, permissionChecker.HasPermission(CycleCookieSecretPermission))
		assert.False(t, permissionChecker.HasPermission(UpdateUserStatusPermission))
		assert.False(t, permissionChecker.HasPermission(ReadUserPermission))
		assert.False(t, permissionChecker.HasPermission(SearchUserPermission))
		assert.True(t, permissionChecker.HasPermission(UpdateAccountPermission))
		assert.True(t, permissionChecker.HasPermission(ArchiveAccountPermission))
		assert.True(t, permissionChecker.HasPermission(InviteUserToAccountPermission))
		assert.True(t, permissionChecker.HasPermission(ModifyMemberPermissionsForAccountPermission))
		assert.True(t, permissionChecker.HasPermission(RemoveMemberAccountPermission))
		assert.True(t, permissionChecker.HasPermission(TransferAccountPermission))
		assert.True(t, permissionChecker.HasPermission(CreateWebhooksPermission))
		assert.True(t, permissionChecker.HasPermission(ReadWebhooksPermission))
		assert.True(t, permissionChecker.HasPermission(UpdateWebhooksPermission))
		assert.True(t, permissionChecker.HasPermission(ArchiveWebhooksPermission))
	})

	T.Run("account member", func(t *testing.T) {
		t.Parallel()

		permissionChecker := NewAccountRolePermissionChecker(accountMemberRoleName)

		assert.False(t, permissionChecker.HasPermission(CycleCookieSecretPermission))
		assert.False(t, permissionChecker.HasPermission(UpdateUserStatusPermission))
		assert.False(t, permissionChecker.HasPermission(ReadUserPermission))
		assert.False(t, permissionChecker.HasPermission(SearchUserPermission))
		assert.False(t, permissionChecker.HasPermission(UpdateAccountPermission))
		assert.False(t, permissionChecker.HasPermission(ArchiveAccountPermission))
		assert.False(t, permissionChecker.HasPermission(InviteUserToAccountPermission))
		assert.False(t, permissionChecker.HasPermission(ModifyMemberPermissionsForAccountPermission))
		assert.False(t, permissionChecker.HasPermission(RemoveMemberAccountPermission))
		assert.False(t, permissionChecker.HasPermission(TransferAccountPermission))
		assert.False(t, permissionChecker.HasPermission(CreateWebhooksPermission))
		assert.True(t, permissionChecker.HasPermission(ReadWebhooksPermission))
		assert.False(t, permissionChecker.HasPermission(UpdateWebhooksPermission))
		assert.False(t, permissionChecker.HasPermission(ArchiveWebhooksPermission))
	})
}
