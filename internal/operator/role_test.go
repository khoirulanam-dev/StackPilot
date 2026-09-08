package operator

import (
	"testing"
)

func TestRole_ParseRole(t *testing.T) {
	cases := []struct {
		input       string
		expected    Role
		expectError bool
	}{
		{"viewer", RoleViewer, false},
		{"operator", RoleOperator, false},
		{"admin", RoleAdmin, false},
		{"", "", true},
		{"ADMIN", "", true},
		{"superuser", "", true},
		{"root", "", true},
		{"guest", "", true},
	}

	for _, tc := range cases {
		r, err := ParseRole(tc.input)
		if tc.expectError {
			if err == nil {
				t.Errorf("ParseRole(%q): expected error, got nil", tc.input)
			}
		} else {
			if err != nil {
				t.Errorf("ParseRole(%q): unexpected error: %v", tc.input, err)
			}
			if r != tc.expected {
				t.Errorf("ParseRole(%q): expected %q, got %q", tc.input, tc.expected, r)
			}
			if !r.Valid() {
				t.Errorf("Role(%q).Valid(): expected true, got false", r)
			}
		}
	}
}

func TestRole_RBACMatrix(t *testing.T) {
	t.Run("viewer role permissions", func(t *testing.T) {
		if !RoleViewer.HasPermission(PermissionServersRead) {
			t.Error("viewer must have servers.read")
		}
		if RoleViewer.HasPermission(PermissionOperationsExecute) {
			t.Error("viewer must not have operations.execute")
		}
		if RoleViewer.HasPermission(PermissionOperatorsManage) {
			t.Error("viewer must not have operators.manage")
		}
		if RoleViewer.HasPermission(PermissionAuditRead) {
			t.Error("viewer must not have audit.read")
		}
	})

	t.Run("operator role permissions", func(t *testing.T) {
		if !RoleOperator.HasPermission(PermissionServersRead) {
			t.Error("operator must have servers.read")
		}
		if !RoleOperator.HasPermission(PermissionOperationsExecute) {
			t.Error("operator must have operations.execute")
		}
		if RoleOperator.HasPermission(PermissionOperatorsManage) {
			t.Error("operator must not have operators.manage")
		}
		if RoleOperator.HasPermission(PermissionAuditRead) {
			t.Error("operator must not have audit.read")
		}
	})

	t.Run("admin role permissions", func(t *testing.T) {
		if !RoleAdmin.HasPermission(PermissionServersRead) {
			t.Error("admin must have servers.read")
		}
		if !RoleAdmin.HasPermission(PermissionOperationsExecute) {
			t.Error("admin must have operations.execute")
		}
		if !RoleAdmin.HasPermission(PermissionOperatorsManage) {
			t.Error("admin must have operators.manage")
		}
		if !RoleAdmin.HasPermission(PermissionAuditRead) {
			t.Error("admin must have audit.read")
		}
	})

	// Security invariant: Unrecognized roles fail closed and deny all permissions.
	t.Run("unknown role fails closed for all permissions", func(t *testing.T) {
		unknownRole := Role("custom_role")
		allPerms := []Permission{
			PermissionServersRead,
			PermissionOperationsExecute,
			PermissionOperatorsManage,
			PermissionAuditRead,
		}
		for _, p := range allPerms {
			if unknownRole.HasPermission(p) {
				t.Errorf("unknown role must not authorize permission %q", p)
			}
		}
	})

	// Security invariant: Unrecognized permissions fail closed across all roles.
	t.Run("unknown permission fails closed across all roles", func(t *testing.T) {
		unknownPerm := Permission("servers.destroy")
		if RoleAdmin.HasPermission(unknownPerm) {
			t.Error("admin must not have unknown permission")
		}
		if RoleOperator.HasPermission(unknownPerm) {
			t.Error("operator must not have unknown permission")
		}
		if RoleViewer.HasPermission(unknownPerm) {
			t.Error("viewer must not have unknown permission")
		}
	})
}
