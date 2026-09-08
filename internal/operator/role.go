package operator

import "fmt"

// Role represents a typed operator role in the system.
type Role string

const (
	RoleViewer   Role = "viewer"
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
)

// Permission represents a typed authorization action within the RBAC model.
type Permission string

const (
	PermissionServersRead       Permission = "servers.read"
	PermissionOperationsExecute Permission = "operations.execute"
	PermissionOperatorsManage   Permission = "operators.manage"
	PermissionAuditRead         Permission = "audit.read"
)

// ParseRole validates and converts an input string to a typed Role fail-closed.
func ParseRole(s string) (Role, error) {
	switch Role(s) {
	case RoleViewer:
		return RoleViewer, nil
	case RoleOperator:
		return RoleOperator, nil
	case RoleAdmin:
		return RoleAdmin, nil
	default:
		return "", fmt.Errorf("unknown role: %q", s)
	}
}

// Valid checks if the role is one of the recognized operator roles.
func (r Role) Valid() bool {
	return r == RoleViewer || r == RoleOperator || r == RoleAdmin
}

// HasPermission performs an explicit matrix lookup for permissions fail-closed.
// Unknown roles or unknown permissions authorize nothing.
func (r Role) HasPermission(p Permission) bool {
	switch r {
	case RoleViewer:
		return p == PermissionServersRead
	case RoleOperator:
		return p == PermissionServersRead || p == PermissionOperationsExecute
	case RoleAdmin:
		return p == PermissionServersRead ||
			p == PermissionOperationsExecute ||
			p == PermissionOperatorsManage ||
			p == PermissionAuditRead
	default:
		return false
	}
}
