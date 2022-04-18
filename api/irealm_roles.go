package api

import (
	"context"
	"github.com/chongyejia/gocloak/v11"
)

type IRealmRoles interface {
	// *** Realm Roles ***

	// CreateRealmRole creates a role in a realm
	CreateRealmRole(ctx context.Context, token, realm string, role gocloak.Role) (string, error)
	// GetRealmRole returns a role from a realm by role's name
	GetRealmRole(ctx context.Context, token, realm, roleName string) (*gocloak.Role, error)
	// GetRealmRoleByID returns a role from a realm by role's ID
	GetRealmRoleByID(ctx context.Context, token, realm, roleID string) (*gocloak.Role, error)
	// GetRealmRoles get all roles of the given realm. It's an alias for the GetRoles function
	GetRealmRoles(ctx context.Context, accessToken, realm string, params gocloak.GetRoleParams) ([]*gocloak.Role, error)
	// GetRealmRolesByUserID returns all roles assigned to the given user
	GetRealmRolesByUserID(ctx context.Context, accessToken, realm, userID string) ([]*gocloak.Role, error)
	// GetRealmRolesByGroupID returns all roles assigned to the given group
	GetRealmRolesByGroupID(ctx context.Context, accessToken, realm, groupID string) ([]*gocloak.Role, error)
	// UpdateRealmRole updates a role in a realm
	UpdateRealmRole(ctx context.Context, token, realm, roleName string, role gocloak.Role) error
	// UpdateRealmRoleByID updates a role in a realm by role's ID
	UpdateRealmRoleByID(ctx context.Context, token, realm, roleID string, role gocloak.Role) error
	// DeleteRealmRole deletes a role in a realm by role's name
	DeleteRealmRole(ctx context.Context, token, realm, roleName string) error
	// AddRealmRoleToUser adds realm-level role mappings
	AddRealmRoleToUser(ctx context.Context, token, realm, userID string, roles []gocloak.Role) error
	// DeleteRealmRoleFromUser deletes realm-level role mappings
	DeleteRealmRoleFromUser(ctx context.Context, token, realm, userID string, roles []gocloak.Role) error
	// AddRealmRoleToGroup adds realm-level role mappings
	AddRealmRoleToGroup(ctx context.Context, token, realm, groupID string, roles []gocloak.Role) error
	// DeleteRealmRoleFromGroup deletes realm-level role mappings
	DeleteRealmRoleFromGroup(ctx context.Context, token, realm, groupID string, roles []gocloak.Role) error
	// AddRealmRoleComposite adds roles as composite
	AddRealmRoleComposite(ctx context.Context, token, realm, roleName string, roles []gocloak.Role) error
	// AddRealmRoleComposite adds roles as composite
	DeleteRealmRoleComposite(ctx context.Context, token, realm, roleName string, roles []gocloak.Role) error
	// GetCompositeRealmRoles returns all realm composite roles associated with the given realm role
	GetCompositeRealmRoles(ctx context.Context, token, realm, roleName string) ([]*gocloak.Role, error)
	// GetCompositeRealmRolesByRoleID returns all realm composite roles associated with the given client role
	GetCompositeRealmRolesByRoleID(ctx context.Context, token, realm, roleID string) ([]*gocloak.Role, error)
	// GetCompositeRealmRolesByUserID returns all realm roles and composite roles assigned to the given user
	GetCompositeRealmRolesByUserID(ctx context.Context, token, realm, userID string) ([]*gocloak.Role, error)
	// GetCompositeRealmRolesByGroupID returns all realm roles and composite roles assigned to the given group
	GetCompositeRealmRolesByGroupID(ctx context.Context, token, realm, groupID string) ([]*gocloak.Role, error)
	// GetAvailableRealmRolesByUserID returns all available realm roles to the given user
	GetAvailableRealmRolesByUserID(ctx context.Context, token, realm, userID string) ([]*gocloak.Role, error)
	// GetAvailableRealmRolesByGroupID returns all available realm roles to the given group
	GetAvailableRealmRolesByGroupID(ctx context.Context, token, realm, groupID string) ([]*gocloak.Role, error)
}
