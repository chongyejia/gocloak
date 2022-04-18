package api

import (
	"context"
	"github.com/chongyejia/gocloak/v11"
)

type IClientRoles interface {

	// *** Client Roles ***

	// AddClientRoleToUser adds a client role to the user
	AddClientRoleToUser(ctx context.Context, token, realm, idOfClient, userID string, roles []gocloak.Role) error
	// AddClientRoleToGroup adds a client role to the group
	AddClientRoleToGroup(ctx context.Context, token, realm, idOfClient, groupID string, roles []gocloak.Role) error
	// CreateClientRole creates a new role for a client
	CreateClientRole(ctx context.Context, accessToken, realm, idOfClient string, role gocloak.Role) (string, error)
	// DeleteClientRole deletes the given role
	DeleteClientRole(ctx context.Context, accessToken, realm, idOfClient, roleName string) error
	// DeleteClientRoleFromUser removes a client role from from the user
	DeleteClientRoleFromUser(ctx context.Context, token, realm, idOfClient, userID string, roles []gocloak.Role) error
	// DeleteClientRoleFromGroup removes a client role from from the group
	DeleteClientRoleFromGroup(ctx context.Context, token, realm, idOfClient, groupID string, roles []gocloak.Role) error
	// GetClientRoles gets roles for the given client
	GetClientRoles(ctx context.Context, accessToken, realm, idOfClient string, params gocloak.GetRoleParams) ([]*gocloak.Role, error)
	// GetClientRoleById gets role for the given client using role id
	GetClientRoleByID(ctx context.Context, accessToken, realm, roleID string) (*gocloak.Role, error)
	// GetRealmRolesByUserID returns all client roles assigned to the given user
	GetClientRolesByUserID(ctx context.Context, token, realm, idOfClient, userID string) ([]*gocloak.Role, error)
	// GetClientRolesByGroupID returns all client roles assigned to the given group
	GetClientRolesByGroupID(ctx context.Context, token, realm, idOfClient, groupID string) ([]*gocloak.Role, error)
	// GetCompositeClientRolesByRoleID returns all client composite roles associated with the given client role
	GetCompositeClientRolesByRoleID(ctx context.Context, token, realm, idOfClient, roleID string) ([]*gocloak.Role, error)
	// GetCompositeClientRolesByUserID returns all client roles and composite roles assigned to the given user
	GetCompositeClientRolesByUserID(ctx context.Context, token, realm, idOfClient, userID string) ([]*gocloak.Role, error)
	// GetCompositeClientRolesByGroupID returns all client roles and composite roles assigned to the given group
	GetCompositeClientRolesByGroupID(ctx context.Context, token, realm, idOfClient, groupID string) ([]*gocloak.Role, error)
	// GetAvailableClientRolesByUserID returns all available client roles to the given user
	GetAvailableClientRolesByUserID(ctx context.Context, token, realm, idOfClient, userID string) ([]*gocloak.Role, error)
	// GetAvailableClientRolesByGroupID returns all available client roles to the given group
	GetAvailableClientRolesByGroupID(ctx context.Context, token, realm, idOfClient, groupID string) ([]*gocloak.Role, error)

	// GetClientRole get a role for the given client in a realm by role name
	GetClientRole(ctx context.Context, token, realm, idOfClient, roleName string) (*gocloak.Role, error)
	// AddClientRoleComposite adds roles as composite
	AddClientRoleComposite(ctx context.Context, token, realm, roleID string, roles []gocloak.Role) error
	// DeleteClientRoleComposite deletes composites from a role
	DeleteClientRoleComposite(ctx context.Context, token, realm, roleID string, roles []gocloak.Role) error
}
