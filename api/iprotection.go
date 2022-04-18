package api

import (
	"context"
	"github.com/chongyejia/gocloak/v11"
)

type IProtection interface {
	// *** Protection API ***
	// GetResource returns a client's resource with the given id, using access token from client
	GetResourceClient(ctx context.Context, token, realm, resourceID string) (*gocloak.ResourceRepresentation, error)
	// GetResources a returns resources associated with the client, using access token from client
	GetResourcesClient(ctx context.Context, token, realm string, params gocloak.GetResourceParams) ([]*gocloak.ResourceRepresentation, error)
	// CreateResource creates a resource associated with the client, using access token from client
	CreateResourceClient(ctx context.Context, token, realm string, resource gocloak.ResourceRepresentation) (*gocloak.ResourceRepresentation, error)
	// UpdateResource updates a resource associated with the client, using access token from client
	UpdateResourceClient(ctx context.Context, token, realm string, resource gocloak.ResourceRepresentation) error
	// DeleteResource deletes a resource associated with the client, using access token from client
	DeleteResourceClient(ctx context.Context, token, realm, resourceID string) error

	// GetResource returns a client's resource with the given id, using access token from admin
	GetResource(ctx context.Context, token, realm, idOfClient, resourceID string) (*gocloak.ResourceRepresentation, error)
	// GetResources a returns resources associated with the client, using access token from admin
	GetResources(ctx context.Context, token, realm, idOfClient string, params gocloak.GetResourceParams) ([]*gocloak.ResourceRepresentation, error)
	// CreateResource creates a resource associated with the client, using access token from admin
	CreateResource(ctx context.Context, token, realm, idOfClient string, resource gocloak.ResourceRepresentation) (*gocloak.ResourceRepresentation, error)
	// UpdateResource updates a resource associated with the client, using access token from admin
	UpdateResource(ctx context.Context, token, realm, idOfClient string, resource gocloak.ResourceRepresentation) error
	// DeleteResource deletes a resource associated with the client, using access token from admin
	DeleteResource(ctx context.Context, token, realm, idOfClient, resourceID string) error

	// GetScope returns a client's scope with the given id, using access token from admin
	GetScope(ctx context.Context, token, realm, idOfClient, scopeID string) (*gocloak.ScopeRepresentation, error)
	// GetScopes returns scopes associated with the client, using access token from admin
	GetScopes(ctx context.Context, token, realm, idOfClient string, params gocloak.GetScopeParams) ([]*gocloak.ScopeRepresentation, error)
	// CreateScope creates a scope associated with the client, using access token from admin
	CreateScope(ctx context.Context, token, realm, idOfClient string, scope gocloak.ScopeRepresentation) (*gocloak.ScopeRepresentation, error)
	// UpdateScope updates a scope associated with the client, using access token from admin
	UpdateScope(ctx context.Context, token, realm, idOfClient string, resource gocloak.ScopeRepresentation) error
	// DeleteScope deletes a scope associated with the client, using access token from admin
	DeleteScope(ctx context.Context, token, realm, idOfClient, scopeID string) error

	// CreatePermissionTicket creates a permission ticket for a resource, using access token from client (typically a resource server)
	CreatePermissionTicket(ctx context.Context, token, realm string, permissions []gocloak.CreatePermissionTicketParams) (*gocloak.PermissionTicketResponseRepresentation, error)
	// GrantUserPermission lets resource owner grant permission for specific resource ID to specific user ID
	GrantUserPermission(ctx context.Context, token, realm string, permission gocloak.PermissionGrantParams) (*gocloak.PermissionGrantResponseRepresentation, error)
	// GrantPermission lets resource owner update permission for specific resource ID to specific user ID
	UpdateUserPermission(ctx context.Context, token, realm string, permission gocloak.PermissionGrantParams) (*gocloak.PermissionGrantResponseRepresentation, error)
	// GetUserPermission gets granted permissions according query parameters
	GetUserPermissions(ctx context.Context, token, realm string, params gocloak.GetUserPermissionParams) ([]*gocloak.PermissionGrantResponseRepresentation, error)
	// DeleteUserPermission lets resource owner delete permission for specific resource ID to specific user ID
	DeleteUserPermission(ctx context.Context, token, realm, ticketID string) error

	// GetPermission returns a client's permission with the given id
	GetPermission(ctx context.Context, token, realm, idOfClient, permissionID string) (*gocloak.PermissionRepresentation, error)
	// GetPermissions returns permissions associated with the client
	GetPermissions(ctx context.Context, token, realm, idOfClient string, params gocloak.GetPermissionParams) ([]*gocloak.PermissionRepresentation, error)
	// CreatePermission creates a permission associated with the client
	CreatePermission(ctx context.Context, token, realm, idOfClient string, permission gocloak.PermissionRepresentation) (*gocloak.PermissionRepresentation, error)
	// UpdatePermission updates a permission associated with the client
	UpdatePermission(ctx context.Context, token, realm, idOfClient string, permission gocloak.PermissionRepresentation) error
	// DeletePermission deletes a permission associated with the client
	DeletePermission(ctx context.Context, token, realm, idOfClient, permissionID string) error
	// GetDependentPermissions returns client's permissions dependent on the policy with given ID
	GetDependentPermissions(ctx context.Context, token, realm, idOfClient, policyID string) ([]*gocloak.PermissionRepresentation, error)
	GetPermissionResources(ctx context.Context, token, realm, idOfClient, permissionID string) ([]*gocloak.PermissionResource, error)
	GetPermissionScopes(ctx context.Context, token, realm, idOfClient, permissionID string) ([]*gocloak.PermissionScope, error)

	// GetPolicy returns a client's policy with the given id, using access token from admin
	GetPolicy(ctx context.Context, token, realm, idOfClient, policyID string) (*gocloak.PolicyRepresentation, error)
	// GetPolicies returns policies associated with the client, using access token from admin
	GetPolicies(ctx context.Context, token, realm, idOfClient string, params gocloak.GetPolicyParams) ([]*gocloak.PolicyRepresentation, error)
	// CreatePolicy creates a policy associated with the client, using access token from admin
	CreatePolicy(ctx context.Context, token, realm, idOfClient string, policy gocloak.PolicyRepresentation) (*gocloak.PolicyRepresentation, error)
	// UpdatePolicy updates a policy associated with the client, using access token from admin
	UpdatePolicy(ctx context.Context, token, realm, idOfClient string, policy gocloak.PolicyRepresentation) error
	// DeletePolicy deletes a policy associated with the client, using access token from admin
	DeletePolicy(ctx context.Context, token, realm, idOfClient, policyID string) error
	// GetPolicyAssociatedPolicies returns a client's policy associated policies with the given policy id, using access token from admin
	GetAuthorizationPolicyAssociatedPolicies(ctx context.Context, token, realm, idOfClient, policyID string) ([]*gocloak.PolicyRepresentation, error)
	// GetPolicyResources returns a client's resources of specific policy with the given policy id, using access token from admin
	GetAuthorizationPolicyResources(ctx context.Context, token, realm, idOfClient, policyID string) ([]*gocloak.PolicyResourceRepresentation, error)
	// GetPolicyScopes returns a client's scopes of specific policy with the given policy id, using access token from admin
	GetAuthorizationPolicyScopes(ctx context.Context, token, realm, idOfClient, policyID string) ([]*gocloak.PolicyScopeRepresentation, error)

	// GetResourcePolicy updates a permission for a specifc resource, using token obtained by Resource Owner Password Credentials Grant or Token exchange
	GetResourcePolicy(ctx context.Context, token, realm, permissionID string) (*gocloak.ResourcePolicyRepresentation, error)
	// GetResources returns resources associated with the client, using token obtained by Resource Owner Password Credentials Grant or Token exchange
	GetResourcePolicies(ctx context.Context, token, realm string, params gocloak.GetResourcePoliciesParams) ([]*gocloak.ResourcePolicyRepresentation, error)
	// GetResources returns all resources associated with the client, using token obtained by Resource Owner Password Credentials Grant or Token exchange
	CreateResourcePolicy(ctx context.Context, token, realm, resourceID string, policy gocloak.ResourcePolicyRepresentation) (*gocloak.ResourcePolicyRepresentation, error)
	// UpdateResourcePolicy updates a permission for a specifc resource, using token obtained by Resource Owner Password Credentials Grant or Token exchange
	UpdateResourcePolicy(ctx context.Context, token, realm, permissionID string, policy gocloak.ResourcePolicyRepresentation) error
	// DeleteResourcePolicy deletes a permission for a specifc resource, using token obtained by Resource Owner Password Credentials Grant or Token exchange
	DeleteResourcePolicy(ctx context.Context, token, realm, permissionID string) error
}
