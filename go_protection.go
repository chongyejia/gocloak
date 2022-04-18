package gocloak

import (
	"context"
	"github.com/pkg/errors"
	"net/http"
)

type Protection struct {
	client *gocloak
}

// ------------------
// Protection API
// ------------------

// GetResource returns a client's resource with the given id, using access token from admin
func (c *Protection) GetResource(ctx context.Context, token, realm, idOfClient, resourceID string) (*ResourceRepresentation, error) {
	const errMessage = "could not get resource"

	var result ResourceRepresentation
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(c.client.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "resource", resourceID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetResource returns a client's resource with the given id, using access token from client
func (c *Protection) GetResourceClient(ctx context.Context, token, realm, resourceID string) (*ResourceRepresentation, error) {
	const errMessage = "could not get resource"

	var result ResourceRepresentation
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(c.client.getRealmURL(realm, "authz", "protection", "resource_set", resourceID))

	// http://${host}:${port}/auth/realms/${realm_name}/authz/protection/resource_set/{resource_id}

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetResources returns resources associated with the client, using access token from admin
func (c *Protection) GetResources(ctx context.Context, token, realm, idOfClient string, params GetResourceParams) ([]*ResourceRepresentation, error) {
	const errMessage = "could not get resources"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, err
	}

	var result []*ResourceRepresentation
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(c.client.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "resource"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetResources returns resources associated with the client, using access token from client
func (c *Protection) GetResourcesClient(ctx context.Context, token, realm string, params GetResourceParams) ([]*ResourceRepresentation, error) {
	const errMessage = "could not get resources"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, err
	}

	var result []*ResourceRepresentation
	var resourceIDs []string
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&resourceIDs).
		SetQueryParams(queryParams).
		Get(c.client.getRealmURL(realm, "authz", "protection", "resource_set"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	for _, resourceID := range resourceIDs {
		resource, err := c.GetResourceClient(ctx, token, realm, resourceID)
		if err == nil {
			result = append(result, resource)
		}
	}

	return result, nil
}

// UpdateResource updates a resource associated with the client, using access token from admin
func (c *Protection) UpdateResource(ctx context.Context, token, realm, idOfClient string, resource ResourceRepresentation) error {
	const errMessage = "could not update resource"

	if NilOrEmpty(resource.ID) {
		return errors.New("ID of a resource required")
	}

	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetBody(resource).
		Put(c.client.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "resource", *(resource.ID)))

	return checkForError(resp, err, errMessage)
}

// UpdateResource updates a resource associated with the client, using access token from client
func (c *Protection) UpdateResourceClient(ctx context.Context, token, realm string, resource ResourceRepresentation) error {
	const errMessage = "could not update resource"

	if NilOrEmpty(resource.ID) {
		return errors.New("ID of a resource required")
	}

	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetBody(resource).
		Put(c.client.getRealmURL(realm, "authz", "protection", "resource_set", *(resource.ID)))

	return checkForError(resp, err, errMessage)
}

// CreateResource creates a resource associated with the client, using access token from admin
func (c *Protection) CreateResource(ctx context.Context, token, realm string, idOfClient string, resource ResourceRepresentation) (*ResourceRepresentation, error) {
	const errMessage = "could not create resource"

	var result ResourceRepresentation
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(resource).
		Post(c.client.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "resource"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// CreateResource creates a resource associated with the client, using access token from client
func (c *Protection) CreateResourceClient(ctx context.Context, token, realm string, resource ResourceRepresentation) (*ResourceRepresentation, error) {
	const errMessage = "could not create resource"

	var result ResourceRepresentation
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(resource).
		Post(c.client.getRealmURL(realm, "authz", "protection", "resource_set"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// DeleteResource deletes a resource associated with the client (using an admin token)
func (c *Protection) DeleteResource(ctx context.Context, token, realm, idOfClient, resourceID string) error {
	const errMessage = "could not delete resource"

	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		Delete(c.client.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "resource", resourceID))

	return checkForError(resp, err, errMessage)
}

// DeleteResource deletes a resource associated with the client (using a client token)
func (c *Protection) DeleteResourceClient(ctx context.Context, token, realm, resourceID string) error {
	const errMessage = "could not delete resource"

	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		Delete(c.client.getRealmURL(realm, "authz", "protection", "resource_set", resourceID))

	return checkForError(resp, err, errMessage)
}

// GetScope returns a client's scope with the given id
func (c *Protection) GetScope(ctx context.Context, token, realm, idOfClient, scopeID string) (*ScopeRepresentation, error) {
	const errMessage = "could not get scope"

	var result ScopeRepresentation
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(c.client.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "scope", scopeID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetScopes returns scopes associated with the client
func (c *Protection) GetScopes(ctx context.Context, token, realm, idOfClient string, params GetScopeParams) ([]*ScopeRepresentation, error) {
	const errMessage = "could not get scopes"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, err
	}
	var result []*ScopeRepresentation
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(c.client.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "scope"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// CreateScope creates a scope associated with the client
func (c *Protection) CreateScope(ctx context.Context, token, realm, idOfClient string, scope ScopeRepresentation) (*ScopeRepresentation, error) {
	const errMessage = "could not create scope"

	var result ScopeRepresentation
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(scope).
		Post(c.client.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "scope"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// UpdateScope updates a scope associated with the client
func (c *Protection) UpdateScope(ctx context.Context, token, realm, idOfClient string, scope ScopeRepresentation) error {
	const errMessage = "could not update scope"

	if NilOrEmpty(scope.ID) {
		return errors.New("ID of a scope required")
	}

	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetBody(scope).
		Put(c.client.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "scope", *(scope.ID)))

	return checkForError(resp, err, errMessage)
}

// DeleteScope deletes a scope associated with the client
func (c *Protection) DeleteScope(ctx context.Context, token, realm, idOfClient, scopeID string) error {
	const errMessage = "could not delete scope"

	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		Delete(c.client.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "scope", scopeID))

	return checkForError(resp, err, errMessage)
}

// GetPolicy returns a client's policy with the given id
func (c *Protection) GetPolicy(ctx context.Context, token, realm, idOfClient, policyID string) (*PolicyRepresentation, error) {
	const errMessage = "could not get policy"

	var result PolicyRepresentation
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(c.client.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "policy", policyID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetPolicies returns policies associated with the client
func (c *Protection) GetPolicies(ctx context.Context, token, realm, idOfClient string, params GetPolicyParams) ([]*PolicyRepresentation, error) {
	const errMessage = "could not get policies"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	path := []string{"clients", idOfClient, "authz", "resource-server", "policy"}
	if !NilOrEmpty(params.Type) {
		path = append(path, *params.Type)
	}

	var result []*PolicyRepresentation
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(c.client.getAdminRealmURL(realm, path...))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// CreatePolicy creates a policy associated with the client
func (c *Protection) CreatePolicy(ctx context.Context, token, realm, idOfClient string, policy PolicyRepresentation) (*PolicyRepresentation, error) {
	const errMessage = "could not create policy"

	if NilOrEmpty(policy.Type) {
		return nil, errors.New("type of a policy required")
	}

	var result PolicyRepresentation
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(policy).
		Post(c.client.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "policy", *(policy.Type)))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// UpdatePolicy updates a policy associated with the client
func (c *Protection) UpdatePolicy(ctx context.Context, token, realm, idOfClient string, policy PolicyRepresentation) error {
	const errMessage = "could not update policy"

	if NilOrEmpty(policy.ID) {
		return errors.New("ID of a policy required")
	}

	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetBody(policy).
		Put(c.client.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "policy", *(policy.Type), *(policy.ID)))

	return checkForError(resp, err, errMessage)
}

// DeletePolicy deletes a policy associated with the client
func (c *Protection) DeletePolicy(ctx context.Context, token, realm, idOfClient, policyID string) error {
	const errMessage = "could not delete policy"

	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		Delete(c.client.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "policy", policyID))

	return checkForError(resp, err, errMessage)
}

// GetAuthorizationPolicyAssociatedPolicies returns a client's associated policies of specific policy with the given policy id, using access token from admin
func (c *Protection) GetAuthorizationPolicyAssociatedPolicies(ctx context.Context, token, realm, idOfClient, policyID string) ([]*PolicyRepresentation, error) {
	const errMessage = "could not get policy associated policies"

	var result []*PolicyRepresentation
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(c.client.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "policy", policyID, "associatedPolicies"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetAuthorizationPolicyResources returns a client's resources of specific policy with the given policy id, using access token from admin
func (c *Protection) GetAuthorizationPolicyResources(ctx context.Context, token, realm, idOfClient, policyID string) ([]*PolicyResourceRepresentation, error) {
	const errMessage = "could not get policy resources"

	var result []*PolicyResourceRepresentation
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(c.client.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "policy", policyID, "resources"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetAuthorizationPolicyScopes returns a client's scopes of specific policy with the given policy id, using access token from admin
func (c *Protection) GetAuthorizationPolicyScopes(ctx context.Context, token, realm, idOfClient, policyID string) ([]*PolicyScopeRepresentation, error) {
	const errMessage = "could not get policy scopes"

	var result []*PolicyScopeRepresentation
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(c.client.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "policy", policyID, "scopes"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetResourcePolicy updates a permission for a specifc resource, using token obtained by Resource Owner Password Credentials Grant or Token exchange
func (c *Protection) GetResourcePolicy(ctx context.Context, token, realm, permissionID string) (*ResourcePolicyRepresentation, error) {
	const errMessage = "could not get resource policy"

	var result ResourcePolicyRepresentation
	resp, err := c.client.getRequestWithBearerAuthNoCache(ctx, token).
		SetResult(&result).
		Get(c.client.getRealmURL(realm, "authz", "protection", "uma-policy", permissionID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetResourcePolicies returns resources associated with the client, using token obtained by Resource Owner Password Credentials Grant or Token exchange
func (c *Protection) GetResourcePolicies(ctx context.Context, token, realm string, params GetResourcePoliciesParams) ([]*ResourcePolicyRepresentation, error) {
	const errMessage = "could not get resource policies"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, err
	}

	var result []*ResourcePolicyRepresentation
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(c.client.getRealmURL(realm, "authz", "protection", "uma-policy"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// CreateResourcePolicy associates a permission with a specifc resource, using token obtained by Resource Owner Password Credentials Grant or Token exchange
func (c *Protection) CreateResourcePolicy(ctx context.Context, token, realm, resourceID string, policy ResourcePolicyRepresentation) (*ResourcePolicyRepresentation, error) {
	const errMessage = "could not create resource policy"

	var result ResourcePolicyRepresentation
	resp, err := c.client.getRequestWithBearerAuthNoCache(ctx, token).
		SetResult(&result).
		SetBody(policy).
		Post(c.client.getRealmURL(realm, "authz", "protection", "uma-policy", resourceID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// UpdateResourcePolicy updates a permission for a specifc resource, using token obtained by Resource Owner Password Credentials Grant or Token exchange
func (c *Protection) UpdateResourcePolicy(ctx context.Context, token, realm, permissionID string, policy ResourcePolicyRepresentation) error {
	const errMessage = "could not update resource policy"

	resp, err := c.client.getRequestWithBearerAuthNoCache(ctx, token).
		SetBody(policy).
		Put(c.client.getRealmURL(realm, "authz", "protection", "uma-policy", permissionID))

	return checkForError(resp, err, errMessage)
}

// DeleteResourcePolicy deletes a permission for a specifc resource, using token obtained by Resource Owner Password Credentials Grant or Token exchange
func (c *Protection) DeleteResourcePolicy(ctx context.Context, token, realm, permissionID string) error {
	const errMessage = "could not  delete resource policy"

	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		Delete(c.client.getRealmURL(realm, "authz", "protection", "uma-policy", permissionID))

	return checkForError(resp, err, errMessage)
}

// GetPermission returns a client's permission with the given id
func (c *Protection) GetPermission(ctx context.Context, token, realm, idOfClient, permissionID string) (*PermissionRepresentation, error) {
	const errMessage = "could not get permission"

	var result PermissionRepresentation
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(c.client.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "permission", permissionID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetDependentPermissions returns a client's permission with the given policy id
func (c *Protection) GetDependentPermissions(ctx context.Context, token, realm, idOfClient, policyID string) ([]*PermissionRepresentation, error) {
	const errMessage = "could not get permission"

	var result []*PermissionRepresentation
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(c.client.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "policy", policyID, "dependentPolicies"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetPermissionResource returns a client's resource attached for the given permission id
func (c *Protection) GetPermissionResources(ctx context.Context, token, realm, idOfClient, permissionID string) ([]*PermissionResource, error) {
	const errMessage = "could not get permission resource"

	var result []*PermissionResource
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(c.client.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "permission", permissionID, "resources"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetPermissionScopes returns a client's scopes configured for the given permission id
func (c *Protection) GetPermissionScopes(ctx context.Context, token, realm, idOfClient, permissionID string) ([]*PermissionScope, error) {
	const errMessage = "could not get permission scopes"

	var result []*PermissionScope
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(c.client.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "permission", permissionID, "scopes"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetPermissions returns permissions associated with the client
func (c *Protection) GetPermissions(ctx context.Context, token, realm, idOfClient string, params GetPermissionParams) ([]*PermissionRepresentation, error) {
	const errMessage = "could not get permissions"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	path := []string{"clients", idOfClient, "authz", "resource-server", "permission"}
	if !NilOrEmpty(params.Type) {
		path = append(path, *params.Type)
	}

	var result []*PermissionRepresentation
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(c.client.getAdminRealmURL(realm, path...))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// checkPermissionTicketParams checks that mandatory fields are present
func checkPermissionTicketParams(permissions []CreatePermissionTicketParams) error {
	if len(permissions) == 0 {
		return errors.New("at least one permission ticket must be requested")
	}

	for _, pt := range permissions {

		if NilOrEmpty(pt.ResourceID) {
			return errors.New("resourceID required for permission ticket")
		}
		if NilOrEmptyArray(pt.ResourceScopes) {
			return errors.New("at least one resourceScope required for permission ticket")
		}
	}

	return nil
}

// CreatePermissionTicket creates a permission ticket, using access token from client
func (c *Protection) CreatePermissionTicket(ctx context.Context, token, realm string, permissions []CreatePermissionTicketParams) (*PermissionTicketResponseRepresentation, error) {
	const errMessage = "could not create permission ticket"

	err := checkPermissionTicketParams(permissions)
	if err != nil {
		return nil, err
	}

	var result PermissionTicketResponseRepresentation
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(permissions).
		Post(c.client.getRealmURL(realm, "authz", "protection", "permission"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// checkPermissionGrantParams checks for mandatory fields
func checkPermissionGrantParams(permission PermissionGrantParams) error {
	if NilOrEmpty(permission.RequesterID) {
		return errors.New("requesterID required to grant user permission")
	}
	if NilOrEmpty(permission.ResourceID) {
		return errors.New("resourceID required to grant user permission")
	}
	if NilOrEmpty(permission.ScopeName) {
		return errors.New("scopeName required to grant user permission")
	}

	return nil
}

// GrantPermission lets resource owner grant permission for specific resource ID to specific user ID
func (c *Protection) GrantUserPermission(ctx context.Context, token, realm string, permission PermissionGrantParams) (*PermissionGrantResponseRepresentation, error) {
	const errMessage = "could not grant user permission"

	err := checkPermissionGrantParams(permission)
	if err != nil {
		return nil, err
	}

	permission.Granted = BoolP(true)

	var result PermissionGrantResponseRepresentation

	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(permission).
		Post(c.client.getRealmURL(realm, "authz", "protection", "permission", "ticket"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// checkPermissionUpdateParams
func checkPermissionUpdateParams(permission PermissionGrantParams) error {
	err := checkPermissionGrantParams(permission)
	if err != nil {
		return err
	}

	if permission.Granted == nil {
		return errors.New("granted required to update user permission")
	}
	return nil
}

func (c *Protection) UpdateUserPermission(ctx context.Context, token, realm string, permission PermissionGrantParams) (*PermissionGrantResponseRepresentation, error) {
	const errMessage = "could not update user permission"

	err := checkPermissionUpdateParams(permission)
	if err != nil {
		return nil, err
	}

	var result PermissionGrantResponseRepresentation

	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(permission).
		Put(c.client.getRealmURL(realm, "authz", "protection", "permission", "ticket"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	if resp.StatusCode() == http.StatusNoContent { // permission updated to 'not granted' removes permission
		return nil, nil
	}

	return &result, nil
}

// GetUserPermission gets granted permissions according query parameters
func (c *Protection) GetUserPermissions(ctx context.Context, token, realm string, params GetUserPermissionParams) ([]*PermissionGrantResponseRepresentation, error) {
	const errMessage = "could not get user permissions"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, err
	}

	var result []*PermissionGrantResponseRepresentation
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(c.client.getRealmURL(realm, "authz", "protection", "permission", "ticket"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

func (c *Protection) DeleteUserPermission(ctx context.Context, token, realm, ticketID string) error {
	const errMessage = "could not delete user permission"

	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		Delete(c.client.getRealmURL(realm, "authz", "protection", "permission", "ticket", ticketID))

	return checkForError(resp, err, errMessage)
}

// CreatePermission creates a permission associated with the client
func (c *Protection) CreatePermission(ctx context.Context, token, realm, idOfClient string, permission PermissionRepresentation) (*PermissionRepresentation, error) {
	const errMessage = "could not create permission"

	if NilOrEmpty(permission.Type) {
		return nil, errors.New("type of a permission required")
	}

	var result PermissionRepresentation
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(permission).
		Post(c.client.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "permission", *(permission.Type)))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// UpdatePermission updates a permission associated with the client
func (c *Protection) UpdatePermission(ctx context.Context, token, realm, idOfClient string, permission PermissionRepresentation) error {
	const errMessage = "could not update permission"

	if NilOrEmpty(permission.ID) {
		return errors.New("ID of a permission required")
	}
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetBody(permission).
		Put(c.client.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "permission", *permission.Type, *permission.ID))

	return checkForError(resp, err, errMessage)
}

// DeletePermission deletes a policy associated with the client
func (c *Protection) DeletePermission(ctx context.Context, token, realm, idOfClient, permissionID string) error {
	const errMessage = "could not delete permission"

	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		Delete(c.client.getAdminRealmURL(realm, "clients", idOfClient, "authz", "resource-server", "permission", permissionID))

	return checkForError(resp, err, errMessage)
}
