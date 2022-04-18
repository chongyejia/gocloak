package gocloak

import (
	"context"
	"github.com/pkg/errors"
)

type ClientRoles struct {
	client *gocloak
}

// AddClientRoleToUser adds client-level role mappings
func (c *ClientRoles) AddClientRoleToUser(ctx context.Context, token, realm, idOfClient, userID string, roles []Role) error {
	const errMessage = "could not add client role to user"

	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(c.client.getAdminRealmURL(realm, "users", userID, "role-mappings", "clients", idOfClient))

	return checkForError(resp, err, errMessage)
}

// AddClientRoleToGroup adds a client role to the group
func (c *ClientRoles) AddClientRoleToGroup(ctx context.Context, token, realm, idOfClient, groupID string, roles []Role) error {
	const errMessage = "could not add client role to group"

	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(c.client.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "clients", idOfClient))

	return checkForError(resp, err, errMessage)
}

// CreateClientRole creates a new role for a client
func (c *ClientRoles) CreateClientRole(ctx context.Context, token, realm, idOfClient string, role Role) (string, error) {
	const errMessage = "could not create client role"

	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetBody(role).
		Post(c.client.getAdminRealmURL(realm, "clients", idOfClient, "roles"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// DeleteClientRole deletes a given role
func (c *ClientRoles) DeleteClientRole(ctx context.Context, token, realm, idOfClient, roleName string) error {
	const errMessage = "could not delete client role"

	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		Delete(c.client.getAdminRealmURL(realm, "clients", idOfClient, "roles", roleName))

	return checkForError(resp, err, errMessage)
}

// DeleteClientRoleFromUser adds client-level role mappings
func (c *ClientRoles) DeleteClientRoleFromUser(ctx context.Context, token, realm, idOfClient, userID string, roles []Role) error {
	const errMessage = "could not delete client role from user"

	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(c.client.getAdminRealmURL(realm, "users", userID, "role-mappings", "clients", idOfClient))

	return checkForError(resp, err, errMessage)
}

// DeleteClientRoleFromGroup removes a client role from from the group
func (c *ClientRoles) DeleteClientRoleFromGroup(ctx context.Context, token, realm, idOfClient, groupID string, roles []Role) error {
	const errMessage = "could not client role from group"

	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(c.client.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "clients", idOfClient))

	return checkForError(resp, err, errMessage)
}

// GetClientRoles get all roles for the given client in realm
func (c *ClientRoles) GetClientRoles(ctx context.Context, token, realm, idOfClient string, params GetRoleParams) ([]*Role, error) {
	const errMessage = "could not get client roles"

	var result []*Role
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(c.client.getAdminRealmURL(realm, "clients", idOfClient, "roles"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientRoleById gets role for the given client in realm using role ID
func (c *ClientRoles) GetClientRoleByID(ctx context.Context, token, realm, roleID string) (*Role, error) {
	const errMessage = "could not get client role"

	var result Role
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(c.client.getAdminRealmURL(realm, "roles-by-id", roleID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetRealmRolesByUserID returns all client roles assigned to the given user
func (c *ClientRoles) GetClientRolesByUserID(ctx context.Context, token, realm, idOfClient, userID string) ([]*Role, error) {
	const errMessage = "could not client roles by user id"

	var result []*Role
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(c.client.getAdminRealmURL(realm, "users", userID, "role-mappings", "clients", idOfClient))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientRolesByGroupID returns all client roles assigned to the given group
func (c *ClientRoles) GetClientRolesByGroupID(ctx context.Context, token, realm, idOfClient, groupID string) ([]*Role, error) {
	const errMessage = "could not get client roles by group id"

	var result []*Role
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(c.client.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "clients", idOfClient))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetCompositeClientRolesByRoleID returns all client composite roles associated with the given client role
func (c *ClientRoles) GetCompositeClientRolesByRoleID(ctx context.Context, token, realm, idOfClient, roleID string) ([]*Role, error) {
	const errMessage = "could not get composite client roles by role id"

	var result []*Role
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(c.client.getAdminRealmURL(realm, "roles-by-id", roleID, "composites", "clients", idOfClient))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetCompositeClientRolesByUserID returns all client roles and composite roles assigned to the given user
func (c *ClientRoles) GetCompositeClientRolesByUserID(ctx context.Context, token, realm, idOfClient, userID string) ([]*Role, error) {
	const errMessage = "could not get composite client roles by user id"

	var result []*Role
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(c.client.getAdminRealmURL(realm, "users", userID, "role-mappings", "clients", idOfClient, "composite"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetCompositeClientRolesByGroupID returns all client roles and composite roles assigned to the given group
func (c *ClientRoles) GetCompositeClientRolesByGroupID(ctx context.Context, token, realm, idOfClient, groupID string) ([]*Role, error) {
	const errMessage = "could not get composite client roles by group id"

	var result []*Role
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(c.client.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "clients", idOfClient, "composite"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetAvailableClientRolesByUserID returns all available client roles to the given user
func (c *ClientRoles) GetAvailableClientRolesByUserID(ctx context.Context, token, realm, idOfClient, userID string) ([]*Role, error) {
	const errMessage = "could not get available client roles by user id"

	var result []*Role
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(c.client.getAdminRealmURL(realm, "users", userID, "role-mappings", "clients", idOfClient, "available"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetAvailableClientRolesByGroupID returns all available roles to the given group
func (c *ClientRoles) GetAvailableClientRolesByGroupID(ctx context.Context, token, realm, idOfClient, groupID string) ([]*Role, error) {
	const errMessage = "could not get available client roles by user id"

	var result []*Role
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(c.client.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "clients", idOfClient, "available"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientRole get a role for the given client in a realm by role name
func (c *ClientRoles) GetClientRole(ctx context.Context, token, realm, idOfClient, roleName string) (*Role, error) {
	const errMessage = "could not get client role"

	var result Role
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(c.client.getAdminRealmURL(realm, "clients", idOfClient, "roles", roleName))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// AddClientRoleComposite adds roles as composite
func (c *ClientRoles) AddClientRoleComposite(ctx context.Context, token, realm, roleID string, roles []Role) error {
	const errMessage = "could not add client role composite"

	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(c.client.getAdminRealmURL(realm, "roles-by-id", roleID, "composites"))

	return checkForError(resp, err, errMessage)
}

// DeleteClientRoleComposite deletes composites from a role
func (c *ClientRoles) DeleteClientRoleComposite(ctx context.Context, token, realm, roleID string, roles []Role) error {
	const errMessage = "could not delete client role composite"

	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(c.client.getAdminRealmURL(realm, "roles-by-id", roleID, "composites"))

	return checkForError(resp, err, errMessage)
}
