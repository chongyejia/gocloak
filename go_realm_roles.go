package gocloak

import (
	"context"
	"github.com/pkg/errors"
)

type RealmRoles struct {
	client *gocloak
}

// -----------
// Realm Roles
// -----------

// CreateRealmRole creates a role in a realm
func (r *RealmRoles) CreateRealmRole(ctx context.Context, token string, realm string, role Role) (string, error) {
	const errMessage = "could not create realm role"

	resp, err := r.client.getRequestWithBearerAuth(ctx, token).
		SetBody(role).
		Post(r.client.getAdminRealmURL(realm, "roles"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// GetRealmRole returns a role from a realm by role's name
func (r *RealmRoles) GetRealmRole(ctx context.Context, token, realm, roleName string) (*Role, error) {
	const errMessage = "could not get realm role"

	var result Role

	resp, err := r.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(r.client.getAdminRealmURL(realm, "roles", roleName))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetRealmRoleByID returns a role from a realm by role's ID
func (r *RealmRoles) GetRealmRoleByID(ctx context.Context, token, realm, roleID string) (*Role, error) {
	const errMessage = "could not get realm role"

	var result Role
	resp, err := r.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(r.client.getAdminRealmURL(realm, "roles-by-id", roleID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetRealmRoles get all roles of the given realm.
func (r *RealmRoles) GetRealmRoles(ctx context.Context, token, realm string, params GetRoleParams) ([]*Role, error) {
	const errMessage = "could not get realm roles"

	var result []*Role
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	resp, err := r.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(r.client.getAdminRealmURL(realm, "roles"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetRealmRolesByUserID returns all roles assigned to the given user
func (r *RealmRoles) GetRealmRolesByUserID(ctx context.Context, token, realm, userID string) ([]*Role, error) {
	const errMessage = "could not get realm roles by user id"

	var result []*Role
	resp, err := r.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(r.client.getAdminRealmURL(realm, "users", userID, "role-mappings", "realm"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetRealmRolesByGroupID returns all roles assigned to the given group
func (r *RealmRoles) GetRealmRolesByGroupID(ctx context.Context, token, realm, groupID string) ([]*Role, error) {
	const errMessage = "could not get realm roles by group id"

	var result []*Role
	resp, err := r.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(r.client.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "realm"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// UpdateRealmRole updates a role in a realm
func (r *RealmRoles) UpdateRealmRole(ctx context.Context, token, realm, roleName string, role Role) error {
	const errMessage = "could not update realm role"

	resp, err := r.client.getRequestWithBearerAuth(ctx, token).
		SetBody(role).
		Put(r.client.getAdminRealmURL(realm, "roles", roleName))

	return checkForError(resp, err, errMessage)
}

// UpdateRealmRoleByID updates a role in a realm by role's ID
func (r *RealmRoles) UpdateRealmRoleByID(ctx context.Context, token, realm, roleID string, role Role) error {
	const errMessage = "could not update realm role"

	resp, err := r.client.getRequestWithBearerAuth(ctx, token).
		SetBody(role).
		Put(r.client.getAdminRealmURL(realm, "roles-by-id", roleID))

	return checkForError(resp, err, errMessage)
}

// DeleteRealmRole deletes a role in a realm by role's name
func (r *RealmRoles) DeleteRealmRole(ctx context.Context, token, realm, roleName string) error {
	const errMessage = "could not delete realm role"

	resp, err := r.client.getRequestWithBearerAuth(ctx, token).
		Delete(r.client.getAdminRealmURL(realm, "roles", roleName))

	return checkForError(resp, err, errMessage)
}

// AddRealmRoleToUser adds realm-level role mappings
func (r *RealmRoles) AddRealmRoleToUser(ctx context.Context, token, realm, userID string, roles []Role) error {
	const errMessage = "could not add realm role to user"

	resp, err := r.client.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(r.client.getAdminRealmURL(realm, "users", userID, "role-mappings", "realm"))

	return checkForError(resp, err, errMessage)
}

// DeleteRealmRoleFromUser deletes realm-level role mappings
func (r *RealmRoles) DeleteRealmRoleFromUser(ctx context.Context, token, realm, userID string, roles []Role) error {
	const errMessage = "could not delete realm role from user"

	resp, err := r.client.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(r.client.getAdminRealmURL(realm, "users", userID, "role-mappings", "realm"))

	return checkForError(resp, err, errMessage)
}

// AddRealmRoleToGroup adds realm-level role mappings
func (r *RealmRoles) AddRealmRoleToGroup(ctx context.Context, token, realm, groupID string, roles []Role) error {
	const errMessage = "could not add realm role to group"

	resp, err := r.client.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(r.client.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "realm"))

	return checkForError(resp, err, errMessage)
}

// DeleteRealmRoleFromGroup deletes realm-level role mappings
func (r *RealmRoles) DeleteRealmRoleFromGroup(ctx context.Context, token, realm, groupID string, roles []Role) error {
	const errMessage = "could not delete realm role from group"

	resp, err := r.client.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(r.client.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "realm"))

	return checkForError(resp, err, errMessage)
}

func (r *RealmRoles) AddRealmRoleComposite(ctx context.Context, token, realm, roleName string, roles []Role) error {
	const errMessage = "could not add realm role composite"

	resp, err := r.client.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(r.client.getAdminRealmURL(realm, "roles", roleName, "composites"))

	return checkForError(resp, err, errMessage)
}

func (r *RealmRoles) DeleteRealmRoleComposite(ctx context.Context, token, realm, roleName string, roles []Role) error {
	const errMessage = "could not delete realm role composite"

	resp, err := r.client.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(r.client.getAdminRealmURL(realm, "roles", roleName, "composites"))

	return checkForError(resp, err, errMessage)
}

// GetCompositeRealmRoles returns all realm composite roles associated with the given realm role
func (r *RealmRoles) GetCompositeRealmRoles(ctx context.Context, token, realm, roleName string) ([]*Role, error) {
	const errMessage = "could not get composite realm roles by role"

	var result []*Role
	resp, err := r.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(r.client.getAdminRealmURL(realm, "roles", roleName, "composites"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetCompositeRealmRolesByRoleID returns all realm composite roles associated with the given client role
func (r *RealmRoles) GetCompositeRealmRolesByRoleID(ctx context.Context, token, realm, roleID string) ([]*Role, error) {
	const errMessage = "could not get composite client roles by role id"

	var result []*Role
	resp, err := r.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(r.client.getAdminRealmURL(realm, "roles-by-id", roleID, "composites", "realm"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetCompositeRealmRolesByUserID returns all realm roles and composite roles assigned to the given user
func (r *RealmRoles) GetCompositeRealmRolesByUserID(ctx context.Context, token, realm, userID string) ([]*Role, error) {
	const errMessage = "could not get composite client roles by user id"

	var result []*Role
	resp, err := r.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(r.client.getAdminRealmURL(realm, "users", userID, "role-mappings", "realm", "composite"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetCompositeRealmRolesByGroupID returns all realm roles and composite roles assigned to the given group
func (r *RealmRoles) GetCompositeRealmRolesByGroupID(ctx context.Context, token, realm, groupID string) ([]*Role, error) {
	const errMessage = "could not get composite client roles by user id"

	var result []*Role
	resp, err := r.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(r.client.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "realm", "composite"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetAvailableRealmRolesByUserID returns all available realm roles to the given user
func (r *RealmRoles) GetAvailableRealmRolesByUserID(ctx context.Context, token, realm, userID string) ([]*Role, error) {
	const errMessage = "could not get available client roles by user id"

	var result []*Role
	resp, err := r.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(r.client.getAdminRealmURL(realm, "users", userID, "role-mappings", "realm", "available"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetAvailableRealmRolesByGroupID returns all available realm roles to the given group
func (r *RealmRoles) GetAvailableRealmRolesByGroupID(ctx context.Context, token, realm, groupID string) ([]*Role, error) {
	const errMessage = "could not get available client roles by user id"

	var result []*Role
	resp, err := r.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(r.client.getAdminRealmURL(realm, "groups", groupID, "role-mappings", "realm", "available"))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}
