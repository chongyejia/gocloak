package gocloak

import (
	"context"
	"github.com/pkg/errors"
)

type Users struct {
	client *gocloak
}

// -----
// Users
// -----

// CreateUser creates the given user in the given realm and returns it's userID
func (u *Users) CreateUser(ctx context.Context, token, realm string, user User) (string, error) {
	const errMessage = "could not create user"

	resp, err := u.client.getRequestWithBearerAuth(ctx, token).
		SetBody(user).
		Post(u.client.getAdminRealmURL(realm, "users"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// DeleteUser delete a given user
func (u *Users) DeleteUser(ctx context.Context, token, realm, userID string) error {
	const errMessage = "could not delete user"

	resp, err := u.client.getRequestWithBearerAuth(ctx, token).
		Delete(u.client.getAdminRealmURL(realm, "users", userID))

	return checkForError(resp, err, errMessage)
}

// GetUserByID fetches a user from the given realm with the given userID
func (u *Users) GetUserByID(ctx context.Context, accessToken, realm, userID string) (*User, error) {
	const errMessage = "could not get user by id"

	if userID == "" {
		return nil, errors.Wrap(errors.New("userID shall not be empty"), errMessage)
	}

	var result User
	resp, err := u.client.getRequestWithBearerAuth(ctx, accessToken).
		SetResult(&result).
		Get(u.client.getAdminRealmURL(realm, "users", userID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetUserCount gets the user count in the realm
func (u *Users) GetUserCount(ctx context.Context, token string, realm string, params GetUsersParams) (int, error) {
	const errMessage = "could not get user count"

	var result int
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return 0, errors.Wrap(err, errMessage)
	}

	resp, err := u.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(u.client.getAdminRealmURL(realm, "users", "count"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return -1, errors.Wrap(err, errMessage)
	}

	return result, nil
}

// GetUserGroups get all groups for user
func (u *Users) GetUserGroups(ctx context.Context, token, realm, userID string, params GetGroupsParams) ([]*Group, error) {
	const errMessage = "could not get user groups"

	var result []*Group
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	resp, err := u.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(u.client.getAdminRealmURL(realm, "users", userID, "groups"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetUsers get all users in realm
func (u *Users) GetUsers(ctx context.Context, token, realm string, params GetUsersParams) ([]*User, error) {
	const errMessage = "could not get users"

	var result []*User
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	resp, err := u.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(u.client.getAdminRealmURL(realm, "users"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetUsersByRoleName returns all users have a given role
func (u *Users) GetUsersByRoleName(ctx context.Context, token, realm, roleName string) ([]*User, error) {
	const errMessage = "could not get users by role name"

	var result []*User
	resp, err := u.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(u.client.getAdminRealmURL(realm, "roles", roleName, "users"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetUsersByClientRoleName returns all users have a given client role
func (u *Users) GetUsersByClientRoleName(ctx context.Context, token, realm, idOfClient, roleName string, params GetUsersByRoleParams) ([]*User, error) {
	const errMessage = "could not get users by client role name"

	var result []*User
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, err
	}

	resp, err := u.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(u.client.getAdminRealmURL(realm, "clients", idOfClient, "roles", roleName, "users"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// SetPassword sets a new password for the user with the given id. Needs elevated privileges
func (u *Users) SetPassword(ctx context.Context, token, userID, realm, password string, temporary bool) error {
	const errMessage = "could not set password"

	requestBody := SetPasswordRequest{Password: &password, Temporary: &temporary, Type: StringP("password")}
	resp, err := u.client.getRequestWithBearerAuth(ctx, token).
		SetBody(requestBody).
		Put(u.client.getAdminRealmURL(realm, "users", userID, "reset-password"))

	return checkForError(resp, err, errMessage)
}

// UpdateUser updates a given user
func (u *Users) UpdateUser(ctx context.Context, token, realm string, user User) error {
	const errMessage = "could not update user"

	resp, err := u.client.getRequestWithBearerAuth(ctx, token).
		SetBody(user).
		Put(u.client.getAdminRealmURL(realm, "users", PString(user.ID)))

	return checkForError(resp, err, errMessage)
}

// AddUserToGroup puts given user to given group
func (u *Users) AddUserToGroup(ctx context.Context, token, realm, userID, groupID string) error {
	const errMessage = "could not add user to group"

	resp, err := u.client.getRequestWithBearerAuth(ctx, token).
		Put(u.client.getAdminRealmURL(realm, "users", userID, "groups", groupID))

	return checkForError(resp, err, errMessage)
}

// DeleteUserFromGroup deletes given user from given group
func (u *Users) DeleteUserFromGroup(ctx context.Context, token, realm, userID, groupID string) error {
	const errMessage = "could not delete user from group"

	resp, err := u.client.getRequestWithBearerAuth(ctx, token).
		Delete(u.client.getAdminRealmURL(realm, "users", userID, "groups", groupID))

	return checkForError(resp, err, errMessage)
}

// GetUserSessions returns user sessions associated with the user
func (u *Users) GetUserSessions(ctx context.Context, token, realm, userID string) ([]*UserSessionRepresentation, error) {
	const errMessage = "could not get user sessions"

	var res []*UserSessionRepresentation
	resp, err := u.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&res).
		Get(u.client.getAdminRealmURL(realm, "users", userID, "sessions"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return res, nil
}

// GetUserOfflineSessionsForClient returns offline sessions associated with the user and client
func (u *Users) GetUserOfflineSessionsForClient(ctx context.Context, token, realm, userID, idOfClient string) ([]*UserSessionRepresentation, error) {
	const errMessage = "could not get user offline sessions for client"

	var res []*UserSessionRepresentation
	resp, err := u.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&res).
		Get(u.client.getAdminRealmURL(realm, "users", userID, "offline-sessions", idOfClient))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return res, nil
}

// GetUserFederatedIdentities gets all user federated identities
func (u *Users) GetUserFederatedIdentities(ctx context.Context, token, realm, userID string) ([]*FederatedIdentityRepresentation, error) {
	const errMessage = "could not get user federeated identities"

	var res []*FederatedIdentityRepresentation
	resp, err := u.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&res).
		Get(u.client.getAdminRealmURL(realm, "users", userID, "federated-identity"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return res, err
}

// CreateUserFederatedIdentity creates an user federated identity
func (u *Users) CreateUserFederatedIdentity(ctx context.Context, token, realm, userID, providerID string, federatedIdentityRep FederatedIdentityRepresentation) error {
	const errMessage = "could not create user federeated identity"

	resp, err := u.client.getRequestWithBearerAuth(ctx, token).
		SetBody(federatedIdentityRep).
		Post(u.client.getAdminRealmURL(realm, "users", userID, "federated-identity", providerID))

	return checkForError(resp, err, errMessage)
}

// DeleteUserFederatedIdentity deletes an user federated identity
func (u *Users) DeleteUserFederatedIdentity(ctx context.Context, token, realm, userID, providerID string) error {
	const errMessage = "could not delete user federeated identity"

	resp, err := u.client.getRequestWithBearerAuth(ctx, token).
		Delete(u.client.getAdminRealmURL(realm, "users", userID, "federated-identity", providerID))

	return checkForError(resp, err, errMessage)
}
