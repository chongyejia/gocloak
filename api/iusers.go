package api

import (
	"context"
	"github.com/chongyejia/gocloak/v11"
)

type IUsers interface {
	// CreateUser creates a new user
	CreateUser(ctx context.Context, token, realm string, user gocloak.User) (string, error)

	// GetUsers gets all users of the given realm
	GetUsers(ctx context.Context, accessToken, realm string, params gocloak.GetUsersParams) ([]*gocloak.User, error)

	// GetUser count returns the userCount of the given realm
	GetUserCount(ctx context.Context, accessToken, realm string, params gocloak.GetUsersParams) (int, error)

	// GetUserByID gets the user with the given id
	GetUserByID(ctx context.Context, accessToken, realm, userID string) (*gocloak.User, error)

	// UpdateUser updates the given user
	UpdateUser(ctx context.Context, accessToken, realm string, user gocloak.User) error

	// DeleteUser deletes the given user
	DeleteUser(ctx context.Context, accessToken, realm, userID string) error

	// GetUserGroups gets the groups of the given user
	GetUserGroups(ctx context.Context, accessToken, realm, userID string, params gocloak.GetGroupsParams) ([]*gocloak.Group, error)
	// GetUsersByRoleName returns all users have a given role
	GetUsersByRoleName(ctx context.Context, token, realm, roleName string) ([]*gocloak.User, error)
	// GetUsersByClientRoleName returns all users have a given client role
	GetUsersByClientRoleName(ctx context.Context, token, realm, idOfClient, roleName string, params gocloak.GetUsersByRoleParams) ([]*gocloak.User, error)
	// SetPassword sets a new password for the user with the given id. Needs elevated privileges
	SetPassword(ctx context.Context, token, userID, realm, password string, temporary bool) error

	// AddUserToGroup puts given user to given group
	AddUserToGroup(ctx context.Context, token, realm, userID, groupID string) error
	// DeleteUserFromGroup deletes given user from given group
	DeleteUserFromGroup(ctx context.Context, token, realm, userID, groupID string) error
	// GetUserSessions returns user sessions associated with the user
	GetUserSessions(ctx context.Context, token, realm, userID string) ([]*gocloak.UserSessionRepresentation, error)
	// GetUserOfflineSessionsForClient returns offline sessions associated with the user and client
	GetUserOfflineSessionsForClient(ctx context.Context, token, realm, userID, idOfClient string) ([]*gocloak.UserSessionRepresentation, error)
	// GetUserFederatedIdentities gets all user federated identities
	GetUserFederatedIdentities(ctx context.Context, token, realm, userID string) ([]*gocloak.FederatedIdentityRepresentation, error)
	// CreateUserFederatedIdentity creates an user federated identity
	CreateUserFederatedIdentity(ctx context.Context, token, realm, userID, providerID string, federatedIdentityRep gocloak.FederatedIdentityRepresentation) error
	// DeleteUserFederatedIdentity deletes an user federated identity
	DeleteUserFederatedIdentity(ctx context.Context, token, realm, userID, providerID string) error
}
