package api

import (
	"context"
	"github.com/chongyejia/gocloak/v11"
)

type IGroups interface {

	// CreateGroup creates a new group
	CreateGroup(ctx context.Context, accessToken, realm string, group gocloak.Group) (string, error)

	// GetGroups gets all groups of the given realm
	GetGroups(ctx context.Context, accessToken, realm string, params gocloak.GetGroupsParams) ([]*gocloak.Group, error)

	// GetGroupsCount gets groups count of the given realm
	GetGroupsCount(ctx context.Context, token, realm string, params gocloak.GetGroupsParams) (int, error)

	// GetGroup gets the given group
	GetGroup(ctx context.Context, accessToken, realm, groupID string) (*gocloak.Group, error)

	// UpdateGroup updates the given group
	UpdateGroup(ctx context.Context, accessToken, realm string, updatedGroup gocloak.Group) error

	// DeleteGroup deletes the given group
	DeleteGroup(ctx context.Context, accessToken, realm, groupID string) error

	// CreateChildGroup creates a new child group
	CreateChildGroup(ctx context.Context, token, realm, groupID string, group gocloak.Group) (string, error)

	// GetGroupMembers get a list of users of group with id in realm
	GetGroupMembers(ctx context.Context, accessToken, realm, groupID string, params gocloak.GetGroupsParams) ([]*gocloak.User, error)

	// TODO PUT /{realm}/groups/{id}/management/permissions

	// TODO GET /{realm}/groups/{id}/management/permissions
}
