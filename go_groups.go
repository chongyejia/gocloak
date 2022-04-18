package gocloak

import (
	"context"
	"github.com/pkg/errors"
)

type Groups struct {
	client *gocloak
}

// GetGroups get all groups in realm
func (g *Groups) GetGroups(ctx context.Context, token, realm string, params GetGroupsParams) ([]*Group, error) {
	const errMessage = "could not get groups"

	var result []*Group
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	resp, err := g.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(g.client.getAdminRealmURL(realm, "groups"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetGroupsCount gets the groups count in the realm
func (g *Groups) GetGroupsCount(ctx context.Context, token, realm string, params GetGroupsParams) (int, error) {
	const errMessage = "could not get groups count"

	var result GroupsCount
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return 0, errors.Wrap(err, errMessage)
	}
	resp, err := g.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(g.client.getAdminRealmURL(realm, "groups", "count"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return -1, errors.Wrap(err, errMessage)
	}

	return result.Count, nil
}

// GetGroup get group with id in realm
func (g *Groups) GetGroup(ctx context.Context, token, realm, groupID string) (*Group, error) {
	const errMessage = "could not get group"

	var result Group

	resp, err := g.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(g.client.getAdminRealmURL(realm, "groups", groupID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

func (g *Groups) UpdateGroup(ctx context.Context, token, realm string, updatedGroup Group) error {
	const errMessage = "could not update group"

	if NilOrEmpty(updatedGroup.ID) {
		return errors.Wrap(errors.New("ID of a group required"), errMessage)
	}
	resp, err := g.client.getRequestWithBearerAuth(ctx, token).
		SetBody(updatedGroup).
		Put(g.client.getAdminRealmURL(realm, "groups", PString(updatedGroup.ID)))

	return checkForError(resp, err, errMessage)
}

func (g *Groups) DeleteGroup(ctx context.Context, token, realm, groupID string) error {
	const errMessage = "could not delete group"

	resp, err := g.client.getRequestWithBearerAuth(ctx, token).
		Delete(g.client.getAdminRealmURL(realm, "groups", groupID))

	return checkForError(resp, err, errMessage)
}

// CreateChildGroup creates a new child group
func (g *Groups) CreateChildGroup(ctx context.Context, token, realm, groupID string, group Group) (string, error) {
	const errMessage = "could not create child group"

	resp, err := g.client.getRequestWithBearerAuth(ctx, token).
		SetBody(group).
		Post(g.client.getAdminRealmURL(realm, "groups", groupID, "children"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// GetGroupMembers get a list of users of group with id in realm
func (g *Groups) GetGroupMembers(ctx context.Context, token, realm, groupID string, params GetGroupsParams) ([]*User, error) {
	const errMessage = "could not get group members"

	var result []*User
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	resp, err := g.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(g.client.getAdminRealmURL(realm, "groups", groupID, "members"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}
