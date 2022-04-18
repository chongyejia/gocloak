package gocloak

import "context"

type Realm struct {
	client *gocloak
}

// -----
// Realm
// -----

// GetRealm returns top-level representation of the realm
func (r *Realm) GetRealm(ctx context.Context, token, realm string) (*RealmRepresentation, error) {
	const errMessage = "could not get realm"

	var result RealmRepresentation
	resp, err := r.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(r.client.getAdminRealmURL(realm))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetRealms returns top-level representation of all realms
func (r *Realm) GetRealms(ctx context.Context, token string) ([]*RealmRepresentation, error) {
	const errMessage = "could not get realms"

	var result []*RealmRepresentation
	resp, err := r.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(r.client.getAdminRealmURL(""))

	if err = checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// CreateRealm creates a realm
func (r *Realm) CreateRealm(ctx context.Context, token string, realm RealmRepresentation) (string, error) {
	const errMessage = "could not create realm"

	resp, err := r.client.getRequestWithBearerAuth(ctx, token).
		SetBody(&realm).
		Post(r.client.getAdminRealmURL(""))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}
	return getID(resp), nil
}

// UpdateRealm updates a given realm
func (r *Realm) UpdateRealm(ctx context.Context, token string, realm RealmRepresentation) error {
	const errMessage = "could not update realm"

	resp, err := r.client.getRequestWithBearerAuth(ctx, token).
		SetBody(realm).
		Put(r.client.getAdminRealmURL(PString(realm.Realm)))

	return checkForError(resp, err, errMessage)
}

// DeleteRealm removes a realm
func (r *Realm) DeleteRealm(ctx context.Context, token, realm string) error {
	const errMessage = "could not delete realm"

	resp, err := r.client.getRequestWithBearerAuth(ctx, token).
		Delete(r.client.getAdminRealmURL(realm))

	return checkForError(resp, err, errMessage)
}

// ClearRealmCache clears realm cache
func (r *Realm) ClearRealmCache(ctx context.Context, token, realm string) error {
	const errMessage = "could not clear realm cache"

	resp, err := r.client.getRequestWithBearerAuth(ctx, token).
		Post(r.client.getAdminRealmURL(realm, "clear-realm-cache"))

	return checkForError(resp, err, errMessage)
}

// ClearUserCache clears realm cache
func (r *Realm) ClearUserCache(ctx context.Context, token, realm string) error {
	const errMessage = "could not clear user cache"

	resp, err := r.client.getRequestWithBearerAuth(ctx, token).
		Post(r.client.getAdminRealmURL(realm, "clear-user-cache"))

	return checkForError(resp, err, errMessage)
}

// ClearKeysCache clears realm cache
func (r *Realm) ClearKeysCache(ctx context.Context, token, realm string) error {
	const errMessage = "could not clear keys cache"

	resp, err := r.client.getRequestWithBearerAuth(ctx, token).
		Post(r.client.getAdminRealmURL(realm, "clear-keys-cache"))

	return checkForError(resp, err, errMessage)
}

//GetAuthenticationFlows get all authentication flows from a realm
func (r *Realm) GetAuthenticationFlows(ctx context.Context, token, realm string) ([]*AuthenticationFlowRepresentation, error) {
	const errMessage = "could not retrieve authentication flows"
	var result []*AuthenticationFlowRepresentation
	resp, err := r.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(r.client.getAdminRealmURL(realm, "authentication", "flows"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}
	return result, nil
}

//Create a new Authentication flow in a realm
func (r *Realm) CreateAuthenticationFlow(ctx context.Context, token, realm string, flow AuthenticationFlowRepresentation) error {
	const errMessage = "could not create authentication flows"
	var result []*AuthenticationFlowRepresentation
	resp, err := r.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).SetBody(flow).
		Post(r.client.getAdminRealmURL(realm, "authentication", "flows"))

	return checkForError(resp, err, errMessage)
}

//DeleteAuthenticationFlow deletes a flow in a realm with the given ID
func (r *Realm) DeleteAuthenticationFlow(ctx context.Context, token, realm, flowID string) error {
	const errMessage = "could not delete authentication flows"
	resp, err := r.client.getRequestWithBearerAuth(ctx, token).
		Delete(r.client.getAdminRealmURL(realm, "authentication", "flows", flowID))

	return checkForError(resp, err, errMessage)
}

//GetAuthenticationExecutions retrieves all executions of a given flow
func (r *Realm) GetAuthenticationExecutions(ctx context.Context, token, realm, flow string) ([]*ModifyAuthenticationExecutionRepresentation, error) {
	const errMessage = "could not retrieve authentication flows"
	var result []*ModifyAuthenticationExecutionRepresentation
	resp, err := r.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(r.client.getAdminRealmURL(realm, "authentication", "flows", flow, "executions"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}
	return result, nil
}

//CreateAuthenticationExecution creates a new execution for the given flow name in the given realm
func (r *Realm) CreateAuthenticationExecution(ctx context.Context, token, realm, flow string, execution CreateAuthenticationExecutionRepresentation) error {
	const errMessage = "could not create authentication execution"
	resp, err := r.client.getRequestWithBearerAuth(ctx, token).SetBody(execution).
		Post(r.client.getAdminRealmURL(realm, "authentication", "flows", flow, "executions", "execution"))

	return checkForError(resp, err, errMessage)
}

//UpdateAuthenticationExecution updates an authentication execution for the given flow in the given realm
func (r *Realm) UpdateAuthenticationExecution(ctx context.Context, token, realm, flow string, execution ModifyAuthenticationExecutionRepresentation) error {
	const errMessage = "could not update authentication execution"
	resp, err := r.client.getRequestWithBearerAuth(ctx, token).SetBody(execution).
		Put(r.client.getAdminRealmURL(realm, "authentication", "flows", flow, "executions"))

	return checkForError(resp, err, errMessage)
}

// DeleteAuthenticationExecution delete a single execution with the given ID
func (r *Realm) DeleteAuthenticationExecution(ctx context.Context, token, realm, executionID string) error {
	const errMessage = "could not delete authentication execution"
	resp, err := r.client.getRequestWithBearerAuth(ctx, token).
		Delete(r.client.getAdminRealmURL(realm, "authentication", "executions", executionID))

	return checkForError(resp, err, errMessage)
}

//CreateAuthenticationExecutionFlow creates a new execution for the given flow name in the given realm
func (r *Realm) CreateAuthenticationExecutionFlow(ctx context.Context, token, realm, flow string, executionFlow CreateAuthenticationExecutionFlowRepresentation) error {
	const errMessage = "could not create authentication execution flow"
	resp, err := r.client.getRequestWithBearerAuth(ctx, token).SetBody(executionFlow).
		Post(r.client.getAdminRealmURL(realm, "authentication", "flows", flow, "executions", "flow"))

	return checkForError(resp, err, errMessage)
}
