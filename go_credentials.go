package gocloak

import "context"

type Credentials struct {
	client *gocloak
}

// ---------------
// Credentials API
// ---------------

// GetCredentialRegistrators returns credentials registrators
func (c *Credentials) GetCredentialRegistrators(ctx context.Context, token, realm string) ([]string, error) {
	const errMessage = "could not get user credential registrators"

	var result []string
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(c.client.getAdminRealmURL(realm, "credential-registrators"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetConfiguredUserStorageCredentialTypes returns credential types, which are provided by the user storage where user is stored
func (c *Credentials) GetConfiguredUserStorageCredentialTypes(ctx context.Context, token, realm, userID string) ([]string, error) {
	const errMessage = "could not get user credential registrators"

	var result []string
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(c.client.getAdminRealmURL(realm, "users", userID, "configured-user-storage-credential-types"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetCredentials returns credentials available for a given user
func (c *Credentials) GetCredentials(ctx context.Context, token, realm, userID string) ([]*CredentialRepresentation, error) {
	const errMessage = "could not get user credentials"

	var result []*CredentialRepresentation
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(c.client.getAdminRealmURL(realm, "users", userID, "credentials"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// DeleteCredentials deletes the given credential for a given user
func (c *Credentials) DeleteCredentials(ctx context.Context, token, realm, userID, credentialID string) error {
	const errMessage = "could not delete user credentials"

	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		Delete(c.client.getAdminRealmURL(realm, "users", userID, "credentials", credentialID))

	return checkForError(resp, err, errMessage)
}

// UpdateCredentialUserLabel updates label for the given credential for the given user
func (c *Credentials) UpdateCredentialUserLabel(ctx context.Context, token, realm, userID, credentialID, userLabel string) error {
	const errMessage = "could not update credential label for a user"

	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetHeader("Content-Type", "text/plain").
		SetBody(userLabel).
		Put(c.client.getAdminRealmURL(realm, "users", userID, "credentials", credentialID, "userLabel"))

	return checkForError(resp, err, errMessage)
}

// DisableAllCredentialsByType disables all credentials for a user of a specific type
func (c *Credentials) DisableAllCredentialsByType(ctx context.Context, token, realm, userID string, types []string) error {
	const errMessage = "could not update disable credentials"

	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetBody(types).
		Put(c.client.getAdminRealmURL(realm, "users", userID, "disable-credential-types"))

	return checkForError(resp, err, errMessage)
}

// MoveCredentialBehind move a credential to a position behind another credential
func (c *Credentials) MoveCredentialBehind(ctx context.Context, token, realm, userID, credentialID, newPreviousCredentialID string) error {
	const errMessage = "could not move credential"

	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		Post(c.client.getAdminRealmURL(realm, "users", userID, "credentials", credentialID, "moveAfter", newPreviousCredentialID))

	return checkForError(resp, err, errMessage)
}

// MoveCredentialToFirst move a credential to a first position in the credentials list of the user
func (c *Credentials) MoveCredentialToFirst(ctx context.Context, token, realm, userID, credentialID string) error {
	const errMessage = "could not move credential"

	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		Post(c.client.getAdminRealmURL(realm, "users", userID, "credentials", credentialID, "moveToFirst"))

	return checkForError(resp, err, errMessage)
}
