package gocloak

import (
	"context"
	"io"
)

type IdentityProvider struct {
	client *gocloak
}

// ------------------
// Identity Providers
// ------------------

// CreateIdentityProvider creates an identity provider in a realm
func (c *IdentityProvider) CreateIdentityProvider(ctx context.Context, token string, realm string, providerRep IdentityProviderRepresentation) (string, error) {
	const errMessage = "could not create identity provider"

	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetBody(providerRep).
		Post(c.client.getAdminRealmURL(realm, "identity-provider", "instances"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// GetIdentityProviders returns list of identity providers in a realm
func (c *IdentityProvider) GetIdentityProviders(ctx context.Context, token, realm string) ([]*IdentityProviderRepresentation, error) {
	const errMessage = "could not get identity providers"

	var result []*IdentityProviderRepresentation
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(c.client.getAdminRealmURL(realm, "identity-provider", "instances"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetIdentityProvider gets the identity provider in a realm
func (c *IdentityProvider) GetIdentityProvider(ctx context.Context, token, realm, alias string) (*IdentityProviderRepresentation, error) {
	const errMessage = "could not get identity provider"

	var result IdentityProviderRepresentation
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(c.client.getAdminRealmURL(realm, "identity-provider", "instances", alias))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// UpdateIdentityProvider updates the identity provider in a realm
func (c *IdentityProvider) UpdateIdentityProvider(ctx context.Context, token, realm, alias string, providerRep IdentityProviderRepresentation) error {
	const errMessage = "could not update identity provider"

	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetBody(providerRep).
		Put(c.client.getAdminRealmURL(realm, "identity-provider", "instances", alias))

	return checkForError(resp, err, errMessage)
}

// DeleteIdentityProvider deletes the identity provider in a realm
func (c *IdentityProvider) DeleteIdentityProvider(ctx context.Context, token, realm, alias string) error {
	const errMessage = "could not delete identity provider"

	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		Delete(c.client.getAdminRealmURL(realm, "identity-provider", "instances", alias))

	return checkForError(resp, err, errMessage)
}

// ExportIDPPublicBrokerConfig exports the broker config for a given alias
func (c *IdentityProvider) ExportIDPPublicBrokerConfig(ctx context.Context, token, realm, alias string) (*string, error) {
	const errMessage = "could not get public identity provider configuration"

	resp, err := c.client.getRequestWithBearerAuthXMLHeader(ctx, token).
		Get(c.client.getAdminRealmURL(realm, "identity-provider", "instances", alias, "export"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	result := resp.String()
	return &result, nil
}

// ImportIdentityProviderConfig parses and returns the identity provider config at a given URL
func (c *IdentityProvider) ImportIdentityProviderConfig(ctx context.Context, token, realm, fromURL, providerID string) (map[string]string, error) {
	const errMessage = "could not import config"

	result := make(map[string]string)
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetBody(map[string]string{
			"fromUrl":    fromURL,
			"providerId": providerID,
		}).
		Post(c.client.getAdminRealmURL(realm, "identity-provider", "import-config"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// ImportIdentityProviderConfigFromFile parses and returns the identity provider config from a given file
func (c *IdentityProvider) ImportIdentityProviderConfigFromFile(ctx context.Context, token, realm, providerID, fileName string, fileBody io.Reader) (map[string]string, error) {
	const errMessage = "could not import config"

	result := make(map[string]string)
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetFileReader("file", fileName, fileBody).
		SetFormData(map[string]string{
			"providerId": providerID,
		}).
		Post(c.client.getAdminRealmURL(realm, "identity-provider", "import-config"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// CreateIdentityProviderMapper creates an instance of an identity provider mapper associated with the given alias
func (c *IdentityProvider) CreateIdentityProviderMapper(ctx context.Context, token, realm, alias string, mapper IdentityProviderMapper) (string, error) {
	const errMessage = "could not create mapper for identity provider"

	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetBody(mapper).
		Post(c.client.getAdminRealmURL(realm, "identity-provider", "instances", alias, "mappers"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// GetIdentityProviderMapper gets the mapper by id for the given identity provider alias in a realm
func (c *IdentityProvider) GetIdentityProviderMapper(ctx context.Context, token string, realm string, alias string, mapperID string) (*IdentityProviderMapper, error) {
	const errMessage = "could not get identity provider mapper"

	result := IdentityProviderMapper{}
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(c.client.getAdminRealmURL(realm, "identity-provider", "instances", alias, "mappers", mapperID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// DeleteIdentityProviderMapper deletes an instance of an identity provider mapper associated with the given alias and mapper ID
func (c *IdentityProvider) DeleteIdentityProviderMapper(ctx context.Context, token, realm, alias, mapperID string) error {
	const errMessage = "could not delete mapper for identity provider"

	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		Delete(c.client.getAdminRealmURL(realm, "identity-provider", "instances", alias, "mappers", mapperID))

	return checkForError(resp, err, errMessage)
}

// GetIdentityProviderMappers returns list of mappers associated with an identity provider
func (c *IdentityProvider) GetIdentityProviderMappers(ctx context.Context, token, realm, alias string) ([]*IdentityProviderMapper, error) {
	const errMessage = "could not get identity provider mappers"

	var result []*IdentityProviderMapper
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(c.client.getAdminRealmURL(realm, "identity-provider", "instances", alias, "mappers"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetIdentityProviderMapperByID gets the mapper of an identity provider
func (c *IdentityProvider) GetIdentityProviderMapperByID(ctx context.Context, token, realm, alias, mapperID string) (*IdentityProviderMapper, error) {
	const errMessage = "could not get identity provider mappers"

	var result IdentityProviderMapper
	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(c.client.getAdminRealmURL(realm, "identity-provider", "instances", alias, "mappers", mapperID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// UpdateIdentityProviderMapper updates mapper of an identity provider
func (c *IdentityProvider) UpdateIdentityProviderMapper(ctx context.Context, token, realm, alias string, mapper IdentityProviderMapper) error {
	const errMessage = "could not update identity provider mapper"

	resp, err := c.client.getRequestWithBearerAuth(ctx, token).
		SetBody(mapper).
		Put(c.client.getAdminRealmURL(realm, "identity-provider", "instances", alias, "mappers", PString(mapper.ID)))

	return checkForError(resp, err, errMessage)
}
