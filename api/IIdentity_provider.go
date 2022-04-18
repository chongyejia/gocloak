package api

import (
	"context"
	"github.com/chongyejia/gocloak/v11"
	"io"
)

type IIdentityProvider interface {
	// *** Identity Provider **
	// CreateIdentityProvider creates an identity provider in a realm
	CreateIdentityProvider(ctx context.Context, token, realm string, providerRep gocloak.IdentityProviderRepresentation) (string, error)
	// GetIdentityProviders gets identity providers in a realm
	GetIdentityProviders(ctx context.Context, token, realm string) ([]*gocloak.IdentityProviderRepresentation, error)
	// GetIdentityProvider gets the identity provider in a realm
	GetIdentityProvider(ctx context.Context, token, realm, alias string) (*gocloak.IdentityProviderRepresentation, error)
	// UpdateIdentityProvider updates the identity provider in a realm
	UpdateIdentityProvider(ctx context.Context, token, realm, alias string, providerRep gocloak.IdentityProviderRepresentation) error
	// DeleteIdentityProvider deletes the identity provider in a realm
	DeleteIdentityProvider(ctx context.Context, token, realm, alias string) error
	// ImportIdentityProviderConfig parses and returns the identity provider config at a given URL
	ImportIdentityProviderConfig(ctx context.Context, token, realm, fromURL, providerID string) (map[string]string, error)
	// ImportIdentityProviderConfigFromFile parses and returns the identity provider config from a given file
	ImportIdentityProviderConfigFromFile(ctx context.Context, token, realm, providerID, fileName string, fileBody io.Reader) (map[string]string, error)
	// ExportIDPPublicBrokerConfig exports the broker config for a given alias
	ExportIDPPublicBrokerConfig(ctx context.Context, token, realm, alias string) (*string, error)
	// CreateIdentityProviderMapper creates an instance of an identity provider mapper associated with the given alias
	CreateIdentityProviderMapper(ctx context.Context, token, realm, alias string, mapper gocloak.IdentityProviderMapper) (string, error)
	// GetIdentityProviderMapperByID gets the mapper of an identity provider
	GetIdentityProviderMapperByID(ctx context.Context, token, realm, alias, mapperID string) (*gocloak.IdentityProviderMapper, error)
	// UpdateIdentityProviderMapper updates mapper of an identity provider
	UpdateIdentityProviderMapper(ctx context.Context, token, realm, alias string, mapper gocloak.IdentityProviderMapper) error
	// DeleteIdentityProviderMapper deletes an instance of an identity provider mapper associated with the given alias and mapper ID
	DeleteIdentityProviderMapper(ctx context.Context, token, realm, alias, mapperID string) error
	// GetIdentityProviderMappers returns list of mappers associated with an identity provider
	GetIdentityProviderMappers(ctx context.Context, token, realm, alias string) ([]*gocloak.IdentityProviderMapper, error)
}
