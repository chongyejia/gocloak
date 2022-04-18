package api

import (
	"context"
	"github.com/chongyejia/gocloak/v11"
)

type ICredentials interface {

	// ---------------
	// Credentials API
	// ---------------

	// GetCredentialRegistrators returns credentials registrators
	GetCredentialRegistrators(ctx context.Context, token, realm string) ([]string, error)
	// GetConfiguredUserStorageCredentialTypes returns credential types, which are provided by the user storage where user is stored
	GetConfiguredUserStorageCredentialTypes(ctx context.Context, token, realm, userID string) ([]string, error)

	// GetCredentials returns credentials available for a given user
	GetCredentials(ctx context.Context, token, realm, UserID string) ([]*gocloak.CredentialRepresentation, error)
	// DeleteCredentials deletes the given credential for a given user
	DeleteCredentials(ctx context.Context, token, realm, UserID, CredentialID string) error
	// UpdateCredentialUserLabel updates label for the given credential for the given user
	UpdateCredentialUserLabel(ctx context.Context, token, realm, userID, credentialID, userLabel string) error
	// DisableAllCredentialsByType disables all credentials for a user of a specific type
	DisableAllCredentialsByType(ctx context.Context, token, realm, userID string, types []string) error
	// MoveCredentialBehind move a credential to a position behind another credential
	MoveCredentialBehind(ctx context.Context, token, realm, userID, credentialID, newPreviousCredentialID string) error
	// MoveCredentialToFirst move a credential to a first position in the credentials list of the user
	MoveCredentialToFirst(ctx context.Context, token, realm, userID, credentialID string) error
}
