package gocloak

import (
	"context"
	"github.com/go-resty/resty/v2"
	"github.com/golang-jwt/jwt/v4"
)

// GoCloak holds all methods a client should fulfill
type GoCloak interface {
	Users() *Users

	Groups() *Groups

	Realm() *Realm

	RealmRoles() *RealmRoles

	ClientRoles() *ClientRoles

	Protection() *Protection

	IdentityProvider() *IdentityProvider

	Credentials() *Credentials

	// RestyClient returns a resty client that gocloak uses
	RestyClient() *resty.Client
	// Sets the resty Client that gocloak uses
	SetRestyClient(restyClient *resty.Client)

	// GetToken returns a token
	GetToken(ctx context.Context, realm string, options TokenOptions) (*JWT, error)
	// GetRequestingPartyToken returns a requesting party token with permissions granted by the server
	GetRequestingPartyToken(ctx context.Context, token, realm string, options RequestingPartyTokenOptions) (*JWT, error)
	// GetRequestingPartyPermissions returns a permissions granted by the server to requesting party
	GetRequestingPartyPermissions(ctx context.Context, token, realm string, options RequestingPartyTokenOptions) (*[]RequestingPartyPermission, error)
	// GetRequestingPartyPermissionDecision returns a permission decision granted by the server to requesting party
	GetRequestingPartyPermissionDecision(ctx context.Context, token, realm string, options RequestingPartyTokenOptions) (*RequestingPartyPermissionDecision, error)
	// Login sends a request to the token endpoint using user and client credentials
	Login(ctx context.Context, clientID, clientSecret, realm, username, password string) (*JWT, error)
	// LoginOtp performs a login with user credentials and otp token
	LoginOtp(ctx context.Context, clientID, clientSecret, realm, username, password, totp string) (*JWT, error)
	// Logout sends a request to the logout endpoint using refresh token
	Logout(ctx context.Context, clientID, clientSecret, realm, refreshToken string) error
	// LogoutPublicClient sends a request to the logout endpoint using refresh token
	LogoutPublicClient(ctx context.Context, idOfClient, realm, accessToken, refreshToken string) error
	// LogoutAllSessions logs out all sessions of a user given an id
	LogoutAllSessions(ctx context.Context, accessToken, realm, userID string) error
	// RevokeConsents revoke consent and offline tokens for particular client from user
	RevokeUserConsents(ctx context.Context, accessToken, realm, userID, clientID string) error
	// LogoutUserSessions logs out a single sessions of a user given a session id.
	// NOTE: this uses bearer token, but this token must belong to a user with proper privileges
	LogoutUserSession(ctx context.Context, accessToken, realm, session string) error
	// LoginClient sends a request to the token endpoint using client credentials
	LoginClient(ctx context.Context, clientID, clientSecret, realm string) (*JWT, error)
	// LoginClientTokenExchange requests a login on a specified users behalf. Returning a user's tokens.
	LoginClientTokenExchange(ctx context.Context, clientID, token, clientSecret, realm, targetClient, userID string) (*JWT, error)
	// LoginClientSignedJWT performs a login with client credentials and signed jwt claims
	LoginClientSignedJWT(ctx context.Context, idOfClient, realm string, key interface{}, signedMethod jwt.SigningMethod, expiresAt *jwt.NumericDate) (*JWT, error)
	// LoginAdmin login as admin
	LoginAdmin(ctx context.Context, username, password, realm string) (*JWT, error)
	// RefreshToken used to refresh the token
	RefreshToken(ctx context.Context, refreshToken, clientID, clientSecret, realm string) (*JWT, error)
	// DecodeAccessToken decodes the accessToken
	DecodeAccessToken(ctx context.Context, accessToken, realm string) (*jwt.Token, *jwt.MapClaims, error)
	// DecodeAccessTokenCustomClaims decodes the accessToken and fills the given claims
	DecodeAccessTokenCustomClaims(ctx context.Context, accessToken, realm string, claims jwt.Claims) (*jwt.Token, error)
	// RetrospectToken calls the openid-connect introspect endpoint
	RetrospectToken(ctx context.Context, accessToken, clientID, clientSecret, realm string) (*RetrospecTokenResult, error)
	// GetIssuer calls the issuer endpoint for the given realm
	GetIssuer(ctx context.Context, realm string) (*IssuerResponse, error)
	// GetCerts gets the public keys for the given realm
	GetCerts(ctx context.Context, realm string) (*CertResponse, error)
	// GetServerInfo returns the server info
	GetServerInfo(ctx context.Context, accessToken string) (*ServerInfoRepesentation, error)
	// GetUserInfo gets the user info for the given realm
	GetUserInfo(ctx context.Context, accessToken, realm string) (*UserInfo, error)
	// GetRawUserInfo calls the UserInfo endpoint and returns a raw json object
	GetRawUserInfo(ctx context.Context, accessToken, realm string) (map[string]interface{}, error)

	// ExecuteActionsEmail executes an actions email
	ExecuteActionsEmail(ctx context.Context, token, realm string, params ExecuteActionsEmail) error

	// CreateClient creates a new client
	CreateClient(ctx context.Context, accessToken, realm string, newClient Client) (string, error)
	// CreateClientScope creates a new clientScope
	CreateClientScope(ctx context.Context, accessToken, realm string, scope ClientScope) (string, error)
	// CreateComponent creates a new component
	CreateComponent(ctx context.Context, accessToken, realm string, component Component) (string, error)
	// CreateClientScopeMappingsRealmRoles creates realm-level roles to the client’s scope
	CreateClientScopeMappingsRealmRoles(ctx context.Context, token, realm, idOfClient string, roles []Role) error
	// CreateClientScopeMappingsClientRoles creates client-level roles from the client’s scope
	CreateClientScopeMappingsClientRoles(ctx context.Context, token, realm, idOfClient, idOfSelectedClient string, roles []Role) error
	// CreateClientScopesScopeMappingsRealmRoles creates realm-level roles to the client-scope
	CreateClientScopesScopeMappingsRealmRoles(ctx context.Context, token, realm, idOfClientScope string, roles []Role) error
	// CreateClientRepresentation creates a new client representation
	CreateClientRepresentation(ctx context.Context, realm string) (*Client, error)

	// UpdateRole updates the given role
	UpdateRole(ctx context.Context, accessToken, realm, idOfClient string, role Role) error
	// UpdateClient updates the given client
	UpdateClient(ctx context.Context, accessToken, realm string, updatedClient Client) error
	// UpdateClientScope updates the given clientScope
	UpdateClientScope(ctx context.Context, accessToken, realm string, scope ClientScope) error
	// UpdateClientRepresentation updates the given client representation
	UpdateClientRepresentation(ctx context.Context, accessToken, realm string, updatedClient Client) (*Client, error)

	// DeleteComponent deletes the given component
	DeleteComponent(ctx context.Context, accessToken, realm, componentID string) error
	// DeleteClient deletes the given client
	DeleteClient(ctx context.Context, accessToken, realm, idOfClient string) error
	// DeleteClientScope
	DeleteClientScope(ctx context.Context, accessToken, realm, scopeID string) error
	// DeleteClientScopeMappingsRealmRoles deletes realm-level roles from the client’s scope
	DeleteClientScopeMappingsRealmRoles(ctx context.Context, token, realm, idOfClient string, roles []Role) error
	// DeleteClientScopeMappingsClientRoles deletes client-level roles from the client’s scope
	DeleteClientScopeMappingsClientRoles(ctx context.Context, token, realm, idOfClient, idOfSelectedClient string, roles []Role) error
	// DeleteClientScopesScopeMappingsRealmRoles deletes realm-level roles from the client-scope
	DeleteClientScopesScopeMappingsRealmRoles(ctx context.Context, token, realm, idOfClientScope string, roles []Role) error
	// DeleteClientRepresentation deletes a given client representation
	DeleteClientRepresentation(ctx context.Context, accessToken, realm, clientID string) error

	// GetClient returns a client
	GetClient(ctx context.Context, accessToken, realm, idOfClient string) (*Client, error)
	// GetClientsDefaultScopes returns a list of the client's default scopes
	GetClientsDefaultScopes(ctx context.Context, token, realm, idOfClient string) ([]*ClientScope, error)
	// AddDefaultScopeToClient adds a client scope to the list of client's default scopes
	AddDefaultScopeToClient(ctx context.Context, token, realm, idOfClient, scopeID string) error
	// RemoveDefaultScopeFromClient removes a client scope from the list of client's default scopes
	RemoveDefaultScopeFromClient(ctx context.Context, token, realm, idOfClient, scopeID string) error
	// GetClientsOptionalScopes returns a list of the client's optional scopes
	GetClientsOptionalScopes(ctx context.Context, token, realm, idOfClient string) ([]*ClientScope, error)
	// AddOptionalScopeToClient adds a client scope to the list of client's optional scopes
	AddOptionalScopeToClient(ctx context.Context, token, realm, idOfClient, scopeID string) error
	// RemoveOptionalScopeFromClient deletes a client scope from the list of client's optional scopes
	RemoveOptionalScopeFromClient(ctx context.Context, token, realm, idOfClient, scopeID string) error
	// GetDefaultOptionalClientScopes returns a list of default realm optional scopes
	GetDefaultOptionalClientScopes(ctx context.Context, token, realm string) ([]*ClientScope, error)
	// GetDefaultDefaultClientScopes returns a list of default realm default scopes
	GetDefaultDefaultClientScopes(ctx context.Context, token, realm string) ([]*ClientScope, error)
	// GetClientScope returns a clientscope
	GetClientScope(ctx context.Context, token, realm, scopeID string) (*ClientScope, error)
	// GetClientScopes returns all client scopes
	GetClientScopes(ctx context.Context, token, realm string) ([]*ClientScope, error)
	// GetClientScopeMappings returns all scope mappings for the client
	GetClientScopeMappings(ctx context.Context, token, realm, idOfClient string) (*MappingsRepresentation, error)
	// GetClientScopeMappingsRealmRoles returns realm-level roles associated with the client’s scope
	GetClientScopeMappingsRealmRoles(ctx context.Context, token, realm, idOfClient string) ([]*Role, error)
	// GetClientScopeMappingsRealmRolesAvailable returns realm-level roles that are available to attach to this client’s scope
	GetClientScopeMappingsRealmRolesAvailable(ctx context.Context, token, realm, idOfClient string) ([]*Role, error)
	// GetClientScopesScopeMappingsRealmRolesAvailable returns realm-level roles that are available to attach to this client-scope
	GetClientScopesScopeMappingsRealmRolesAvailable(ctx context.Context, token, realm, idOfClientScope string) ([]*Role, error)
	// GetClientScopeMappingsClientRoles returns roles associated with a client’s scope
	GetClientScopeMappingsClientRoles(ctx context.Context, token, realm, idOfClient, idOfSelectedClient string) ([]*Role, error)
	// GetClientScopesScopeMappingsRealmRoles returns roles associated with a client-scope
	GetClientScopesScopeMappingsRealmRoles(ctx context.Context, token, realm, idOfClientScope string) ([]*Role, error)
	// GetClientScopeMappingsClientRolesAvailable returns available roles associated with a client’s scope
	GetClientScopeMappingsClientRolesAvailable(ctx context.Context, token, realm, idOfClient, idOfSelectedClient string) ([]*Role, error)
	// GetClientSecret returns a client's secret
	GetClientSecret(ctx context.Context, token, realm, idOfClient string) (*CredentialRepresentation, error)
	// GetClientServiceAccount retrieves the service account "user" for a client if enabled
	GetClientServiceAccount(ctx context.Context, token, realm, idOfClient string) (*User, error)
	// RegenerateClientSecret creates a new client secret returning the updated CredentialRepresentation
	RegenerateClientSecret(ctx context.Context, token, realm, idOfClient string) (*CredentialRepresentation, error)
	// GetKeyStoreConfig gets the keyStoreConfig
	GetKeyStoreConfig(ctx context.Context, accessToken, realm string) (*KeyStoreConfig, error)
	// GetComponents gets components of the given realm
	GetComponents(ctx context.Context, accessToken, realm string) ([]*Component, error)
	// GetDefaultGroups returns a list of default groups
	GetDefaultGroups(ctx context.Context, accessToken, realm string) ([]*Group, error)
	// AddDefaultGroup adds group to the list of default groups
	AddDefaultGroup(ctx context.Context, accessToken, realm, groupID string) error
	// RemoveDefaultGroup removes group from the list of default groups
	RemoveDefaultGroup(ctx context.Context, accessToken, realm, groupID string) error

	// GetGroupsByRole gets groups with specified roles assigned of given realm
	GetGroupsByRole(ctx context.Context, accessToken, realm string, roleName string) ([]*Group, error)

	// GetRoleMappingByGroupID gets the rolemapping for the given group id
	GetRoleMappingByGroupID(ctx context.Context, accessToken, realm, groupID string) (*MappingsRepresentation, error)
	// GetRoleMappingByUserID gets the rolemapping for the given user id
	GetRoleMappingByUserID(ctx context.Context, accessToken, realm, userID string) (*MappingsRepresentation, error)
	// GetClients gets the clients in the realm
	GetClients(ctx context.Context, accessToken, realm string, params GetClientsParams) ([]*Client, error)
	// GetClientOfflineSessions returns offline sessions associated with the client
	GetClientOfflineSessions(ctx context.Context, token, realm, idOfClient string) ([]*UserSessionRepresentation, error)
	// GetClientUserSessions returns user sessions associated with the client
	GetClientUserSessions(ctx context.Context, token, realm, idOfClient string) ([]*UserSessionRepresentation, error)
	// CreateClientProtocolMapper creates a protocol mapper in client scope
	CreateClientProtocolMapper(ctx context.Context, token, realm, idOfClient string, mapper ProtocolMapperRepresentation) (string, error)
	// CreateClientProtocolMapper updates a protocol mapper in client scope
	UpdateClientProtocolMapper(ctx context.Context, token, realm, idOfClient, mapperID string, mapper ProtocolMapperRepresentation) error
	// DeleteClientProtocolMapper deletes a protocol mapper in client scope
	DeleteClientProtocolMapper(ctx context.Context, token, realm, idOfClient, mapperID string) error
	// GetClientRepresentation return a client representation
	GetClientRepresentation(ctx context.Context, accessToken, realm, clientID string) (*Client, error)
	// GetAdapterConfiguration returns a adapter configuration
	GetAdapterConfiguration(ctx context.Context, accessToken, realm, clientID string) (*AdapterConfiguration, error)

	// ---------------
	// Events API
	// ---------------

	// GetEvents returns events
	GetEvents(ctx context.Context, token string, realm string, params GetEventsParams) ([]*EventRepresentation, error)

	// -------------------
	// RequiredActions API
	// -------------------

	// UpdateRequiredAction updates a required action for a given realm
	UpdateRequiredAction(ctx context.Context, token string, realm string, requiredAction RequiredActionProviderRepresentation) error
}
