package gocloak

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
	"github.com/segmentio/ksuid"

	"github.com/chongyejia/gocloak/v11/pkg/jwx"
)

type gocloak struct {
	basePath    string
	certsCache  sync.Map
	certsLock   sync.Mutex
	restyClient *resty.Client
	Config      struct {
		CertsInvalidateTime time.Duration
		authAdminRealms     string
		authRealms          string
		tokenEndpoint       string
		logoutEndpoint      string
		openIDConnect       string
	}
	groups           *Groups
	users            *Users
	realm            *Realm
	realmRoles       *RealmRoles
	clientRoles      *ClientRoles
	protection       *Protection
	identityProvider *IdentityProvider
	credentials      *Credentials
}

const (
	adminClientID string = "admin-cli"
	urlSeparator  string = "/"
)

func makeURL(path ...string) string {
	return strings.Join(path, urlSeparator)
}

func (client *gocloak) getRequest(ctx context.Context) *resty.Request {
	var err HTTPErrorResponse
	return injectTracingHeaders(
		ctx, client.restyClient.R().
			SetContext(ctx).
			SetError(&err),
	)
}

func (client *gocloak) getRequestWithBearerAuthNoCache(ctx context.Context, token string) *resty.Request {
	return client.getRequest(ctx).
		SetAuthToken(token).
		SetHeader("Content-Type", "application/json").
		SetHeader("Cache-Control", "no-cache")
}

func (client *gocloak) getRequestWithBearerAuth(ctx context.Context, token string) *resty.Request {
	return client.getRequest(ctx).
		SetAuthToken(token).
		SetHeader("Content-Type", "application/json")
}

func (client *gocloak) getRequestWithBearerAuthXMLHeader(ctx context.Context, token string) *resty.Request {
	return client.getRequest(ctx).
		SetAuthToken(token).
		SetHeader("Content-Type", "application/xml;charset=UTF-8")
}

func (client *gocloak) getRequestWithBasicAuth(ctx context.Context, clientID, clientSecret string) *resty.Request {
	req := client.getRequest(ctx).
		SetHeader("Content-Type", "application/x-www-form-urlencoded")
	// Public client doesn't require Basic Auth
	if len(clientID) > 0 && len(clientSecret) > 0 {
		httpBasicAuth := base64.StdEncoding.EncodeToString([]byte(clientID + ":" + clientSecret))
		req.SetHeader("Authorization", "Basic "+httpBasicAuth)
	}

	return req
}

func (client *gocloak) getRequestingParty(ctx context.Context, token string, realm string, options RequestingPartyTokenOptions, res interface{}) (*resty.Response, error) {
	return client.getRequestWithBearerAuth(ctx, token).
		SetFormData(options.FormData()).
		SetFormDataFromValues(url.Values{"permission": PStringSlice(options.Permissions)}).
		SetResult(&res).
		Post(client.getRealmURL(realm, client.Config.tokenEndpoint))
}

func checkForError(resp *resty.Response, err error, errMessage string) error {
	if err != nil {
		return &APIError{
			Code:    0,
			Message: errors.Wrap(err, errMessage).Error(),
			Type:    ParseAPIErrType(err),
		}
	}

	if resp == nil {
		return &APIError{
			Message: "empty response",
			Type:    ParseAPIErrType(err),
		}
	}

	if resp.IsError() {
		var msg string

		if e, ok := resp.Error().(*HTTPErrorResponse); ok && e.NotEmpty() {
			msg = fmt.Sprintf("%s: %s", resp.Status(), e)
		} else {
			msg = resp.Status()
		}

		return &APIError{
			Code:    resp.StatusCode(),
			Message: msg,
			Type:    ParseAPIErrType(err),
		}
	}

	return nil
}

func getID(resp *resty.Response) string {
	header := resp.Header().Get("Location")
	splittedPath := strings.Split(header, urlSeparator)
	return splittedPath[len(splittedPath)-1]
}

func findUsedKey(usedKeyID string, keys []CertResponseKey) *CertResponseKey {
	for _, key := range keys {
		if *(key.Kid) == usedKeyID {
			return &key
		}
	}

	return nil
}

func injectTracingHeaders(ctx context.Context, req *resty.Request) *resty.Request {
	// look for span in context, do nothing if span is not found
	span := opentracing.SpanFromContext(ctx)
	if span == nil {
		return req
	}

	// look for tracer in context, use global tracer if not found
	tracer, ok := ctx.Value(tracerContextKey).(opentracing.Tracer)
	if !ok || tracer == nil {
		tracer = opentracing.GlobalTracer()
	}

	// inject tracing header into request
	err := tracer.Inject(span.Context(), opentracing.HTTPHeaders, opentracing.HTTPHeadersCarrier(req.Header))

	if err != nil {
		return req
	}

	return req
}

// ===============
// Keycloak client
// ===============

// NewClient creates a new Client
func NewClient(basePath string, options ...func(*gocloak)) GoCloak {
	c := gocloak{
		basePath:    strings.TrimRight(basePath, urlSeparator),
		restyClient: resty.New(),
	}

	c.Config.CertsInvalidateTime = 10 * time.Minute
	c.Config.authAdminRealms = makeURL("admin", "realms")
	c.Config.authRealms = makeURL("realms")
	c.Config.tokenEndpoint = makeURL("protocol", "openid-connect", "token")
	c.Config.logoutEndpoint = makeURL("protocol", "openid-connect", "logout")
	c.Config.openIDConnect = makeURL("protocol", "openid-connect")

	for _, option := range options {
		option(&c)
	}

	c.groups = &Groups{client: &c}
	c.users = &Users{client: &c}
	c.realmRoles = &RealmRoles{client: &c}
	c.clientRoles = &ClientRoles{client: &c}
	c.protection = &Protection{client: &c}
	c.identityProvider = &IdentityProvider{client: &c}
	return &c
}

func (client *gocloak) RestyClient() *resty.Client {
	return client.restyClient
}

func (client *gocloak) Users() *Users {
	return client.users
}
func (client *gocloak) Protection() *Protection {
	return client.protection
}

func (client *gocloak) Realm() *Realm {
	return client.realm
}

func (client *gocloak) Credentials() *Credentials {
	return client.credentials
}

func (client *gocloak) IdentityProvider() *IdentityProvider {
	return client.identityProvider
}

func (client *gocloak) RealmRoles() *RealmRoles {
	return client.realmRoles
}

func (client *gocloak) ClientRoles() *ClientRoles {
	return client.clientRoles
}

func (client *gocloak) Groups() *Groups {
	return client.groups
}

func (client *gocloak) SetRestyClient(restyClient *resty.Client) {
	client.restyClient = restyClient
}

func (client *gocloak) getRealmURL(realm string, path ...string) string {
	path = append([]string{client.basePath, client.Config.authRealms, realm}, path...)
	return makeURL(path...)
}

func (client *gocloak) getAdminRealmURL(realm string, path ...string) string {
	path = append([]string{client.basePath, client.Config.authAdminRealms, realm}, path...)
	return makeURL(path...)
}

// ==== Functional Options ===

// SetAuthRealms sets the auth realm
func SetAuthRealms(url string) func(client *gocloak) {
	return func(client *gocloak) {
		client.Config.authRealms = url
	}
}

// SetAuthAdminRealms sets the auth admin realm
func SetAuthAdminRealms(url string) func(client *gocloak) {
	return func(client *gocloak) {
		client.Config.authAdminRealms = url
	}
}

// SetTokenEndpoint sets the token endpoint
func SetTokenEndpoint(url string) func(client *gocloak) {
	return func(client *gocloak) {
		client.Config.tokenEndpoint = url
	}
}

// SetLogoutEndpoint sets the logout
func SetLogoutEndpoint(url string) func(client *gocloak) {
	return func(client *gocloak) {
		client.Config.logoutEndpoint = url
	}
}

// SetOpenIDConnectEndpoint sets the logout
func SetOpenIDConnectEndpoint(url string) func(client *gocloak) {
	return func(client *gocloak) {
		client.Config.openIDConnect = url
	}
}

// SetCertCacheInvalidationTime sets the logout
func SetCertCacheInvalidationTime(duration time.Duration) func(client *gocloak) {
	return func(client *gocloak) {
		client.Config.CertsInvalidateTime = duration
	}
}

func (client *gocloak) GetServerInfo(ctx context.Context, accessToken string) (*ServerInfoRepesentation, error) {
	errMessage := "could not get server info"
	var result ServerInfoRepesentation

	resp, err := client.getRequestWithBearerAuth(ctx, accessToken).
		SetResult(&result).
		Get(makeURL(client.basePath, "auth", "admin", "serverinfo"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetUserInfo calls the UserInfo endpoint
func (client *gocloak) GetUserInfo(ctx context.Context, accessToken, realm string) (*UserInfo, error) {
	const errMessage = "could not get user info"

	var result UserInfo
	resp, err := client.getRequestWithBearerAuth(ctx, accessToken).
		SetResult(&result).
		Get(client.getRealmURL(realm, client.Config.openIDConnect, "userinfo"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetRawUserInfo calls the UserInfo endpoint and returns a raw json object
func (client *gocloak) GetRawUserInfo(ctx context.Context, accessToken, realm string) (map[string]interface{}, error) {
	const errMessage = "could not get user info"

	var result map[string]interface{}
	resp, err := client.getRequestWithBearerAuth(ctx, accessToken).
		SetResult(&result).
		Get(client.getRealmURL(realm, client.Config.openIDConnect, "userinfo"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

func (client *gocloak) getNewCerts(ctx context.Context, realm string) (*CertResponse, error) {
	const errMessage = "could not get newCerts"

	var result CertResponse
	resp, err := client.getRequest(ctx).
		SetResult(&result).
		Get(client.getRealmURL(realm, client.Config.openIDConnect, "certs"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetCerts fetches certificates for the given realm from the public /open-id-connect/certs endpoint
func (client *gocloak) GetCerts(ctx context.Context, realm string) (*CertResponse, error) {
	const errMessage = "could not get certs"

	if cert, ok := client.certsCache.Load(realm); ok {
		return cert.(*CertResponse), nil
	}

	client.certsLock.Lock()
	defer client.certsLock.Unlock()

	if cert, ok := client.certsCache.Load(realm); ok {
		return cert.(*CertResponse), nil
	}

	cert, err := client.getNewCerts(ctx, realm)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	client.certsCache.Store(realm, cert)
	time.AfterFunc(client.Config.CertsInvalidateTime, func() {
		client.certsCache.Delete(realm)
	})

	return cert, nil
}

// GetIssuer gets the issuer of the given realm
func (client *gocloak) GetIssuer(ctx context.Context, realm string) (*IssuerResponse, error) {
	const errMessage = "could not get issuer"

	var result IssuerResponse
	resp, err := client.getRequest(ctx).
		SetResult(&result).
		Get(client.getRealmURL(realm))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// RetrospectToken calls the openid-connect introspect endpoint
func (client *gocloak) RetrospectToken(ctx context.Context, accessToken, clientID, clientSecret, realm string) (*RetrospecTokenResult, error) {
	const errMessage = "could not introspect requesting party token"

	var result RetrospecTokenResult
	resp, err := client.getRequestWithBasicAuth(ctx, clientID, clientSecret).
		SetFormData(map[string]string{
			"token_type_hint": "requesting_party_token",
			"token":           accessToken,
		}).
		SetResult(&result).
		Post(client.getRealmURL(realm, client.Config.tokenEndpoint, "introspect"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// DecodeAccessToken decodes the accessToken
func (client *gocloak) DecodeAccessToken(ctx context.Context, accessToken, realm string) (*jwt.Token, *jwt.MapClaims, error) {
	const errMessage = "could not decode access token"
	accessToken = strings.Replace(accessToken, "Bearer ", "", 1)

	decodedHeader, err := jwx.DecodeAccessTokenHeader(accessToken)
	if err != nil {
		return nil, nil, errors.Wrap(err, errMessage)
	}

	certResult, err := client.GetCerts(ctx, realm)
	if err != nil {
		return nil, nil, errors.Wrap(err, errMessage)
	}
	if certResult.Keys == nil {
		return nil, nil, errors.Wrap(errors.New("there is no keys to decode the token"), errMessage)
	}
	usedKey := findUsedKey(decodedHeader.Kid, *certResult.Keys)
	if usedKey == nil {
		return nil, nil, errors.Wrap(errors.New("cannot find a key to decode the token"), errMessage)
	}

	return jwx.DecodeAccessToken(accessToken, usedKey.E, usedKey.N)
}

// DecodeAccessTokenCustomClaims decodes the accessToken and writes claims into the given claims
func (client *gocloak) DecodeAccessTokenCustomClaims(ctx context.Context, accessToken, realm string, claims jwt.Claims) (*jwt.Token, error) {
	const errMessage = "could not decode access token with custom claims"
	accessToken = strings.Replace(accessToken, "Bearer ", "", 1)

	decodedHeader, err := jwx.DecodeAccessTokenHeader(accessToken)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	certResult, err := client.GetCerts(ctx, realm)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}
	if certResult.Keys == nil {
		return nil, errors.Wrap(errors.New("there is no keys to decode the token"), errMessage)
	}
	usedKey := findUsedKey(decodedHeader.Kid, *certResult.Keys)
	if usedKey == nil {
		return nil, errors.Wrap(errors.New("cannot find a key to decode the token"), errMessage)
	}

	return jwx.DecodeAccessTokenCustomClaims(accessToken, usedKey.E, usedKey.N, claims)
}

func (client *gocloak) GetToken(ctx context.Context, realm string, options TokenOptions) (*JWT, error) {
	const errMessage = "could not get token"

	var token JWT
	var req *resty.Request

	if !NilOrEmpty(options.ClientSecret) {
		req = client.getRequestWithBasicAuth(ctx, *options.ClientID, *options.ClientSecret)
	} else {
		req = client.getRequest(ctx)
	}

	resp, err := req.SetFormData(options.FormData()).
		SetResult(&token).
		Post(client.getRealmURL(realm, client.Config.tokenEndpoint))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &token, nil
}

// GetRequestingPartyToken returns a requesting party token with permissions granted by the server
func (client *gocloak) GetRequestingPartyToken(ctx context.Context, token, realm string, options RequestingPartyTokenOptions) (*JWT, error) {
	const errMessage = "could not get requesting party token"

	var res JWT

	resp, err := client.getRequestingParty(ctx, token, realm, options, &res)

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &res, nil
}

// GetRequestingPartyPermissions returns a requesting party permissions granted by the server
func (client *gocloak) GetRequestingPartyPermissions(ctx context.Context, token, realm string, options RequestingPartyTokenOptions) (*[]RequestingPartyPermission, error) {
	const errMessage = "could not get requesting party token"

	var res []RequestingPartyPermission

	options.ResponseMode = StringP("permissions")

	resp, err := client.getRequestingParty(ctx, token, realm, options, &res)

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &res, nil
}

// GetRequestingPartyPermissionDecision returns a requesting party permission decision granted by the server
func (client *gocloak) GetRequestingPartyPermissionDecision(ctx context.Context, token, realm string, options RequestingPartyTokenOptions) (*RequestingPartyPermissionDecision, error) {
	const errMessage = "could not get requesting party token"

	var res RequestingPartyPermissionDecision

	options.ResponseMode = StringP("decision")

	resp, err := client.getRequestingParty(ctx, token, realm, options, &res)

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &res, nil
}

// RefreshToken refreshes the given token.
// May return a *APIError with further details about the issue.
func (client *gocloak) RefreshToken(ctx context.Context, refreshToken, clientID, clientSecret, realm string) (*JWT, error) {
	return client.GetToken(ctx, realm, TokenOptions{
		ClientID:     &clientID,
		ClientSecret: &clientSecret,
		GrantType:    StringP("refresh_token"),
		RefreshToken: &refreshToken,
	})
}

// LoginAdmin performs a login with Admin client
func (client *gocloak) LoginAdmin(ctx context.Context, username, password, realm string) (*JWT, error) {
	return client.GetToken(ctx, realm, TokenOptions{
		ClientID:  StringP(adminClientID),
		GrantType: StringP("password"),
		Username:  &username,
		Password:  &password,
	})
}

// LoginClient performs a login with client credentials
func (client *gocloak) LoginClient(ctx context.Context, clientID, clientSecret, realm string) (*JWT, error) {
	return client.GetToken(ctx, realm, TokenOptions{
		ClientID:     &clientID,
		ClientSecret: &clientSecret,
		GrantType:    StringP("client_credentials"),
	})
}

// LoginClientTokenExchange will exchange the presented token for a user's token
// Requires Token-Exchange is enabled: https://www.keycloak.org/docs/latest/securing_apps/index.html#_token-exchange
func (client *gocloak) LoginClientTokenExchange(ctx context.Context, clientID, token, clientSecret, realm, targetClient, userID string) (*JWT, error) {
	tokenOptions := TokenOptions{
		ClientID:           &clientID,
		ClientSecret:       &clientSecret,
		GrantType:          StringP("urn:ietf:params:oauth:grant-type:token-exchange"),
		SubjectToken:       &token,
		RequestedTokenType: StringP("urn:ietf:params:oauth:token-type:refresh_token"),
		Audience:           &targetClient,
	}
	if userID != "" {
		tokenOptions.RequestedSubject = &userID
	}
	return client.GetToken(ctx, realm, tokenOptions)
}

// LoginClientSignedJWT performs a login with client credentials and signed jwt claims
func (client *gocloak) LoginClientSignedJWT(
	ctx context.Context,
	clientID,
	realm string,
	key interface{},
	signedMethod jwt.SigningMethod,
	expiresAt *jwt.NumericDate,
) (*JWT, error) {
	claims := jwt.RegisteredClaims{
		ExpiresAt: expiresAt,
		Issuer:    clientID,
		Subject:   clientID,
		ID:        ksuid.New().String(),
		Audience: jwt.ClaimStrings{
			client.getRealmURL(realm),
		},
	}
	assertion, err := jwx.SignClaims(claims, key, signedMethod)
	if err != nil {
		return nil, err
	}

	return client.GetToken(ctx, realm, TokenOptions{
		ClientID:            &clientID,
		GrantType:           StringP("client_credentials"),
		ClientAssertionType: StringP("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
		ClientAssertion:     &assertion,
	})
}

// Login performs a login with user credentials and a client
func (client *gocloak) Login(ctx context.Context, clientID, clientSecret, realm, username, password string) (*JWT, error) {
	return client.GetToken(ctx, realm, TokenOptions{
		ClientID:     &clientID,
		ClientSecret: &clientSecret,
		GrantType:    StringP("password"),
		Username:     &username,
		Password:     &password,
	})
}

// LoginOtp performs a login with user credentials and otp token
func (client *gocloak) LoginOtp(ctx context.Context, clientID, clientSecret, realm, username, password, totp string) (*JWT, error) {
	return client.GetToken(ctx, realm, TokenOptions{
		ClientID:     &clientID,
		ClientSecret: &clientSecret,
		GrantType:    StringP("password"),
		Username:     &username,
		Password:     &password,
		Totp:         &totp,
	})
}

// Logout logs out users with refresh token
func (client *gocloak) Logout(ctx context.Context, clientID, clientSecret, realm, refreshToken string) error {
	const errMessage = "could not logout"

	resp, err := client.getRequestWithBasicAuth(ctx, clientID, clientSecret).
		SetFormData(map[string]string{
			"client_id":     clientID,
			"refresh_token": refreshToken,
		}).
		Post(client.getRealmURL(realm, client.Config.logoutEndpoint))

	return checkForError(resp, err, errMessage)
}

func (client *gocloak) LogoutPublicClient(ctx context.Context, clientID, realm, accessToken, refreshToken string) error {
	const errMessage = "could not logout public client"

	resp, err := client.getRequestWithBearerAuth(ctx, accessToken).
		SetFormData(map[string]string{
			"client_id":     clientID,
			"refresh_token": refreshToken,
		}).
		Post(client.getRealmURL(realm, client.Config.logoutEndpoint))

	return checkForError(resp, err, errMessage)
}

// LogoutAllSessions logs out all sessions of a user given an id
func (client *gocloak) LogoutAllSessions(ctx context.Context, accessToken, realm, userID string) error {
	const errMessage = "could not logout"

	resp, err := client.getRequestWithBearerAuth(ctx, accessToken).
		Post(client.getAdminRealmURL(realm, "users", userID, "logout"))

	return checkForError(resp, err, errMessage)
}

func (client *gocloak) RevokeUserConsents(ctx context.Context, accessToken, realm, userID, clientID string) error {
	const errMessage = "could not revoke consents"

	resp, err := client.getRequestWithBearerAuth(ctx, accessToken).
		Delete(client.getAdminRealmURL(realm, "users", userID, "consents", clientID))

	return checkForError(resp, err, errMessage)
}

// LogoutUserSessions logs out a single sessions of a user given a session id
func (client *gocloak) LogoutUserSession(ctx context.Context, accessToken, realm, session string) error {
	const errMessage = "could not logout"

	resp, err := client.getRequestWithBearerAuth(ctx, accessToken).
		Delete(client.getAdminRealmURL(realm, "sessions", session))

	return checkForError(resp, err, errMessage)
}

// ExecuteActionsEmail executes an actions email
func (client *gocloak) ExecuteActionsEmail(ctx context.Context, token, realm string, params ExecuteActionsEmail) error {
	const errMessage = "could not execute actions email"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return errors.Wrap(err, errMessage)
	}

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(params.Actions).
		SetQueryParams(queryParams).
		Put(client.getAdminRealmURL(realm, "users", *(params.UserID), "execute-actions-email"))

	return checkForError(resp, err, errMessage)
}

func (g *Groups) CreateGroup(ctx context.Context, token, realm string, group Group) (string, error) {
	const errMessage = "could not create group"

	resp, err := g.client.getRequestWithBearerAuth(ctx, token).
		SetBody(group).
		Post(g.client.getAdminRealmURL(realm, "groups"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}
	return getID(resp), nil
}

func (client *gocloak) CreateComponent(ctx context.Context, token, realm string, component Component) (string, error) {
	const errMessage = "could not create component"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(component).
		Post(client.getAdminRealmURL(realm, "components"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

func (client *gocloak) CreateClient(ctx context.Context, accessToken, realm string, newClient Client) (string, error) {
	const errMessage = "could not create client"

	resp, err := client.getRequestWithBearerAuth(ctx, accessToken).
		SetBody(newClient).
		Post(client.getAdminRealmURL(realm, "clients"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// CreateClientRepresentation creates a new client representation
func (client *gocloak) CreateClientRepresentation(ctx context.Context, realm string) (*Client, error) {
	const errMessage = "could not create client representation"

	var result Client

	resp, err := client.getRequest(ctx).
		SetResult(&result).
		SetBody(Client{}).
		Post(client.getRealmURL(realm, "clients-registrations", "default"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// CreateClientScope creates a new client scope
func (client *gocloak) CreateClientScope(ctx context.Context, token, realm string, scope ClientScope) (string, error) {
	const errMessage = "could not create client scope"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(scope).
		Post(client.getAdminRealmURL(realm, "client-scopes"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// UpdateClient updates the given Client
func (client *gocloak) UpdateClient(ctx context.Context, token, realm string, updatedClient Client) error {
	const errMessage = "could not update client"

	if NilOrEmpty(updatedClient.ID) {
		return errors.Wrap(errors.New("ID of a client required"), errMessage)
	}

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(updatedClient).
		Put(client.getAdminRealmURL(realm, "clients", PString(updatedClient.ID)))

	return checkForError(resp, err, errMessage)
}

// UpdateClientRepresentation updates the given client representation
func (client *gocloak) UpdateClientRepresentation(ctx context.Context, accessToken, realm string, updatedClient Client) (*Client, error) {
	const errMessage = "could not update client representation"

	if NilOrEmpty(updatedClient.ID) {
		return nil, errors.Wrap(errors.New("ID of a client required"), errMessage)
	}

	var result Client

	resp, err := client.getRequestWithBearerAuth(ctx, accessToken).
		SetResult(&result).
		SetBody(updatedClient).
		Put(client.getRealmURL(realm, "clients-registrations", "default", PString(updatedClient.ID)))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

func (client *gocloak) UpdateRole(ctx context.Context, token, realm, idOfClient string, role Role) error {
	const errMessage = "could not update role"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(role).
		Put(client.getAdminRealmURL(realm, "clients", idOfClient, "roles", PString(role.Name)))

	return checkForError(resp, err, errMessage)
}

func (client *gocloak) UpdateClientScope(ctx context.Context, token, realm string, scope ClientScope) error {
	const errMessage = "could not update client scope"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(scope).
		Put(client.getAdminRealmURL(realm, "client-scopes", PString(scope.ID)))

	return checkForError(resp, err, errMessage)
}

// DeleteClient deletes a given client
func (client *gocloak) DeleteClient(ctx context.Context, token, realm, idOfClient string) error {
	const errMessage = "could not delete client"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Delete(client.getAdminRealmURL(realm, "clients", idOfClient))

	return checkForError(resp, err, errMessage)
}

func (client *gocloak) DeleteComponent(ctx context.Context, token, realm, componentID string) error {
	const errMessage = "could not delete component"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Delete(client.getAdminRealmURL(realm, "components", componentID))

	return checkForError(resp, err, errMessage)
}

// DeleteClientRepresentation deletes a given client representation
func (client *gocloak) DeleteClientRepresentation(ctx context.Context, accessToken, realm, clientID string) error {
	const errMessage = "could not delete client representation"

	resp, err := client.getRequestWithBearerAuth(ctx, accessToken).
		Delete(client.getRealmURL(realm, "clients-registrations", "default", clientID))

	return checkForError(resp, err, errMessage)
}

func (client *gocloak) DeleteClientScope(ctx context.Context, token, realm, scopeID string) error {
	const errMessage = "could not delete client scope"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Delete(client.getAdminRealmURL(realm, "client-scopes", scopeID))

	return checkForError(resp, err, errMessage)
}

// GetClient returns a client
func (client *gocloak) GetClient(ctx context.Context, token, realm, idOfClient string) (*Client, error) {
	const errMessage = "could not get client"

	var result Client

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "clients", idOfClient))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetClientRepresentation returns a client representation
func (client *gocloak) GetClientRepresentation(ctx context.Context, accessToken, realm, clientID string) (*Client, error) {
	const errMessage = "could not get client representation"

	var result Client

	resp, err := client.getRequestWithBearerAuth(ctx, accessToken).
		SetResult(&result).
		Get(client.getRealmURL(realm, "clients-registrations", "default", clientID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetAdapterConfiguration returns a adapter configuration
func (client *gocloak) GetAdapterConfiguration(ctx context.Context, accessToken, realm, clientID string) (*AdapterConfiguration, error) {
	const errMessage = "could not get adapter configuration"

	var result AdapterConfiguration

	resp, err := client.getRequestWithBearerAuth(ctx, accessToken).
		SetResult(&result).
		Get(client.getRealmURL(realm, "clients-registrations", "install", clientID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetClientsDefaultScopes returns a list of the client's default scopes
func (client *gocloak) GetClientsDefaultScopes(ctx context.Context, token, realm, idOfClient string) ([]*ClientScope, error) {
	const errMessage = "could not get clients default scopes"

	var result []*ClientScope

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "clients", idOfClient, "default-client-scopes"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// AddDefaultScopeToClient adds a client scope to the list of client's default scopes
func (client *gocloak) AddDefaultScopeToClient(ctx context.Context, token, realm, idOfClient, scopeID string) error {
	const errMessage = "could not add default scope to client"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Put(client.getAdminRealmURL(realm, "clients", idOfClient, "default-client-scopes", scopeID))

	return checkForError(resp, err, errMessage)
}

// RemoveDefaultScopeFromClient removes a client scope from the list of client's default scopes
func (client *gocloak) RemoveDefaultScopeFromClient(ctx context.Context, token, realm, idOfClient, scopeID string) error {
	const errMessage = "could not remove default scope from client"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Delete(client.getAdminRealmURL(realm, "clients", idOfClient, "default-client-scopes", scopeID))

	return checkForError(resp, err, errMessage)
}

// GetClientsOptionalScopes returns a list of the client's optional scopes
func (client *gocloak) GetClientsOptionalScopes(ctx context.Context, token, realm, idOfClient string) ([]*ClientScope, error) {
	const errMessage = "could not get clients optional scopes"

	var result []*ClientScope

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "clients", idOfClient, "optional-client-scopes"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// AddOptionalScopeToClient adds a client scope to the list of client's optional scopes
func (client *gocloak) AddOptionalScopeToClient(ctx context.Context, token, realm, idOfClient, scopeID string) error {
	const errMessage = "could not add optional scope to client"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Put(client.getAdminRealmURL(realm, "clients", idOfClient, "optional-client-scopes", scopeID))

	return checkForError(resp, err, errMessage)
}

// RemoveOptionalScopeFromClient deletes a client scope from the list of client's optional scopes
func (client *gocloak) RemoveOptionalScopeFromClient(ctx context.Context, token, realm, idOfClient, scopeID string) error {
	const errMessage = "could not remove optional scope from client"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Delete(client.getAdminRealmURL(realm, "clients", idOfClient, "optional-client-scopes", scopeID))

	return checkForError(resp, err, errMessage)
}

// GetDefaultOptionalClientScopes returns a list of default realm optional scopes
func (client *gocloak) GetDefaultOptionalClientScopes(ctx context.Context, token, realm string) ([]*ClientScope, error) {
	const errMessage = "could not get default optional client scopes"

	var result []*ClientScope

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "default-optional-client-scopes"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetDefaultDefaultClientScopes returns a list of default realm default scopes
func (client *gocloak) GetDefaultDefaultClientScopes(ctx context.Context, token, realm string) ([]*ClientScope, error) {
	const errMessage = "could not get default client scopes"

	var result []*ClientScope

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "default-default-client-scopes"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientScope returns a clientscope
func (client *gocloak) GetClientScope(ctx context.Context, token, realm, scopeID string) (*ClientScope, error) {
	const errMessage = "could not get client scope"

	var result ClientScope

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "client-scopes", scopeID))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetClientScopes returns all client scopes
func (client *gocloak) GetClientScopes(ctx context.Context, token, realm string) ([]*ClientScope, error) {
	const errMessage = "could not get client scopes"

	var result []*ClientScope

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "client-scopes"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientScopeMappings returns all scope mappings for the client
func (client *gocloak) GetClientScopeMappings(ctx context.Context, token, realm, idOfClient string) (*MappingsRepresentation, error) {
	const errMessage = "could not get all scope mappings for the client"

	var result *MappingsRepresentation

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "clients", idOfClient, "scope-mappings"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientScopeMappingsRealmRoles returns realm-level roles associated with the client’s scope
func (client *gocloak) GetClientScopeMappingsRealmRoles(ctx context.Context, token, realm, idOfClient string) ([]*Role, error) {
	const errMessage = "could not get realm-level roles with the client’s scope"

	var result []*Role

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "clients", idOfClient, "scope-mappings", "realm"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientScopeMappingsRealmRolesAvailable returns realm-level roles that are available to attach to this client’s scope
func (client *gocloak) GetClientScopeMappingsRealmRolesAvailable(ctx context.Context, token, realm, idOfClient string) ([]*Role, error) {
	const errMessage = "could not get available realm-level roles with the client’s scope"

	var result []*Role

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "clients", idOfClient, "scope-mappings", "realm", "available"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// CreateClientScopeMappingsRealmRoles create realm-level roles to the client’s scope
func (client *gocloak) CreateClientScopeMappingsRealmRoles(ctx context.Context, token, realm, idOfClient string, roles []Role) error {
	const errMessage = "could not create realm-level roles to the client’s scope"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(client.getAdminRealmURL(realm, "clients", idOfClient, "scope-mappings", "realm"))

	return checkForError(resp, err, errMessage)
}

// DeleteClientScopeMappingsRealmRoles deletes realm-level roles from the client’s scope
func (client *gocloak) DeleteClientScopeMappingsRealmRoles(ctx context.Context, token, realm, idOfClient string, roles []Role) error {
	const errMessage = "could not delete realm-level roles from the client’s scope"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(client.getAdminRealmURL(realm, "clients", idOfClient, "scope-mappings", "realm"))

	return checkForError(resp, err, errMessage)
}

// GetClientScopeMappingsClientRoles returns roles associated with a client’s scope
func (client *gocloak) GetClientScopeMappingsClientRoles(ctx context.Context, token, realm, idOfClient, idOfSelectedClient string) ([]*Role, error) {
	const errMessage = "could not get roles associated with a client’s scope"

	var result []*Role

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "clients", idOfClient, "scope-mappings", "clients", idOfSelectedClient))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientScopeMappingsClientRolesAvailable returns available roles associated with a client’s scope
func (client *gocloak) GetClientScopeMappingsClientRolesAvailable(ctx context.Context, token, realm, idOfClient, idOfSelectedClient string) ([]*Role, error) {
	const errMessage = "could not get available roles associated with a client’s scope"

	var result []*Role

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "clients", idOfClient, "scope-mappings", "clients", idOfSelectedClient, "available"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// CreateClientScopeMappingsClientRoles creates client-level roles from the client’s scope
func (client *gocloak) CreateClientScopeMappingsClientRoles(ctx context.Context, token, realm, idOfClient, idOfSelectedClient string, roles []Role) error {
	const errMessage = "could not create client-level roles from the client’s scope"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(client.getAdminRealmURL(realm, "clients", idOfClient, "scope-mappings", "clients", idOfSelectedClient))

	return checkForError(resp, err, errMessage)
}

// DeleteClientScopeMappingsClientRoles deletes client-level roles from the client’s scope
func (client *gocloak) DeleteClientScopeMappingsClientRoles(ctx context.Context, token, realm, idOfClient, idOfSelectedClient string, roles []Role) error {
	const errMessage = "could not delete client-level roles from the client’s scope"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(client.getAdminRealmURL(realm, "clients", idOfClient, "scope-mappings", "clients", idOfSelectedClient))

	return checkForError(resp, err, errMessage)
}

// GetClientSecret returns a client's secret
func (client *gocloak) GetClientSecret(ctx context.Context, token, realm, idOfClient string) (*CredentialRepresentation, error) {
	const errMessage = "could not get client secret"

	var result CredentialRepresentation

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "clients", idOfClient, "client-secret"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetClientServiceAccount retrieves the service account "user" for a client if enabled
func (client *gocloak) GetClientServiceAccount(ctx context.Context, token, realm, idOfClient string) (*User, error) {
	const errMessage = "could not get client service account"

	var result User
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "clients", idOfClient, "service-account-user"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

func (client *gocloak) RegenerateClientSecret(ctx context.Context, token, realm, idOfClient string) (*CredentialRepresentation, error) {
	const errMessage = "could not regenerate client secret"

	var result CredentialRepresentation
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Post(client.getAdminRealmURL(realm, "clients", idOfClient, "client-secret"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetClientOfflineSessions returns offline sessions associated with the client
func (client *gocloak) GetClientOfflineSessions(ctx context.Context, token, realm, idOfClient string) ([]*UserSessionRepresentation, error) {
	const errMessage = "could not get client offline sessions"

	var res []*UserSessionRepresentation
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&res).
		Get(client.getAdminRealmURL(realm, "clients", idOfClient, "offline-sessions"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return res, nil
}

// GetClientUserSessions returns user sessions associated with the client
func (client *gocloak) GetClientUserSessions(ctx context.Context, token, realm, idOfClient string) ([]*UserSessionRepresentation, error) {
	const errMessage = "could not get client user sessions"

	var res []*UserSessionRepresentation
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&res).
		Get(client.getAdminRealmURL(realm, "clients", idOfClient, "user-sessions"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return res, nil
}

// CreateClientProtocolMapper creates a protocol mapper in client scope
func (client *gocloak) CreateClientProtocolMapper(ctx context.Context, token, realm, idOfClient string, mapper ProtocolMapperRepresentation) (string, error) {
	const errMessage = "could not create client protocol mapper"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(mapper).
		Post(client.getAdminRealmURL(realm, "clients", idOfClient, "protocol-mappers", "models"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return "", err
	}

	return getID(resp), nil
}

// UpdateClientProtocolMapper updates a protocol mapper in client scope
func (client *gocloak) UpdateClientProtocolMapper(ctx context.Context, token, realm, idOfClient, mapperID string, mapper ProtocolMapperRepresentation) error {
	const errMessage = "could not update client protocol mapper"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(mapper).
		Put(client.getAdminRealmURL(realm, "clients", idOfClient, "protocol-mappers", "models", mapperID))

	return checkForError(resp, err, errMessage)
}

// DeleteClientProtocolMapper deletes a protocol mapper in client scope
func (client *gocloak) DeleteClientProtocolMapper(ctx context.Context, token, realm, idOfClient, mapperID string) error {
	const errMessage = "could not delete client protocol mapper"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Delete(client.getAdminRealmURL(realm, "clients", idOfClient, "protocol-mappers", "models", mapperID))

	return checkForError(resp, err, errMessage)
}

// GetKeyStoreConfig get keystoreconfig of the realm
func (client *gocloak) GetKeyStoreConfig(ctx context.Context, token, realm string) (*KeyStoreConfig, error) {
	const errMessage = "could not get key store config"

	var result KeyStoreConfig
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "keys"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetComponents get all components in realm
func (client *gocloak) GetComponents(ctx context.Context, token, realm string) ([]*Component, error) {
	const errMessage = "could not get components"

	var result []*Component
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "components"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetDefaultGroups returns a list of default groups
func (client *gocloak) GetDefaultGroups(ctx context.Context, token, realm string) ([]*Group, error) {
	const errMessage = "could not get default groups"

	var result []*Group

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "default-groups"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// AddDefaultGroup adds group to the list of default groups
func (client *gocloak) AddDefaultGroup(ctx context.Context, token, realm, groupID string) error {
	const errMessage = "could not add default group"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Put(client.getAdminRealmURL(realm, "default-groups", groupID))

	return checkForError(resp, err, errMessage)
}

// RemoveDefaultGroup removes group from the list of default groups
func (client *gocloak) RemoveDefaultGroup(ctx context.Context, token, realm, groupID string) error {
	const errMessage = "could not remove default group"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		Delete(client.getAdminRealmURL(realm, "default-groups", groupID))

	return checkForError(resp, err, errMessage)
}

func (client *gocloak) getRoleMappings(ctx context.Context, token, realm, path, objectID string) (*MappingsRepresentation, error) {
	const errMessage = "could not get role mappings"

	var result MappingsRepresentation
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, path, objectID, "role-mappings"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetRoleMappingByGroupID gets the role mappings by group
func (client *gocloak) GetRoleMappingByGroupID(ctx context.Context, token, realm, groupID string) (*MappingsRepresentation, error) {
	return client.getRoleMappings(ctx, token, realm, "groups", groupID)
}

// GetRoleMappingByUserID gets the role mappings by user
func (client *gocloak) GetRoleMappingByUserID(ctx context.Context, token, realm, userID string) (*MappingsRepresentation, error) {
	return client.getRoleMappings(ctx, token, realm, "users", userID)
}

// GetGroupsByRole gets groups assigned with a specific role of a realm
func (client *gocloak) GetGroupsByRole(ctx context.Context, token, realm string, roleName string) ([]*Group, error) {
	const errMessage = "could not get groups"

	var result []*Group
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(fmt.Sprintf("%s/%s/%s", client.getAdminRealmURL(realm, "roles"), roleName, "groups"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// UserAttributeContains checks if the given attribute value is set
func UserAttributeContains(attributes map[string][]string, attribute, value string) bool {
	for _, item := range attributes[attribute] {
		if item == value {
			return true
		}
	}
	return false
}

// GetEvents returns events
func (client *gocloak) GetEvents(ctx context.Context, token string, realm string, params GetEventsParams) ([]*EventRepresentation, error) {
	const errMessage = "could not get events"

	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}

	var result []*EventRepresentation
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(client.getAdminRealmURL(realm, "events"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientScopesScopeMappingsRealmRolesAvailable returns realm-level roles that are available to attach to this client scope
func (client *gocloak) GetClientScopesScopeMappingsRealmRolesAvailable(ctx context.Context, token, realm, clientScopeID string) ([]*Role, error) {
	const errMessage = "could not get available realm-level roles with the client-scope"

	var result []*Role

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "client-scopes", clientScopeID, "scope-mappings", "realm", "available"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// GetClientScopesScopeMappingsRealmRoles returns roles associated with a client-scope
func (client *gocloak) GetClientScopesScopeMappingsRealmRoles(ctx context.Context, token, realm, clientScopeID string) ([]*Role, error) {
	const errMessage = "could not get realm-level roles with the client-scope"

	var result []*Role

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		Get(client.getAdminRealmURL(realm, "client-scopes", clientScopeID, "scope-mappings", "realm"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}

// DeleteClientScopesScopeMappingsRealmRoles deletes realm-level roles from the client-scope
func (client *gocloak) DeleteClientScopesScopeMappingsRealmRoles(ctx context.Context, token, realm, clientScopeID string, roles []Role) error {
	const errMessage = "could not delete realm-level roles from the client-scope"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Delete(client.getAdminRealmURL(realm, "client-scopes", clientScopeID, "scope-mappings", "realm"))

	return checkForError(resp, err, errMessage)
}

// CreateClientScopesScopeMappingsRealmRoles creates realm-level roles to the client scope
func (client *gocloak) CreateClientScopesScopeMappingsRealmRoles(ctx context.Context, token, realm, clientScopeID string, roles []Role) error {
	const errMessage = "could not create realm-level roles to the client-scope"

	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(roles).
		Post(client.getAdminRealmURL(realm, "client-scopes", clientScopeID, "scope-mappings", "realm"))

	return checkForError(resp, err, errMessage)
}

// UpdateRequiredAction updates a required action for a given realm
func (client *gocloak) UpdateRequiredAction(ctx context.Context, token string, realm string, requiredAction RequiredActionProviderRepresentation) error {
	const errMessage = "could not update required action"

	if NilOrEmpty(requiredAction.ProviderID) {
		return errors.New("providerId is required for updating a required action")
	}
	_, err := client.getRequestWithBearerAuth(ctx, token).
		SetBody(requiredAction).
		Put(client.getAdminRealmURL(realm, "authentication", "required-actions", *requiredAction.ProviderID))

	return err
}

// ----- user

// GetClients gets all clients in realm
func (client *gocloak) GetClients(ctx context.Context, token, realm string, params GetClientsParams) ([]*Client, error) {
	const errMessage = "could not get clients"

	var result []*Client
	queryParams, err := GetQueryParams(params)
	if err != nil {
		return nil, errors.Wrap(err, errMessage)
	}
	resp, err := client.getRequestWithBearerAuth(ctx, token).
		SetResult(&result).
		SetQueryParams(queryParams).
		Get(client.getAdminRealmURL(realm, "clients"))

	if err := checkForError(resp, err, errMessage); err != nil {
		return nil, err
	}

	return result, nil
}
