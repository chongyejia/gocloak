package api

import (
	"context"
	"github.com/chongyejia/gocloak/v11"
)

type IRealm interface {

	// *** Realm ***

	// GetRealm returns top-level representation of the realm
	GetRealm(ctx context.Context, token, realm string) (*gocloak.RealmRepresentation, error)
	// GetRealms returns top-level representation of all realms
	GetRealms(ctx context.Context, token string) ([]*gocloak.RealmRepresentation, error)
	// CreateRealm creates a realm
	CreateRealm(ctx context.Context, token string, realm gocloak.RealmRepresentation) (string, error)
	// UpdateRealm updates a given realm
	UpdateRealm(ctx context.Context, token string, realm gocloak.RealmRepresentation) error
	// DeleteRealm removes a realm
	DeleteRealm(ctx context.Context, token, realm string) error
	// ClearRealmCache clears realm cache
	ClearRealmCache(ctx context.Context, token, realm string) error
	// ClearUserCache clears realm cache
	ClearUserCache(ctx context.Context, token, realm string) error
	// ClearKeysCache clears realm cache
	ClearKeysCache(ctx context.Context, token, realm string) error
	//GetAuthenticationFlows get all authentication flows from a realm
	GetAuthenticationFlows(ctx context.Context, token, realm string) ([]*gocloak.AuthenticationFlowRepresentation, error)
	//Create a new Authentication flow in a realm
	CreateAuthenticationFlow(ctx context.Context, token, realm string, flow gocloak.AuthenticationFlowRepresentation) error
	//DeleteAuthenticationFlow deletes a flow in a realm with the given ID
	DeleteAuthenticationFlow(ctx context.Context, token, realm, flowID string) error
	//GetAuthenticationExecutions retrieves all executions of a given flow
	GetAuthenticationExecutions(ctx context.Context, token, realm, flow string) ([]*gocloak.ModifyAuthenticationExecutionRepresentation, error)
	//CreateAuthenticationExecution creates a new execution for the given flow name in the given realm
	CreateAuthenticationExecution(ctx context.Context, token, realm, flow string, execution gocloak.CreateAuthenticationExecutionRepresentation) error
	//UpdateAuthenticationExecution updates an authentication execution for the given flow in the given realm
	UpdateAuthenticationExecution(ctx context.Context, token, realm, flow string, execution gocloak.ModifyAuthenticationExecutionRepresentation) error
	// DeleteAuthenticationExecution delete a single execution with the given ID
	DeleteAuthenticationExecution(ctx context.Context, token, realm, executionID string) error

	//CreateAuthenticationExecutionFlow creates a new flow execution for the given flow name in the given realm
	CreateAuthenticationExecutionFlow(ctx context.Context, token, realm, flow string, execution gocloak.CreateAuthenticationExecutionFlowRepresentation) error
}
