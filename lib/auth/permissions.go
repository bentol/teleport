/*
Copyright 2015 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package auth

import (
	"context"
	"fmt"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/services"

	"github.com/gravitational/trace"
)

// NewAdminContext returns new admin auth context
func NewAdminContext() (*AuthContext, error) {
	authContext, err := contextForBuiltinRole(nil, teleport.RoleAdmin, fmt.Sprintf("%v", teleport.RoleAdmin))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return authContext, nil
}

// NewRoleAuthorizer authorizes everyone as predefined role, used in tests
func NewRoleAuthorizer(clusterConfig services.ClusterConfig, r teleport.Role) (Authorizer, error) {
	authContext, err := contextForBuiltinRole(clusterConfig, r, fmt.Sprintf("%v", r))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &contextAuthorizer{authContext: *authContext}, nil
}

// contextAuthorizer is a helper struct that always authorizes
// based on predefined context, helpful for tests
type contextAuthorizer struct {
	authContext AuthContext
}

// Authorize authorizes user based on identity supplied via context
func (r *contextAuthorizer) Authorize(ctx context.Context) (*AuthContext, error) {
	return &r.authContext, nil
}

// NewUserAuthorizer authorizes everyone as predefined local user
func NewUserAuthorizer(username string, identity services.Identity, access services.Access) (Authorizer, error) {
	authContext, err := contextForLocalUser(username, identity, access)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &contextAuthorizer{authContext: *authContext}, nil
}

// NewAuthorizer returns new authorizer using backends
func NewAuthorizer(access services.Access, identity services.Identity, trust services.Trust) (Authorizer, error) {
	if access == nil {
		return nil, trace.BadParameter("missing parameter access")
	}
	if identity == nil {
		return nil, trace.BadParameter("missing parameter identity")
	}
	if trust == nil {
		return nil, trace.BadParameter("missing parameter trust")
	}
	return &authorizer{access: access, identity: identity, trust: trust}, nil
}

// Authorizer authorizes identity and returns auth context
type Authorizer interface {
	// Authorize authorizes user based on identity supplied via context
	Authorize(ctx context.Context) (*AuthContext, error)
}

// authorizer creates new local authorizer
type authorizer struct {
	access   services.Access
	identity services.Identity
	trust    services.Trust
}

// AuthzContext is authorization context
type AuthContext struct {
	// User is the user name
	User services.User
	// Checker is access checker
	Checker services.AccessChecker
}

// Authorize authorizes user based on identity supplied via context
func (a *authorizer) Authorize(ctx context.Context) (*AuthContext, error) {
	if ctx == nil {
		return nil, trace.AccessDenied("missing authentication context")
	}
	userI := ctx.Value(ContextUser)
	switch user := userI.(type) {
	case LocalUser:
		return a.authorizeLocalUser(user)
	case RemoteUser:
		return a.authorizeRemoteUser(user)
	case BuiltinRole:
		return a.authorizeBuiltinRole(user)
	case RemoteBuiltinRole:
		return a.authorizeRemoteBuiltinRole(user)
	default:
		return nil, trace.AccessDenied("unsupported context type %T", userI)
	}
}

// authorizeLocalUser returns authz context based on the username
func (a *authorizer) authorizeLocalUser(u LocalUser) (*AuthContext, error) {
	return contextForLocalUser(u.Username, a.identity, a.access)
}

// authorizeRemoteUser returns checker based on cert authority roles
func (a *authorizer) authorizeRemoteUser(u RemoteUser) (*AuthContext, error) {
	ca, err := a.trust.GetCertAuthority(services.CertAuthID{Type: services.UserCA, DomainName: u.ClusterName}, false)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	roleNames, err := ca.CombinedMapping().Map(u.RemoteRoles)
	if err != nil {
		return nil, trace.AccessDenied("failed to map roles for remote user %q from cluster %q", u.Username, u.ClusterName)
	}
	if len(roleNames) == 0 {
		return nil, trace.AccessDenied("no roles mapped for remote user %q from cluster %q", u.Username, u.ClusterName)
	}
	log.Debugf("Mapped roles %v of remote user %q to local roles %v.", u.RemoteRoles, u.Username, roleNames)
	checker, err := services.FetchRoles(roleNames, a.access, nil)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	user, err := services.NewUser(fmt.Sprintf("remote-%v-%v", u.Username, u.ClusterName))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &AuthContext{
		// this is done on purpose to make sure user does not match some real local user
		User:    user,
		Checker: checker,
	}, nil
}

// authorizeBuiltinRole authorizes builtin role
func (a *authorizer) authorizeBuiltinRole(r BuiltinRole) (*AuthContext, error) {
	config, err := r.GetClusterConfig()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return contextForBuiltinRole(config, r.Role, r.Username)
}

func (a *authorizer) authorizeRemoteBuiltinRole(r RemoteBuiltinRole) (*AuthContext, error) {
	if r.Role != teleport.RoleProxy {
		return nil, trace.AccessDenied("access denied for remote %v connecting to cluster", r.Role)
	}
	// TODO(klizhentas): allow remote proxy to update the cluster's certificate authorities
	// during certificates renewal
	roles, err := services.FromSpec(
		string(teleport.RoleRemoteProxy),
		services.RoleSpecV3{
			Allow: services.RoleConditions{
				Namespaces: []string{services.Wildcard},
				Rules: []services.Rule{
					services.NewRule(services.KindNode, services.RO()),
					services.NewRule(services.KindProxy, services.RO()),
					services.NewRule(services.KindCertAuthority, services.ReadNoSecrets()),
					services.NewRule(services.KindNamespace, services.RO()),
					services.NewRule(services.KindUser, services.RO()),
					services.NewRule(services.KindAuthServer, services.RO()),
					services.NewRule(services.KindReverseTunnel, services.RO()),
					services.NewRule(services.KindTunnelConnection, services.RO()),
					services.NewRule(services.KindClusterConfig, services.RO()),
				},
			},
		})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	user, err := services.NewUser(r.Username)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	user.SetRoles([]string{string(teleport.RoleRemoteProxy)})
	return &AuthContext{
		User:    user,
		Checker: roles,
	}, nil
}

// GetCheckerForBuiltinRole returns checkers for embedded builtin role
func GetCheckerForBuiltinRole(clusterConfig services.ClusterConfig, role teleport.Role) (services.AccessChecker, error) {
	switch role {
	case teleport.RoleAuth:
		return services.FromSpec(
			role.String(),
			services.RoleSpecV3{
				Allow: services.RoleConditions{
					Namespaces: []string{services.Wildcard},
					Rules: []services.Rule{
						services.NewRule(services.KindAuthServer, services.RW()),
					},
				},
			})
	case teleport.RoleProvisionToken:
		return services.FromSpec(role.String(), services.RoleSpecV3{})
	case teleport.RoleNode:
		return services.FromSpec(
			role.String(),
			services.RoleSpecV3{
				Allow: services.RoleConditions{
					Namespaces: []string{services.Wildcard},
					Rules: []services.Rule{
						services.NewRule(services.KindNode, services.RW()),
						services.NewRule(services.KindSSHSession, services.RW()),
						services.NewRule(services.KindEvent, services.RW()),
						services.NewRule(services.KindProxy, services.RO()),
						services.NewRule(services.KindCertAuthority, services.ReadNoSecrets()),
						services.NewRule(services.KindUser, services.RO()),
						services.NewRule(services.KindNamespace, services.RO()),
						services.NewRule(services.KindRole, services.RO()),
						services.NewRule(services.KindAuthServer, services.RO()),
						services.NewRule(services.KindReverseTunnel, services.RO()),
						services.NewRule(services.KindTunnelConnection, services.RO()),
						services.NewRule(services.KindClusterConfig, services.RO()),
					},
				},
			})
	case teleport.RoleProxy:
		// if in recording mode, return a different set of permissions than regular
		// mode. recording proxy needs to be able to generate host certificates.
		if clusterConfig.GetSessionRecording() == services.RecordAtProxy {
			return services.FromSpec(
				role.String(),
				services.RoleSpecV3{
					Allow: services.RoleConditions{
						Namespaces: []string{services.Wildcard},
						Rules: []services.Rule{
							services.NewRule(services.KindProxy, services.RW()),
							services.NewRule(services.KindOIDCRequest, services.RW()),
							services.NewRule(services.KindSSHSession, services.RW()),
							services.NewRule(services.KindSession, services.RO()),
							services.NewRule(services.KindEvent, services.RW()),
							services.NewRule(services.KindSAMLRequest, services.RW()),
							services.NewRule(services.KindOIDC, services.ReadNoSecrets()),
							services.NewRule(services.KindSAML, services.ReadNoSecrets()),
							services.NewRule(services.KindGithub, services.ReadNoSecrets()),
							services.NewRule(services.KindGithubRequest, services.RW()),
							services.NewRule(services.KindNamespace, services.RO()),
							services.NewRule(services.KindNode, services.RO()),
							services.NewRule(services.KindAuthServer, services.RO()),
							services.NewRule(services.KindReverseTunnel, services.RO()),
							services.NewRule(services.KindCertAuthority, services.ReadNoSecrets()),
							services.NewRule(services.KindUser, services.RO()),
							services.NewRule(services.KindRole, services.RO()),
							services.NewRule(services.KindClusterAuthPreference, services.RO()),
							services.NewRule(services.KindClusterConfig, services.RO()),
							services.NewRule(services.KindClusterName, services.RO()),
							services.NewRule(services.KindStaticTokens, services.RO()),
							services.NewRule(services.KindTunnelConnection, services.RW()),
							services.NewRule(services.KindHostCert, services.RW()),
							services.NewRule(services.KindRemoteCluster, services.RO()),
						},
					},
				})
		}
		return services.FromSpec(
			role.String(),
			services.RoleSpecV3{
				Allow: services.RoleConditions{
					Namespaces: []string{services.Wildcard},
					Rules: []services.Rule{
						services.NewRule(services.KindProxy, services.RW()),
						services.NewRule(services.KindOIDCRequest, services.RW()),
						services.NewRule(services.KindSSHSession, services.RW()),
						services.NewRule(services.KindSession, services.RO()),
						services.NewRule(services.KindEvent, services.RW()),
						services.NewRule(services.KindSAMLRequest, services.RW()),
						services.NewRule(services.KindOIDC, services.ReadNoSecrets()),
						services.NewRule(services.KindSAML, services.ReadNoSecrets()),
						services.NewRule(services.KindGithub, services.ReadNoSecrets()),
						services.NewRule(services.KindGithubRequest, services.RW()),
						services.NewRule(services.KindNamespace, services.RO()),
						services.NewRule(services.KindNode, services.RO()),
						services.NewRule(services.KindAuthServer, services.RO()),
						services.NewRule(services.KindReverseTunnel, services.RO()),
						services.NewRule(services.KindCertAuthority, services.ReadNoSecrets()),
						services.NewRule(services.KindUser, services.RO()),
						services.NewRule(services.KindRole, services.RO()),
						services.NewRule(services.KindClusterAuthPreference, services.RO()),
						services.NewRule(services.KindClusterConfig, services.RO()),
						services.NewRule(services.KindClusterName, services.RO()),
						services.NewRule(services.KindStaticTokens, services.RO()),
						services.NewRule(services.KindTunnelConnection, services.RW()),
						services.NewRule(services.KindRemoteCluster, services.RO()),
					},
				},
			})
	case teleport.RoleWeb:
		return services.FromSpec(
			role.String(),
			services.RoleSpecV3{
				Allow: services.RoleConditions{
					Namespaces: []string{services.Wildcard},
					Rules: []services.Rule{
						services.NewRule(services.KindWebSession, services.RW()),
						services.NewRule(services.KindSSHSession, services.RW()),
						services.NewRule(services.KindAuthServer, services.RO()),
						services.NewRule(services.KindUser, services.RO()),
						services.NewRule(services.KindRole, services.RO()),
						services.NewRule(services.KindNamespace, services.RO()),
						services.NewRule(services.KindTrustedCluster, services.RO()),
					},
				},
			})
	case teleport.RoleSignup:
		return services.FromSpec(
			role.String(),
			services.RoleSpecV3{
				Allow: services.RoleConditions{
					Namespaces: []string{services.Wildcard},
					Rules: []services.Rule{
						services.NewRule(services.KindAuthServer, services.RO()),
						services.NewRule(services.KindClusterAuthPreference, services.RO()),
					},
				},
			})
	case teleport.RoleAdmin:
		return services.FromSpec(
			role.String(),
			services.RoleSpecV3{
				Options: services.RoleOptions{
					services.MaxSessionTTL: services.MaxDuration(),
				},
				Allow: services.RoleConditions{
					Namespaces: []string{services.Wildcard},
					Logins:     []string{},
					NodeLabels: map[string]string{services.Wildcard: services.Wildcard},
					Rules: []services.Rule{
						services.NewRule(services.Wildcard, services.RW()),
					},
				},
			})
	case teleport.RoleNop:
		return services.FromSpec(
			role.String(),
			services.RoleSpecV3{
				Allow: services.RoleConditions{
					Namespaces: []string{},
					Rules:      []services.Rule{},
				},
			})
	}

	return nil, trace.NotFound("%v is not reconginzed", role.String())
}

func contextForBuiltinRole(clusterConfig services.ClusterConfig, r teleport.Role, username string) (*AuthContext, error) {
	checker, err := GetCheckerForBuiltinRole(clusterConfig, r)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	user, err := services.NewUser(username)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	user.SetRoles([]string{string(r)})
	return &AuthContext{
		User:    user,
		Checker: checker,
	}, nil
}

func contextForLocalUser(username string, identity services.Identity, access services.Access) (*AuthContext, error) {
	user, err := identity.GetUser(username)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	checker, err := services.FetchRoles(user.GetRoles(), access, user.GetTraits())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &AuthContext{
		User:    user,
		Checker: checker,
	}, nil
}

// ContextUser is a user set in the context of the request
const ContextUser = "teleport-user"

// LocalUsername is a local username
type LocalUser struct {
	// Username is local username
	Username string
}

// BuiltinRole is the role of the Teleport service.
type BuiltinRole struct {
	// GetClusterConfig fetches cluster configuration.
	GetClusterConfig GetClusterConfigFunc

	// Role is the builtin role this username is associated with
	Role teleport.Role

	// Username is for authentication tracking purposes
	Username string
}

// RemoteBuiltinRole is the role of the remote (service connecting via trusted cluster link)
// Teleport service.
type RemoteBuiltinRole struct {
	// Role is the builtin role of the user
	Role teleport.Role

	// Username is for authentication tracking purposes
	Username string

	// ClusterName is the name of the remote cluster
	ClusterName string
}

// RemoteUser defines encoded remote user
type RemoteUser struct {
	// Username is a name of the remote user
	Username string `json:"username"`

	// ClusterName is a name of the remote cluster
	// of the user
	ClusterName string `json:"cluster_name"`

	// RemoteRoles is optional list of remote roles
	RemoteRoles []string `json:"remote_roles"`
}

// GetClusterConfigFunc returns a cached services.ClusterConfig.
type GetClusterConfigFunc func() (services.ClusterConfig, error)
