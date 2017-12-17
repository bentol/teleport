/*
Copyright 2017 Gravitational, Inc.

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
	"encoding/base32"
	"fmt"
	"net/url"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/services/suite"
	"github.com/gravitational/teleport/lib/session"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"github.com/pquerna/otp/totp"
	"gopkg.in/check.v1"
)

type TLSSuite struct {
	server *TestTLSServer
}

var _ = check.Suite(&TLSSuite{})

func (s *TLSSuite) SetUpSuite(c *check.C) {
	utils.InitLoggerForTests()
}

func (s *TLSSuite) SetUpTest(c *check.C) {
	testAuthServer, err := NewTestAuthServer(TestAuthServerConfig{
		Dir: c.MkDir(),
	})
	c.Assert(err, check.IsNil)
	s.server, err = testAuthServer.NewTestTLSServer()
	c.Assert(err, check.IsNil)
}

func (s *TLSSuite) TearDownTest(c *check.C) {
	if s.server != nil {
		s.server.Close()
	}
}

func (s *TLSSuite) TestRBAC(c *check.C) {
	client, err := s.server.NewClient(TestIdentity{})
	c.Assert(err, check.IsNil)

	// Nop User can get cluster name
	_, err = client.GetDomainName()
	c.Assert(err, check.IsNil)

	// But can not get users
	_, err = client.GetUsers()
	c.Assert(trace.IsAccessDenied(err), check.Equals, true, check.Commentf("expected AccessDenied, got %T"))

}

// TestOwnRole tests that user can read roles assigned to them
func (s *TLSSuite) TestReadOwnRole(c *check.C) {
	clt, err := s.server.NewClient(TestAdmin())
	c.Assert(err, check.IsNil)

	user1, userRole, err := CreateUserAndRoleWithoutRoles(clt, "user1", []string{"user1"})
	c.Assert(err, check.IsNil)

	user2, _, err := CreateUserAndRoleWithoutRoles(clt, "user2", []string{"user2"})
	c.Assert(err, check.IsNil)

	// user should be able to read their own roles
	userClient, err := s.server.NewClient(TestIdentity{I: LocalUser{Username: user1.GetName()}})
	c.Assert(err, check.IsNil)

	_, err = userClient.GetRole(userRole.GetName())
	c.Assert(err, check.IsNil)

	// user2 can't read user1 role
	userClient2, err := s.server.NewClient(TestIdentity{I: LocalUser{Username: user2.GetName()}})
	c.Assert(err, check.IsNil)

	_, err = userClient2.GetRole(userRole.GetName())
	c.Assert(trace.IsAccessDenied(err), check.Equals, true, check.Commentf("expected AccessDenied, got %T"))
}

func (s *TLSSuite) TestTunnelConnectionsCRUD(c *check.C) {
	clt, err := s.server.NewClient(TestAdmin())
	c.Assert(err, check.IsNil)

	suite := &suite.ServicesTestSuite{
		PresenceS: clt,
	}
	suite.TunnelConnectionsCRUD(c)
}

func (s *TLSSuite) TestServersCRUD(c *check.C) {
	clt, err := s.server.NewClient(TestAdmin())
	c.Assert(err, check.IsNil)

	suite := &suite.ServicesTestSuite{
		PresenceS: clt,
	}
	suite.ServerCRUD(c)
}

func (s *TLSSuite) TestReverseTunnelsCRUD(c *check.C) {
	clt, err := s.server.NewClient(TestAdmin())
	c.Assert(err, check.IsNil)

	suite := &suite.ServicesTestSuite{
		PresenceS: clt,
	}
	suite.ReverseTunnelsCRUD(c)
}

func (s *TLSSuite) TestUsersCRUD(c *check.C) {
	clt, err := s.server.NewClient(TestAdmin())
	c.Assert(err, check.IsNil)

	err = clt.UpsertPassword("user1", []byte("some pass"))
	c.Assert(err, check.IsNil)

	users, err := clt.GetUsers()
	c.Assert(err, check.IsNil)
	c.Assert(len(users), check.Equals, 1)
	c.Assert(users[0].GetName(), check.Equals, "user1")

	c.Assert(clt.DeleteUser("user1"), check.IsNil)

	users, err = clt.GetUsers()
	c.Assert(err, check.IsNil)
	c.Assert(len(users), check.Equals, 0)
}

func (s *TLSSuite) TestPasswordGarbage(c *check.C) {
	clt, err := s.server.NewClient(TestAdmin())
	c.Assert(err, check.IsNil)
	garbage := [][]byte{
		nil,
		make([]byte, defaults.MaxPasswordLength+1),
		make([]byte, defaults.MinPasswordLength-1),
	}
	for _, g := range garbage {
		err := clt.CheckPassword("user1", g, "123456")
		c.Assert(trace.IsBadParameter(err), check.Equals, true, check.Commentf("expected BadParameter, got %T %v", err, err))
	}
}

func (s *TLSSuite) TestPasswordCRUD(c *check.C) {
	clt, err := s.server.NewClient(TestAdmin())
	c.Assert(err, check.IsNil)

	pass := []byte("abc123")
	rawSecret := "def456"
	otpSecret := base32.StdEncoding.EncodeToString([]byte(rawSecret))

	err = clt.CheckPassword("user1", pass, "123456")
	c.Assert(err, check.NotNil)

	err = clt.UpsertPassword("user1", pass)
	c.Assert(err, check.IsNil)

	err = s.server.AuthServer.AuthServer.UpsertTOTP("user1", otpSecret)
	c.Assert(err, check.IsNil)

	validToken, err := totp.GenerateCode(otpSecret, s.server.Clock().Now())
	c.Assert(err, check.IsNil)

	err = clt.CheckPassword("user1", pass, validToken)
	c.Assert(err, check.IsNil)
}

func (s *TLSSuite) TestTokens(c *check.C) {
	clt, err := s.server.NewClient(TestAdmin())
	c.Assert(err, check.IsNil)

	out, err := clt.GenerateToken(teleport.Roles{teleport.RoleNode}, 0)
	c.Assert(err, check.IsNil)
	c.Assert(len(out), check.Not(check.Equals), 0)
}

func (s *TLSSuite) TestSharedSessions(c *check.C) {
	clt, err := s.server.NewClient(TestAdmin())
	c.Assert(err, check.IsNil)

	out, err := clt.GetSessions(defaults.Namespace)
	c.Assert(err, check.IsNil)
	c.Assert(out, check.DeepEquals, []session.Session{})

	date := time.Date(2009, time.November, 10, 23, 0, 0, 0, time.UTC)
	sess := session.Session{
		Active:         true,
		ID:             session.NewID(),
		TerminalParams: session.TerminalParams{W: 100, H: 100},
		Created:        date,
		LastActive:     date,
		Login:          "bob",
		Namespace:      defaults.Namespace,
	}
	c.Assert(clt.CreateSession(sess), check.IsNil)

	out, err = clt.GetSessions(defaults.Namespace)
	c.Assert(err, check.IsNil)

	c.Assert(out, check.DeepEquals, []session.Session{sess})

	// emit two events: "one" and "two" for this session, and event "three"
	// for some other session
	err = clt.EmitAuditEvent(events.SessionStartEvent, events.EventFields{
		events.SessionEventID: sess.ID,
		events.EventNamespace: defaults.Namespace,
		"val": "one",
	})
	c.Assert(err, check.IsNil)
	err = clt.EmitAuditEvent(events.SessionStartEvent, events.EventFields{
		events.SessionEventID: sess.ID,
		events.EventNamespace: defaults.Namespace,
		"val": "two",
	})
	c.Assert(err, check.IsNil)
	anotherSessionID := session.NewID()
	err = clt.EmitAuditEvent(events.SessionEndEvent, events.EventFields{
		events.SessionEventID: anotherSessionID,
		"val": "three",
		events.EventNamespace: defaults.Namespace,
	})
	c.Assert(err, check.IsNil)
	// ask for strictly session events:
	e, err := clt.GetSessionEvents(defaults.Namespace, sess.ID, 0)
	c.Assert(err, check.IsNil)
	c.Assert(len(e), check.Equals, 2)
	c.Assert(e[0].GetString("val"), check.Equals, "one")
	c.Assert(e[1].GetString("val"), check.Equals, "two")

	// try searching for events with no filter (empty query) - should get all 3 events:
	to := time.Now().In(time.UTC).Add(time.Hour)
	from := to.Add(-time.Hour * 2)
	history, err := clt.SearchEvents(from, to, "")
	c.Assert(err, check.IsNil)
	c.Assert(history, check.NotNil)
	c.Assert(len(history), check.Equals, 3)

	// try searching for only "session.end" events (real query)
	history, err = clt.SearchEvents(from, to,
		fmt.Sprintf("%s=%s", events.EventType, events.SessionEndEvent))
	c.Assert(err, check.IsNil)
	c.Assert(history, check.NotNil)
	c.Assert(len(history), check.Equals, 1)
	c.Assert(history[0].GetString(events.SessionEventID), check.Equals, string(anotherSessionID))
	c.Assert(history[0].GetString("val"), check.Equals, "three")
}

func (s *TLSSuite) TestOTPCRUD(c *check.C) {
	clt, err := s.server.NewClient(TestAdmin())
	c.Assert(err, check.IsNil)

	user := "user1"
	pass := []byte("abc123")
	rawSecret := "def456"
	otpSecret := base32.StdEncoding.EncodeToString([]byte(rawSecret))

	// upsert a password and totp secret
	err = clt.UpsertPassword("user1", pass)
	c.Assert(err, check.IsNil)
	err = s.server.AuthServer.AuthServer.UpsertTOTP(user, otpSecret)
	c.Assert(err, check.IsNil)

	// make sure the otp url we get back is valid url issued to the correct user
	otpURL, _, err := s.server.AuthServer.AuthServer.GetOTPData(user)
	c.Assert(err, check.IsNil)
	u, err := url.Parse(otpURL)
	c.Assert(err, check.IsNil)
	c.Assert(u.Path, check.Equals, "/user1")

	// a completely invalid token should return access denied
	err = clt.CheckPassword("user1", pass, "123456")
	c.Assert(err, check.NotNil)

	// an invalid token should return access denied
	//
	// this tests makes the token 61 seconds in the future (but from a valid key)
	// even though the validity period is 30 seconds. this is because a token is
	// valid for 30 seconds + 30 second skew before and after for a usability
	// reasons. so a token made between seconds 31 and 60 is still valid, and
	// invalidity starts at 61 seconds in the future.
	invalidToken, err := totp.GenerateCode(otpSecret, s.server.Clock().Now().Add(61*time.Second))
	c.Assert(err, check.IsNil)
	err = clt.CheckPassword("user1", pass, invalidToken)
	c.Assert(err, check.NotNil)

	// a valid token (created right now and from a valid key) should return success
	validToken, err := totp.GenerateCode(otpSecret, s.server.Clock().Now())
	c.Assert(err, check.IsNil)

	err = clt.CheckPassword("user1", pass, validToken)
	c.Assert(err, check.IsNil)

	// try the same valid token now it should fail because we don't allow re-use of tokens
	err = clt.CheckPassword("user1", pass, validToken)
	c.Assert(err, check.NotNil)
}

// TestSyncCachedClusterConfig tests behavior with cluster configuration
func (s *TLSSuite) TestSyncCachedClusterConfig(c *check.C) {
	// set cluster config to record at nodes
	clusterConfig, err := services.NewClusterConfig(services.ClusterConfigSpecV3{
		SessionRecording: services.RecordAtNode,
	})
	authServer := s.server.AuthServer.AuthServer
	err = authServer.SetClusterConfig(clusterConfig)
	c.Assert(err, check.IsNil)

	// check to make sure the cached value is the same
	clusterConfig = authServer.getCachedClusterConfig()
	c.Assert(clusterConfig.GetSessionRecording(), check.Equals, services.RecordAtNode)

	// update cluster config to record at proxy
	clusterConfig.SetSessionRecording(services.RecordAtProxy)
	err = authServer.SetClusterConfig(clusterConfig)
	c.Assert(err, check.IsNil)

	// manually force synching cluster config
	err = authServer.syncCachedClusterConfig()
	c.Assert(err, check.IsNil)

	// check to make sure the cached value was updated
	clusterConfig = authServer.getCachedClusterConfig()
	c.Assert(clusterConfig.GetSessionRecording(), check.Equals, services.RecordAtProxy)
}

// TestWebSessions tests web sessions flow
func (s *TLSSuite) TestWebSessions(c *check.C) {
	clt, err := s.server.NewClient(TestAdmin())
	c.Assert(err, check.IsNil)

	user := "user1"
	pass := []byte("abc123")

	_, _, err = CreateUserAndRole(clt, user, []string{user})
	c.Assert(err, check.IsNil)

	proxy, err := s.server.NewClient(TestIdentity{I: BuiltinRole{Role: teleport.RoleProxy, Username: string(teleport.RoleProxy)}})
	c.Assert(err, check.IsNil)

	req := AuthenticateUserRequest{
		Username: user,
		Pass: &PassCreds{
			Password: pass,
		},
	}
	// authentication attempt fails with no password set up
	_, err = proxy.AuthenticateWebUser(req)
	c.Assert(trace.IsAccessDenied(err), check.Equals, true, check.Commentf("expected AccessDenied, got %T %#v", err, err))

	err = clt.UpsertPassword(user, pass)

	// success with password set up
	ws, err := proxy.AuthenticateWebUser(req)
	c.Assert(err, check.IsNil)
	c.Assert(ws, check.Not(check.Equals), "")

	web, err := s.server.NewClientFromWebSession(ws)
	c.Assert(err, check.IsNil)

	_, err = web.GetWebSessionInfo(user, ws.GetName())
	c.Assert(err, check.IsNil)

	new, err := web.ExtendWebSession(user, ws.GetName())
	c.Assert(err, check.IsNil)
	c.Assert(new, check.NotNil)

	err = clt.DeleteWebSession(user, ws.GetName())
	c.Assert(err, check.IsNil)

	_, err = web.GetWebSessionInfo(user, ws.GetName())
	c.Assert(err, check.NotNil)

	_, err = web.ExtendWebSession(user, ws.GetName())
	c.Assert(err, check.NotNil)
}

// TestGenerateCerts tests edge cases around authorization of
// certificate generation for servers and users
func (s *TLSSuite) TestGenerateCerts(c *check.C) {
	priv, pub, err := s.server.AuthServer.AuthServer.GenerateKeyPair("")
	c.Assert(err, check.IsNil)

	// make sure we can parse the private and public key
	_, err = ssh.ParsePrivateKey(priv)
	c.Assert(err, check.IsNil)
	_, _, _, _, err = ssh.ParseAuthorizedKey(pub)
	c.Assert(err, check.IsNil)

	// make sure we can parse the private and public key
	clt, err := s.server.NewClient(TestAdmin())
	c.Assert(err, check.IsNil)

	// generate server keys for node
	hostID := "00000000-0000-0000-0000-000000000000"
	hostClient, err := s.server.NewClient(TestIdentity{I: BuiltinRole{Username: hostID, Role: teleport.RoleNode}})
	c.Assert(err, check.IsNil)

	certs, err := hostClient.GenerateServerKeys(
		hostID, s.server.AuthServer.ClusterName, teleport.Roles{teleport.RoleNode})
	c.Assert(err, check.IsNil)

	_, _, _, _, err = ssh.ParseAuthorizedKey(certs.Cert)
	c.Assert(err, check.IsNil)

	// attempt to elevate privileges by getting admin role in the certificate
	_, err = hostClient.GenerateServerKeys(
		hostID, s.server.AuthServer.ClusterName, teleport.Roles{teleport.RoleAdmin})
	c.Assert(trace.IsAccessDenied(err), check.Equals, true, check.Commentf("expected AccessDenied, got %T"))

	// attempt to get certificate for different host id
	_, err = hostClient.GenerateServerKeys(
		"some-other-host-id", s.server.AuthServer.ClusterName, teleport.Roles{teleport.RoleNode})
	c.Assert(trace.IsAccessDenied(err), check.Equals, true, check.Commentf("expected AccessDenied, got %T"))

	user1, userRole, err := CreateUserAndRole(clt, "user1", []string{"user1"})
	c.Assert(err, check.IsNil)

	user2, _, err := CreateUserAndRole(clt, "user2", []string{"user2"})
	c.Assert(err, check.IsNil)

	// unauthenticated client should NOT be able to generate a user cert without auth
	nopClient, err := s.server.NewClient(TestNop())
	c.Assert(err, check.IsNil)

	_, err = nopClient.GenerateUserCert(pub, user1.GetName(), time.Hour, teleport.CompatibilityNone)
	c.Assert(err, check.NotNil)
	c.Assert(trace.IsAccessDenied(err), check.Equals, true, check.Commentf("expected AccessDenied, got %T"))
	c.Assert(err, check.ErrorMatches, ".*cannot request a certificate for user1")

	// Users don't match
	userClient2, err := s.server.NewClient(TestUser(user2.GetName()))
	c.Assert(err, check.IsNil)

	_, err = userClient2.GenerateUserCert(pub, user1.GetName(), time.Hour, teleport.CompatibilityNone)
	c.Assert(err, check.NotNil)
	c.Assert(trace.IsAccessDenied(err), check.Equals, true, check.Commentf("expected AccessDenied, got %T"))
	c.Assert(err, check.ErrorMatches, ".*cannot request a certificate for user1")

	// should not be able to generate cert for longer than duration
	userClient1, err := s.server.NewClient(TestUser(user1.GetName()))
	c.Assert(err, check.IsNil)

	cert, err := userClient1.GenerateUserCert(pub, user1.GetName(), 40*time.Hour, teleport.CompatibilityNone)
	c.Assert(err, check.IsNil)

	parsedKey, _, _, _, err := ssh.ParseAuthorizedKey(cert)
	c.Assert(err, check.IsNil)
	parsedCert, _ := parsedKey.(*ssh.Certificate)
	validBefore := time.Unix(int64(parsedCert.ValidBefore), 0)
	diff := validBefore.Sub(time.Now())
	c.Assert(diff < defaults.MaxCertDuration, check.Equals, true, check.Commentf("expected %v < %v", diff, defaults.CertDuration))

	// user should not have agent forwarding
	_, exists := parsedCert.Extensions[teleport.CertExtensionPermitAgentForwarding]
	c.Assert(exists, check.Equals, false)

	// now update role to permit agent forwarding
	roleOptions := userRole.GetOptions()
	roleOptions.Set(services.ForwardAgent, true)
	userRole.SetOptions(roleOptions)
	err = clt.UpsertRole(userRole, backend.Forever)
	c.Assert(err, check.IsNil)

	cert, err = userClient1.GenerateUserCert(pub, user1.GetName(), 1*time.Hour, teleport.CompatibilityNone)
	c.Assert(err, check.IsNil)
	parsedKey, _, _, _, err = ssh.ParseAuthorizedKey(cert)
	c.Assert(err, check.IsNil)
	parsedCert, _ = parsedKey.(*ssh.Certificate)

	// user should get agent forwarding
	_, exists = parsedCert.Extensions[teleport.CertExtensionPermitAgentForwarding]
	c.Assert(exists, check.Equals, true)

	// apply HTTP Auth to generate user cert:
	cert, err = userClient1.GenerateUserCert(pub, user1.GetName(), time.Hour, teleport.CompatibilityNone)
	c.Assert(err, check.IsNil)

	_, _, _, _, err = ssh.ParseAuthorizedKey(cert)
	c.Assert(err, check.IsNil)
}
