/*
Copyright 2018 Gravitational, Inc.

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

package main

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/utils"
)

func main() {
	log.Printf("Starting teleport client...")

	// Teleport HTTPS client uses TLS client authentication
	// so we have to set up certificates there
	tlsConfig, err := setupClientTLS()
	if err != nil {
		log.Fatalf("Failed to parse TLS config: %v", err)
	}

	authServerAddr := []utils.NetAddr{*utils.MustParseAddr("127.0.0.1:3025")}
	client, err := auth.NewTLSClient(authServerAddr, tlsConfig)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	token, err := client.GenerateToken(auth.GenerateTokenRequest{
		Token: "mytoken-proxy",
		Roles: teleport.Roles{teleport.RoleProxy},
		TTL:   time.Hour,
	})
	if err != nil {
		log.Fatalf("Failed to generate token: %v", err)
	}
	log.Printf("Generated token: %v\n", token)
}

// setupClientTLS sets up client TLS authentiction between TLS client
// and Teleport Auth server. This function uses hardcoded certificate paths,
// assuming program runs alongside auth server, but it can be ran
// on a remote location, assuming client has all the client certificates.
func setupClientTLS() (*tls.Config, error) {
	// read auth server TLS certificate, used to verify auth server identity
	authServerCert, err := ioutil.ReadFile("/var/lib/teleport/ca.cert")
	if err != nil {
		return nil, err
	}

	// client TLS key pair, used to authenticate with auth server
	tlsCert, err := tls.LoadX509KeyPair("/var/lib/teleport/admin.tlscert", "/var/lib/teleport/admin.key")
	if err != nil {
		return nil, err
	}

	// set up TLS config for HTTPS client
	tlsConfig := utils.TLSConfig()
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(authServerCert)
	tlsConfig.Certificates = []tls.Certificate{tlsCert}
	tlsConfig.RootCAs = certPool
	tlsConfig.ClientCAs = certPool
	return tlsConfig, nil
}
