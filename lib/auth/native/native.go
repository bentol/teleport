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
package native

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"sync/atomic"
	"time"

	"github.com/gravitational/teleport/lib/utils"

	log "github.com/Sirupsen/logrus"
	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh"
)

var PrecalculatedKeysNum = 20

type keyPair struct {
	privPem  []byte
	pubBytes []byte
}

type nauth struct {
	generatedKeysC chan keyPair
	closeC         chan bool
	closed         int32
}

func New() *nauth {
	n := nauth{
		generatedKeysC: make(chan keyPair, PrecalculatedKeysNum),
		closeC:         make(chan bool),
	}
	go n.precalculateKeys()
	return &n
}

func (n *nauth) GetNewKeyPairFromPool() ([]byte, []byte, error) {
	select {
	case key := <-n.generatedKeysC:
		return key.privPem, key.pubBytes, nil
	default:
		return n.GenerateKeyPair("")
	}
}

func (n *nauth) precalculateKeys() {

	for {
		privPem, pubBytes, err := n.GenerateKeyPair("")
		if err != nil {
			log.Errorf(err.Error())
			continue
		}
		key := keyPair{
			privPem:  privPem,
			pubBytes: pubBytes,
		}

		select {
		case <-n.closeC:
			return
		case n.generatedKeysC <- key:
			continue
		}
	}
}

func (n *nauth) Close() error {
	if atomic.CompareAndSwapInt32(&n.closed, 0, 1) {
		close(n.closeC)
	}
	return nil
}

func (n *nauth) GenerateKeyPair(passphrase string) ([]byte, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	privDer := x509.MarshalPKCS1PrivateKey(priv)
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDer,
	}
	privPem := pem.EncodeToMemory(&privBlock)

	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	pubBytes := ssh.MarshalAuthorizedKey(pub)
	return privPem, pubBytes, nil
}

func (n *nauth) GenerateHostCert(pkey, key []byte, id, hostname, role string, ttl time.Duration) ([]byte, error) {
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(key)
	if err != nil {
		return nil, err
	}
	validBefore := uint64(ssh.CertTimeInfinity)
	if ttl != 0 {
		b := time.Now().Add(ttl)
		validBefore = uint64(b.UnixNano())
	}
	cert := &ssh.Certificate{
		ValidPrincipals: []string{hostname},
		Key:             pubKey,
		ValidBefore:     validBefore,
		CertType:        ssh.HostCert,
	}
	cert.Permissions.Extensions = make(map[string]string)
	cert.Permissions.Extensions[utils.CertExtensionRole] = role
	signer, err := ssh.ParsePrivateKey(pkey)
	if err != nil {
		return nil, err
	}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		return nil, err
	}
	return ssh.MarshalAuthorizedKey(cert), nil
}

func (n *nauth) GenerateUserCert(pkey, key []byte, id, username string, ttl time.Duration) ([]byte, error) {
	if (ttl > MaxCertDuration) || (ttl < MinCertDuration) {
		return nil, trace.Errorf("wrong certificate ttl")
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(key)
	if err != nil {
		return nil, err
	}
	validBefore := uint64(ssh.CertTimeInfinity)
	if ttl != 0 {
		b := time.Now().Add(ttl)
		validBefore = uint64(b.Unix())
	}
	cert := &ssh.Certificate{
		Key:         pubKey,
		ValidBefore: validBefore,
		CertType:    ssh.UserCert,
	}
	cert.Permissions.Extensions = make(map[string]string)
	cert.Permissions.Extensions[utils.CertExtensionUser] = username
	signer, err := ssh.ParsePrivateKey(pkey)
	if err != nil {
		return nil, err
	}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		return nil, err
	}
	return ssh.MarshalAuthorizedKey(cert), nil
}

const (
	MinCertDuration = time.Minute
	MaxCertDuration = 30 * time.Hour
)