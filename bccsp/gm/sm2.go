/*
Copyright IBM Corp. 2016 All Rights Reserved.

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
package gm

import (
	"crypto/rand"
	"github.com/tjfoc/gmsm/sm2"

	"github.com/hyperledger/fabric/bccsp"
)

func signSM2(k *sm2.PrivateKey, digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
	return k.Sign(rand.Reader, digest, opts)
}

func verifySM2(k *sm2.PublicKey, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	verify := k.Verify(digest, signature)
	return verify, nil
}

type sm2Signer struct{}

func (s *sm2Signer) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
	return signSM2(k.(*sm2PrivateKey).privKey, digest, opts)
}

type sm2PrivateKeyVerifier struct{}

func (v *sm2PrivateKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	return verifySM2(&(k.(*sm2PrivateKey).privKey.PublicKey), signature, digest, opts)
}

type sm2PublicKeyKeyVerifier struct{}

func (v *sm2PublicKeyKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	return verifySM2(k.(*sm2PublicKey).pubKey, signature, digest, opts)
}

type ecdsaSigner struct{}

func (s *ecdsaSigner) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
	publicKey := k.(*ecdsaPrivateKey).privKey.PublicKey
	sm2pk := sm2.PublicKey{
		Curve: publicKey.Curve,
		X:     publicKey.X,
		Y:     publicKey.Y,
	}
	privateKey := k.(*ecdsaPrivateKey).privKey
	sm2privateKey := sm2.PrivateKey{
		D:         privateKey.D,
		PublicKey: sm2pk,
	}
	return signSM2(&sm2privateKey, digest, opts)
}

type ecdsaPrivateKeyVerifier struct{}

func (v *ecdsaPrivateKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	publicKey := k.(*ecdsaPrivateKey).privKey.PublicKey
	sm2pk := sm2.PublicKey{
		Curve: publicKey.Curve,
		X: publicKey.X,
		Y: publicKey.Y,
	}
	return verifySM2(&sm2pk, signature, digest, opts)
}

type ecdsaPublicKeyKeyVerifier struct{}

func (v *ecdsaPublicKeyKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	publicKey := k.(*ecdsaPublicKey).pubKey
	sm2pk := sm2.PublicKey{
		Curve: publicKey.Curve,
		X: publicKey.X,
		Y: publicKey.Y,
	}
	return verifySM2(&sm2pk, signature, digest, opts)
}

