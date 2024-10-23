package rsa

import "fmt"

// KeyFormat defines key format enum type.
type KeyFormat string

// key format constants.
const (
	PKCS1 KeyFormat = "pkcs1"
	PKCS8 KeyFormat = "pkcs8"

	PKCS1PublicKey     = "RSA PUBLIC KEY"
	PKCS1PrivateKey    = "RSA PRIVATE KEY"
	PKCS1PublicHeader  = "-----BEGIN RSA PUBLIC KEY-----"
	PKCS1PublicTail    = "-----END RSA PUBLIC KEY-----"
	PKCS1PrivateHeader = "-----BEGIN RSA PRIVATE KEY-----"
	PKCS1PrivateTail   = "-----END RSA PRIVATE KEY-----"

	PKCS8PublicKey     = "PUBLIC KEY"
	PKCS8PrivateKey    = "PRIVATE KEY"
	PKCS8PublicHeader  = "-----BEGIN PUBLIC KEY-----"
	PKCS8PublicTail    = "-----END PUBLIC KEY-----"
	PKCS8PrivateHeader = "-----BEGIN PRIVATE KEY-----"
	PKCS8PrivateTail   = "-----END PRIVATE KEY-----"
)

var (
	invalidPublicKeyError = func() error {
		return fmt.Errorf("invalid public key, please make sure the public key is valid")
	}
	invalidPrivateKeyError = func() error {
		return fmt.Errorf("invalid private key, please make sure the private key is valid")
	}
	invalidRSAKeyError = func() error {
		return fmt.Errorf("invalid rsa key, please make sure the key pair is valid")
	}
)
