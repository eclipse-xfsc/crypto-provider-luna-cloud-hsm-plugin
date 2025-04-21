package main

import (
	"crypto/elliptic"
	"github.com/ThalesIgnite/crypto11"
	"io"
)

// methods used from crypto11.Context
type ContextType interface {
	// GenerateRSAKeyPair creates an RSA key pair on the token. The id parameter is used to
	// set CKA_ID and must be non-nil. RSA private keys are generated with both sign and decrypt
	// permissions, and a public exponent of 65537.
	GenerateRSAKeyPair(id []byte, bits int) (crypto11.SignerDecrypter, error)
	// GenerateRSAKeyPairWithLabel creates an RSA key pair on the token. The id and label parameters are used to
	// set CKA_ID and CKA_LABEL respectively and must be non-nil. RSA private keys are generated with both sign and decrypt
	// permissions, and a public exponent of 65537.
	GenerateRSAKeyPairWithLabel(id, label []byte, bits int) (crypto11.SignerDecrypter, error)
	// GenerateRSAKeyPairWithAttributes generates an RSA key pair on the token. After this function returns, public and
	// private will contain the attributes applied to the key pair. If required attributes are missing, they will be set to
	// a default value.
	GenerateRSAKeyPairWithAttributes(public, private crypto11.AttributeSet, bits int) (crypto11.SignerDecrypter, error)
	// FindKeyPair retrieves a previously created asymmetric key pair, or nil if it cannot be found.
	//
	// At least one of id and label must be specified.
	// Only private keys that have a non-empty CKA_ID will be found, as this is required to locate the matching public key.
	// If the private key is found, but the public key with a corresponding CKA_ID is not, the key is not returned
	// because we cannot implement crypto.Signer without the public key.
	FindKeyPair(id []byte, label []byte) (crypto11.Signer, error)
	// FindKeyPairs retrieves all matching asymmetric key pairs, or a nil slice if none can be found.
	//
	// At least one of id and label must be specified.
	// Only private keys that have a non-empty CKA_ID will be found, as this is required to locate the matching public key.
	// If the private key is found, but the public key with a corresponding CKA_ID is not, the key is not returned
	// because we cannot implement crypto.Signer without the public key.
	FindKeyPairs(id []byte, label []byte) (signer []crypto11.Signer, err error)
	// FindKeyPairWithAttributes retrieves a previously created asymmetric key pair, or nil if it cannot be found.
	// The given attributes are matched against the private half only. Then the public half with a matching CKA_ID
	// and CKA_LABEL values is found.
	//
	// Only private keys that have a non-empty CKA_ID will be found, as this is required to locate the matching public key.
	// If the private key is found, but the public key with a corresponding CKA_ID is not, the key is not returned
	// because we cannot implement crypto.Signer without the public key.
	FindKeyPairWithAttributes(attributes crypto11.AttributeSet) (crypto11.Signer, error)
	// FindKeyPairsWithAttributes retrieves previously created asymmetric key pairs, or nil if none can be found.
	// The given attributes are matched against the private half only. Then the public half with a matching CKA_ID
	// and CKA_LABEL values is found.
	//
	// Only private keys that have a non-empty CKA_ID will be found, as this is required to locate the matching public key.
	// If the private key is found, but the public key with a corresponding CKA_ID is not, the key is not returned
	// because we cannot implement crypto.Signer without the public key.
	FindKeyPairsWithAttributes(attributes crypto11.AttributeSet) (signer []crypto11.Signer, err error)
	// FindAllKeyPairs retrieves all existing asymmetric key pairs, or a nil slice if none can be found.
	//
	// If a private key is found, but the corresponding public key is not, the key is not returned because we cannot
	// implement crypto.Signer without the public key.
	FindAllKeyPairs() ([]crypto11.Signer, error)
	// FindKey retrieves a previously created symmetric key, or nil if it cannot be found.
	//
	// Either (but not both) of id and label may be nil, in which case they are ignored.
	FindKey(id []byte, label []byte) (*crypto11.SecretKey, error)
	// FindKeys retrieves all matching symmetric keys, or a nil slice if none can be found.
	//
	// At least one of id and label must be specified.
	FindKeys(id []byte, label []byte) (key []*crypto11.SecretKey, err error)
	// FindKeyWithAttributes retrieves a previously created symmetric key, or nil if it cannot be found.
	FindKeyWithAttributes(attributes crypto11.AttributeSet) (*crypto11.SecretKey, error)
	// FindKeysWithAttributes retrieves previously created symmetric keys, or a nil slice if none can be found.
	FindKeysWithAttributes(attributes crypto11.AttributeSet) ([]*crypto11.SecretKey, error)
	// FindAllKeyPairs retrieves all existing symmetric keys, or a nil slice if none can be found.
	FindAllKeys() ([]*crypto11.SecretKey, error)
	// GetAttributes gets the values of the specified attributes on the given key or keypair.
	// If the key is asymmetric, then the attributes are retrieved from the private half.
	//
	// If the object is not a crypto11 key or keypair then an error is returned.
	GetAttributes(key interface{}, attributes []crypto11.AttributeType) (a crypto11.AttributeSet, err error)
	// GetAttribute gets the value of the specified attribute on the given key or keypair.
	// If the key is asymmetric, then the attribute is retrieved from the private half.
	//
	// If the object is not a crypto11 key or keypair then an error is returned.
	GetAttribute(key interface{}, attribute crypto11.AttributeType) (a *crypto11.Attribute, err error)
	// GetPubAttributes gets the values of the specified attributes on the public half of the given keypair.
	//
	// If the object is not a crypto11 keypair then an error is returned.
	GetPubAttributes(key interface{}, attributes []crypto11.AttributeType) (a crypto11.AttributeSet, err error)
	// GetPubAttribute gets the value of the specified attribute on the public half of the given key.
	//
	// If the object is not a crypto11 keypair then an error is returned.
	GetPubAttribute(key interface{}, attribute crypto11.AttributeType) (a *crypto11.Attribute, err error)
	// GenerateECDSAKeyPair creates a ECDSA key pair on the token using curve c. The id parameter is used to
	// set CKA_ID and must be non-nil. Only a limited set of named elliptic curves are supported. The
	// underlying PKCS#11 implementation may impose further restrictions.
	GenerateECDSAKeyPair(id []byte, curve elliptic.Curve) (crypto11.Signer, error)
	// GenerateECDSAKeyPairWithLabel creates a ECDSA key pair on the token using curve c. The id and label parameters are used to
	// set CKA_ID and CKA_LABEL respectively and must be non-nil. Only a limited set of named elliptic curves are supported. The
	// underlying PKCS#11 implementation may impose further restrictions.
	GenerateECDSAKeyPairWithLabel(id, label []byte, curve elliptic.Curve) (crypto11.Signer, error)
	// GenerateECDSAKeyPairWithAttributes generates an ECDSA key pair on the token. After this function returns, public and
	// private will contain the attributes applied to the key pair. If required attributes are missing, they will be set to
	// a default value.
	GenerateECDSAKeyPairWithAttributes(public, private crypto11.AttributeSet, curve elliptic.Curve) (crypto11.Signer, error)

	GenerateSecretKey(id []byte, bits int, cipher *crypto11.SymmetricCipher) (*crypto11.SecretKey, error)
	// GenerateSecretKey creates an secret key of given length and type. The id and label parameters are used to
	// set CKA_ID and CKA_LABEL respectively and must be non-nil.
	GenerateSecretKeyWithLabel(id, label []byte, bits int, cipher *crypto11.SymmetricCipher) (*crypto11.SecretKey, error)
	// GenerateSecretKeyWithAttributes creates an secret key of given length and type. After this function returns, template
	// will contain the attributes applied to the key. If required attributes are missing, they will be set to a default
	// value.
	GenerateSecretKeyWithAttributes(template crypto11.AttributeSet, bits int, cipher *crypto11.SymmetricCipher) (k *crypto11.SecretKey, err error)
	// NewRandomReader returns a reader for the random number generator on the token.
	NewRandomReader() (io.Reader, error)
}
