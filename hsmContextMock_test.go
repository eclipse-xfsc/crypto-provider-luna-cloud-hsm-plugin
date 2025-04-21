package main

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/ThalesIgnite/crypto11"
	"github.com/stretchr/testify/mock"
	"io"
)

type ContextTypeMock struct {
	mock.Mock
}

type SignerMock struct {
	public crypto.PublicKey
}

func (s *SignerMock) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return []byte("signed"), nil
}
func (s *SignerMock) Delete() error {
	return nil
}
func (s *SignerMock) Public() crypto.PublicKey {
	return s.public
}

// GenerateRSAKeyPair creates an RSA key pair on the token. The id parameter is used to
// set CKA_ID and must be non-nil. RSA private keys are generated with both sign and decrypt
// permissions, and a public exponent of 65537.
func (t *ContextTypeMock) GenerateRSAKeyPair(id []byte, bits int) (crypto11.SignerDecrypter, error) {

	args := t.Called(id, bits)

	return args.Get(0).(crypto11.SignerDecrypter), args.Error(1)
}

// GenerateRSAKeyPairWithLabel creates an RSA key pair on the token. The id and label parameters are used to
// set CKA_ID and CKA_LABEL respectively and must be non-nil. RSA private keys are generated with both sign and decrypt
// permissions, and a public exponent of 65537.

func (t *ContextTypeMock) GenerateRSAKeyPairWithLabel(id, label []byte, bits int) (crypto11.SignerDecrypter, error) {

	args := t.Called(id, label, bits)

	return args.Get(0).(crypto11.SignerDecrypter), args.Error(1)
}

// GenerateRSAKeyPairWithAttributes generates an RSA key pair on the token. After this function returns, public and
// private will contain the attributes applied to the key pair. If required attributes are missing, they will be set to
// a default value.
func (t *ContextTypeMock) GenerateRSAKeyPairWithAttributes(public, private crypto11.AttributeSet, bits int) (crypto11.SignerDecrypter, error) {

	args := t.Called(public, private, bits)

	return args.Get(0).(crypto11.SignerDecrypter), args.Error(1)
}

// FindKeyPair retrieves a previously created asymmetric key pair, or nil if it cannot be found.
//
// At least one of id and label must be specified.
// Only private keys that have a non-empty CKA_ID will be found, as this is required to locate the matching public key.
// If the private key is found, but the public key with a corresponding CKA_ID is not, the key is not returned
// because we cannot implement crypto.Signer without the public key.
func (t *ContextTypeMock) FindKeyPair(id []byte, label []byte) (crypto11.Signer, error) {

	args := t.Called(id, label)

	return args.Get(0).(crypto11.Signer), args.Error(1)
}

// FindKeyPairs retrieves all matching asymmetric key pairs, or a nil slice if none can be found.
//
// At least one of id and label must be specified.
// Only private keys that have a non-empty CKA_ID will be found, as this is required to locate the matching public key.
// If the private key is found, but the public key with a corresponding CKA_ID is not, the key is not returned
// because we cannot implement crypto.Signer without the public key.
func (t *ContextTypeMock) FindKeyPairs(id []byte, label []byte) (signer []crypto11.Signer, err error) {

	args := t.Called(id, label)

	return args.Get(0).([]crypto11.Signer), args.Error(1)
}

// FindKeyPairWithAttributes retrieves a previously created asymmetric key pair, or nil if it cannot be found.
// The given attributes are matched against the private half only. Then the public half with a matching CKA_ID
// and CKA_LABEL values is found.
//
// Only private keys that have a non-empty CKA_ID will be found, as this is required to locate the matching public key.
// If the private key is found, but the public key with a corresponding CKA_ID is not, the key is not returned
// because we cannot implement crypto.Signer without the public key.
func (t *ContextTypeMock) FindKeyPairWithAttributes(attributes crypto11.AttributeSet) (crypto11.Signer, error) {

	args := t.Called(attributes)

	return args.Get(0).(crypto11.Signer), args.Error(1)
}

// FindKeyPairsWithAttributes retrieves previously created asymmetric key pairs, or nil if none can be found.
// The given attributes are matched against the private half only. Then the public half with a matching CKA_ID
// and CKA_LABEL values is found.
//
// Only private keys that have a non-empty CKA_ID will be found, as this is required to locate the matching public key.
// If the private key is found, but the public key with a corresponding CKA_ID is not, the key is not returned
// because we cannot implement crypto.Signer without the public key.
func (t *ContextTypeMock) FindKeyPairsWithAttributes(attributes crypto11.AttributeSet) (signer []crypto11.Signer, err error) {

	args := t.Called(attributes)

	return args.Get(0).([]crypto11.Signer), args.Error(1)
}

// FindAllKeyPairs retrieves all existing asymmetric key pairs, or a nil slice if none can be found.
//
// If a private key is found, but the corresponding public key is not, the key is not returned because we cannot
// implement crypto.Signer without the public key.
func (t *ContextTypeMock) FindAllKeyPairs() ([]crypto11.Signer, error) {

	args := t.Called()

	return args.Get(0).([]crypto11.Signer), args.Error(1)
}

// FindKey retrieves a previously created symmetric key, or nil if it cannot be found.
//
// Either (but not both) of id and label may be nil, in which case they are ignored.
func (t *ContextTypeMock) FindKey(id []byte, label []byte) (*crypto11.SecretKey, error) {

	args := t.Called(id, label)

	return args.Get(0).(*crypto11.SecretKey), args.Error(1)
}

// FindKeys retrieves all matching symmetric keys, or a nil slice if none can be found.
//
// At least one of id and label must be specified.
func (t *ContextTypeMock) FindKeys(id []byte, label []byte) (key []*crypto11.SecretKey, err error) {

	args := t.Called(id, label)

	return args.Get(0).([]*crypto11.SecretKey), args.Error(1)
}

// FindKeyWithAttributes retrieves a previously created symmetric key, or nil if it cannot be found.
func (t *ContextTypeMock) FindKeyWithAttributes(attributes crypto11.AttributeSet) (*crypto11.SecretKey, error) {

	args := t.Called(attributes)

	return args.Get(0).(*crypto11.SecretKey), args.Error(1)
}

// FindKeysWithAttributes retrieves previously created symmetric keys, or a nil slice if none can be found.
func (t *ContextTypeMock) FindKeysWithAttributes(attributes crypto11.AttributeSet) ([]*crypto11.SecretKey, error) {

	args := t.Called(attributes)

	return args.Get(0).([]*crypto11.SecretKey), args.Error(1)
}

// FindAllKeyPairs retrieves all existing symmetric keys, or a nil slice if none can be found.
func (t *ContextTypeMock) FindAllKeys() ([]*crypto11.SecretKey, error) {

	args := t.Called()

	return args.Get(0).([]*crypto11.SecretKey), args.Error(1)
}

// GetAttributes gets the values of the specified attributes on the given key or keypair.
// If the key is asymmetric, then the attributes are retrieved from the private half.
//
// If the object is not a crypto11 key or keypair then an error is returned.
func (t *ContextTypeMock) GetAttributes(key interface{}, attributes []crypto11.AttributeType) (a crypto11.AttributeSet, err error) {
	return nil, nil
}

// GetAttribute gets the value of the specified attribute on the given key or keypair.
// If the key is asymmetric, then the attribute is retrieved from the private half.
//
// If the object is not a crypto11 key or keypair then an error is returned.
func (t *ContextTypeMock) GetAttribute(key interface{}, attribute crypto11.AttributeType) (a *crypto11.Attribute, err error) {
	return nil, nil
}

// GetPubAttributes gets the values of the specified attributes on the public half of the given keypair.
//
// If the object is not a crypto11 keypair then an error is returned.
func (t *ContextTypeMock) GetPubAttributes(key interface{}, attributes []crypto11.AttributeType) (a crypto11.AttributeSet, err error) {
	return nil, nil
}

// GetPubAttribute gets the value of the specified attribute on the public half of the given key.
//
// If the object is not a crypto11 keypair then an error is returned.
func (t *ContextTypeMock) GetPubAttribute(key interface{}, attribute crypto11.AttributeType) (a *crypto11.Attribute, err error) {
	return nil, nil
}

// GenerateECDSAKeyPair creates a ECDSA key pair on the token using curve c. The id parameter is used to
// set CKA_ID and must be non-nil. Only a limited set of named elliptic curves are supported. The
// underlying PKCS#11 implementation may impose further restrictions.
func (t *ContextTypeMock) GenerateECDSAKeyPair(id []byte, curve elliptic.Curve) (crypto11.Signer, error) {

	args := t.Called(id, curve)

	return args.Get(0).(crypto11.Signer), args.Error(1)
}

// GenerateECDSAKeyPairWithLabel creates a ECDSA key pair on the token using curve c. The id and label parameters are used to
// set CKA_ID and CKA_LABEL respectively and must be non-nil. Only a limited set of named elliptic curves are supported. The
// underlying PKCS#11 implementation may impose further restrictions.
func (t *ContextTypeMock) GenerateECDSAKeyPairWithLabel(id, label []byte, curve elliptic.Curve) (crypto11.Signer, error) {

	args := t.Called(id, label, curve)

	return args.Get(0).(crypto11.Signer), args.Error(1)
}

// GenerateECDSAKeyPairWithAttributes generates an ECDSA key pair on the token. After this function returns, public and
// private will contain the attributes applied to the key pair. If required attributes are missing, they will be set to
// a default value.
func (t *ContextTypeMock) GenerateECDSAKeyPairWithAttributes(public, private crypto11.AttributeSet, curve elliptic.Curve) (crypto11.Signer, error) {
	return nil, nil
}

func (t *ContextTypeMock) GenerateSecretKey(id []byte, bits int, cipher *crypto11.SymmetricCipher) (*crypto11.SecretKey, error) {

	args := t.Called(id, bits, cipher)

	return args.Get(0).(*crypto11.SecretKey), args.Error(1)
}

// GenerateSecretKey creates an secret key of given length and type. The id and label parameters are used to
// set CKA_ID and CKA_LABEL respectively and must be non-nil.
func (t *ContextTypeMock) GenerateSecretKeyWithLabel(id, label []byte, bits int, cipher *crypto11.SymmetricCipher) (*crypto11.SecretKey, error) {
	return nil, nil
}

// GenerateSecretKeyWithAttributes creates an secret key of given length and type. After this function returns, template
// will contain the attributes applied to the key. If required attributes are missing, they will be set to a default
// value.
func (t *ContextTypeMock) GenerateSecretKeyWithAttributes(template crypto11.AttributeSet, bits int, cipher *crypto11.SymmetricCipher) (k *crypto11.SecretKey, err error) {
	return nil, nil
}

// NewRandomReader returns a reader for the random number generator on the token.
func (t *ContextTypeMock) NewRandomReader() (io.Reader, error) {
	return rand.Reader, nil
}
