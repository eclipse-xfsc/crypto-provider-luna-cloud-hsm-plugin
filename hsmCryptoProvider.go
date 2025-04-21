package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	b64 "encoding/base64"
	"errors"
	"fmt"
	"math/rand"
	"strconv"

	"github.com/ThalesIgnite/crypto11"
	"github.com/eclipse-xfsc/crypto-provider-core/types"
)

const (
	HsmNamespace = "luna-cloud-hsm"
)

func (p HSMCryptoProvider) CreateCryptoContext(context types.CryptoContext) error {
	return nil
}

func (p HSMCryptoProvider) DestroyCryptoContext(context types.CryptoContext) error {
	return nil
}

func (p HSMCryptoProvider) DeleteKey(parameter types.CryptoIdentifier) error {
	return nil
}

func (p HSMCryptoProvider) getSigner(parameter types.CryptoIdentifier) (crypto11.Signer, error) {
	id := []byte(parameter.KeyId)
	return p.controller.api.FindKeyPair(id, nil)
}

func (p HSMCryptoProvider) GetNamespaces(context types.CryptoContext) ([]string, error) {
	return []string{HsmNamespace}, nil
}
func (p HSMCryptoProvider) GenerateRandom(context types.CryptoContext, number int) ([]byte, error) {
	key := make([]byte, number)
	reader, err := p.controller.api.NewRandomReader()
	if err != nil {
		return nil, err
	}
	_, err = reader.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}
func (p HSMCryptoProvider) Hash(parameter types.CryptoHashParameter, msg []byte) ([]byte, error) {
	// todo use hsm?
	if parameter.HashAlgorithm == types.Sha2256 {
		msgHash := sha256.New()
		_, err := msgHash.Write(msg)
		if err != nil {
			return nil, err
		}
		msgHashSum := msgHash.Sum(nil)
		return msgHashSum, nil
	} else {
		return nil, errors.ErrUnsupported
	}

}
func (p HSMCryptoProvider) Encrypt(parameter types.CryptoIdentifier, data []byte) ([]byte, error) {
	id := []byte(parameter.KeyId)
	key, err := p.controller.api.FindKey(id, nil)
	if err != nil {
		return nil, err
	}
	var res []byte
	key.Encrypt(res, data)
	return res, nil
}
func (p HSMCryptoProvider) Decrypt(parameter types.CryptoIdentifier, data []byte) ([]byte, error) {
	id := []byte(parameter.KeyId)
	key, err := p.controller.api.FindKey(id, nil)
	if err != nil {
		return nil, err
	}
	var res []byte
	key.Decrypt(res, data)
	return res, nil
}
func (p HSMCryptoProvider) Sign(parameter types.CryptoIdentifier, data []byte) ([]byte, error) {
	signer, err := p.getSigner(parameter)
	if err != nil {
		return nil, err
	}
	return signer.Sign(p.controller.rand, data, p.controller.signerOptions)
}
func (p HSMCryptoProvider) GetKeys(parameter types.CryptoFilter) (*types.CryptoKeySet, error) {
	identifier := types.CryptoIdentifier{KeyId: parameter.Id, CryptoContext: parameter.CryptoContext}
	key, err := p.GetKey(identifier)
	if err != nil {
		return nil, err
	} else {
		keySet := &types.CryptoKeySet{Keys: []types.CryptoKey{*key}}
		return keySet, nil
	}
}
func (p HSMCryptoProvider) GetKey(parameter types.CryptoIdentifier) (*types.CryptoKey, error) {
	signer, err := p.getSigner(parameter)
	if err != nil {
		return nil, err
	}
	pubKeyObj := signer.Public()
	var key = new(types.CryptoKey)
	var params = new(types.CryptoKeyParameter)

	if pubKey, ok := pubKeyObj.(*ecdsa.PublicKey); ok {
		repr, err := pubKey.ECDH()
		if err != nil {
			return nil, err
		}
		key.Key = repr.Bytes()
		params.Identifier = parameter
		params.KeyType = constructKeyType(ECDSA, pubKey.Curve.Params().Name)
	} else if pubKey, ok := pubKeyObj.(*rsa.PublicKey); ok {
		keyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			return nil, err
		}
		key.Key = keyBytes
		params.KeyType = constructKeyType(RSA, strconv.Itoa(pubKey.Size()))

	} else if pubKey, ok := pubKeyObj.(*crypto11.SecretKey); ok {
		return nil, fmt.Errorf("keys of type %T are not retrievable", pubKey)

	} else {
		return nil, fmt.Errorf("key %s has unsupported key format", parameter.KeyId)
	}

	key.CryptoKeyParameter = *params
	return key, nil
}
func (p HSMCryptoProvider) Verify(parameter types.CryptoIdentifier, data []byte, signature []byte) (bool, error) {
	signer, err := p.getSigner(parameter)
	if err != nil {
		return false, err
	}
	pubKeyObj := signer.Public()
	if pubKey, ok := pubKeyObj.(*ecdsa.PublicKey); ok {
		hashed := sha256.Sum256(data)
		result := ecdsa.VerifyASN1(pubKey, hashed[:], signature)
		return result, nil
	} else if pubKey, ok := pubKeyObj.(*rsa.PublicKey); ok {
		hashed := sha256.Sum256(data)
		err = rsa.VerifyPSS(pubKey, crypto.SHA256, hashed[:], signature, nil)
		return err == nil, err
	} else if pubKey, ok := pubKeyObj.(*crypto11.SecretKey); ok {
		return false, fmt.Errorf("keys of type %T are not retrievable", pubKey)
	} else {
		return false, fmt.Errorf("key %s has unsupported key format", parameter.KeyId)
	}
}
func (p HSMCryptoProvider) GenerateKey(parameter types.CryptoKeyParameter) error {
	switch parameter.KeyType {
	case types.Rsa2048, types.Rsa3072, types.Rsa4096:
		_, err := p.generateRSA(parameter)
		return err
	case types.Ecdsap256, types.Ecdsap384, types.Ecdsap512:
		_, err := p.generateECDSA(parameter)
		return err
	case types.Aes256GCM:
		_, err := p.generateAES(parameter)
		return err
	case types.Ed25519:
		_, err := p.generateEDDSA(parameter)
		return err
	default:
		return fmt.Errorf("unsupported key type %v", parameter.KeyType)
	}
}
func (p HSMCryptoProvider) GetSeed(context context.Context) string {
	n := rand.Int()
	random, err := p.GenerateRandom(types.CryptoContext{}, n)
	if err != nil {
		fmt.Print(err.Error())
		return ""
	}
	return b64.StdEncoding.EncodeToString(random)
}

func (p HSMCryptoProvider) GetSupportedKeysAlgs() []types.KeyType {
	return []types.KeyType{types.Ecdsap256, types.Ecdsap384, types.Ecdsap512, types.Aes256GCM, types.Ed25519, types.Rsa2048, types.Rsa3072, types.Rsa4096}
}

func (p HSMCryptoProvider) GetSupportedHashAlgs() []types.HashAlgorithm {
	return []types.HashAlgorithm{types.Sha2256}
}

func (p HSMCryptoProvider) IsCryptoContextExisting(context types.CryptoContext) (bool, error) {
	return true, nil
}

func (p HSMCryptoProvider) IsKeyExisting(parameter types.CryptoIdentifier) (bool, error) {
	_, err := p.getSigner(parameter)

	if err != nil {
		return false, err
	}
	return true, nil
}

func (p HSMCryptoProvider) RotateKey(parameter types.CryptoIdentifier) error {
	return errors.ErrUnsupported
}
