package main

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/ThalesIgnite/crypto11"
	"github.com/eclipse-xfsc/crypto-provider-core/types"
)

func (p HSMCryptoProvider) generateRSA(params types.CryptoKeyParameter) (crypto11.Signer, error) {
	mkt, param, err := splitKeyTypeAndParams(params.KeyType)
	if err != nil {
		return nil, err
	}
	if mkt == RSA {
		bits, err := strconv.Atoi(param)
		if err != nil {
			return nil, err
		}
		id := []byte(params.Identifier.KeyId)
		return p.controller.api.GenerateRSAKeyPair(id, bits)
	}
	return nil, fmt.Errorf("expected type %v - got %v", RSA, mkt)
}

func (p HSMCryptoProvider) generateECDSA(params types.CryptoKeyParameter) (crypto11.Signer, error) {
	mkt, param, err := splitKeyTypeAndParams(params.KeyType)
	if err != nil {
		return nil, err
	}
	if mkt == ECDSA {
		var curve elliptic.Curve
		switch param {
		case "p256":
			curve = elliptic.P256()
		case "p384":
			curve = elliptic.P384()
		case "p521":
			curve = elliptic.P521()
		}
		return p.controller.api.GenerateECDSAKeyPair([]byte(params.Identifier.KeyId), curve)
	}
	return nil, fmt.Errorf("expected type %v - got %v", ECDSA, mkt)
}

func (p HSMCryptoProvider) generateEDDSA(params types.CryptoKeyParameter) (crypto11.Signer, error) {
	return nil, errors.ErrUnsupported
}

func (p HSMCryptoProvider) generateAES(params types.CryptoKeyParameter) (crypto11.Signer, error) {
	if params.KeyType == types.Aes256GCM {
		_, err := p.controller.api.GenerateSecretKey([]byte(params.Identifier.KeyId), 256, crypto11.CipherAES)
		return nil, err
	}
	return nil, fmt.Errorf("expected type %s got %s", types.Aes256GCM, params.KeyType)
}

func splitKeyTypeAndParams(keyType types.KeyType) (MajorKeyType, string, error) {
	keyData := strings.Split(string(keyType), "-")
	if len(keyData) != 2 {
		return "", "", fmt.Errorf("expected %T in a form `type`-`typeParam`. Got %s", keyType, keyType)
	}
	return MajorKeyType(keyData[0]), keyData[1], nil
}
