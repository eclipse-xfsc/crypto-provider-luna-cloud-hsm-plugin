package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/ThalesIgnite/crypto11"
	"github.com/eclipse-xfsc/crypto-provider-core/types"
	"github.com/stretchr/testify/assert"
)

var testId = "test id"

func getTestHSMCryptoProvider(mock *ContextTypeMock) HSMCryptoProvider {
	return HSMCryptoProvider{
		controller: &hsmController{
			config: &crypto11.Config{},
			rand:   rand.Reader,
			api:    mock,
		},
	}
}

func TestHSMCryptoProvider_GenerateKey(t *testing.T) {
	var mockApi = new(ContextTypeMock)
	provider := getTestHSMCryptoProvider(mockApi)
	param := types.CryptoKeyParameter{KeyType: types.Ecdsap256, Identifier: types.CryptoIdentifier{KeyId: testId}}
	mockApi.On("GenerateECDSAKeyPair", []byte(testId), elliptic.P256()).Return(&SignerMock{}, nil)
	_ = provider.GenerateKey(param)
	mockApi.AssertExpectations(t)
}

func TestHSMCryptoProvider_GetKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	expected, _ := key.Public().(*ecdsa.PublicKey).ECDH()
	var mockApi = new(ContextTypeMock)
	mockApi.On("FindKeyPair", []byte(testId), []byte(nil)).Return(&SignerMock{public: key.Public()}, nil)
	provider := getTestHSMCryptoProvider(mockApi)
	actual, _ := provider.GetKey(types.CryptoIdentifier{KeyId: testId})
	assert.Equal(t, expected.Bytes(), actual.Key)
	assert.Equal(t, types.Ecdsap256, actual.CryptoKeyParameter.KeyType)
}
