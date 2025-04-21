package main

import (
	"crypto"
	"io"
	"strings"

	"github.com/ThalesIgnite/crypto11"
	"github.com/eclipse-xfsc/crypto-provider-core/types"
)

type hsmController struct {
	config        *crypto11.Config
	api           ContextType
	signerOptions crypto.SignerOpts
	rand          io.Reader
}

type HSMCryptoProvider struct {
	controller *hsmController
}

type MajorKeyType string

const (
	RSA   MajorKeyType = "rsa"
	ECDSA MajorKeyType = "ecdsa"
)

func constructKeyType(typ MajorKeyType, typParam string) types.KeyType {
	typParam = strings.ToLower(strings.Replace(typParam, "-", "", -1))
	return types.KeyType(strings.Join([]string{string(typ), typParam}, "-"))
}
