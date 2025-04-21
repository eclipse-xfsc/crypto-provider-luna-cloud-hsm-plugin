package main

import (
	"github.com/ThalesIgnite/crypto11"
	"github.com/eclipse-xfsc/crypto-provider-core/types"
	"github.com/spf13/viper"
)

var Plugin types.CryptoProviderModule = plugin{} //export Plugin Symbol, dont

type plugin struct{}

func (p plugin) GetCryptoProvider() types.CryptoProvider {
	config := crypto11.Config{
		Path:       viper.GetString("CRYPTO_EXECUTABLE_PATH"),
		TokenLabel: viper.GetString("HSM_PARTITION_LABEL"),
		Pin:        viper.GetString("HSM_PARTITION_PASSWORD"),
	}
	def := hsmController{config: &config, signerOptions: nil}
	controller, err := def.withApiAndRandomReader()
	if err != nil {
		panic(err)
	}
	provider := HSMCryptoProvider{controller: controller}
	return provider
}
