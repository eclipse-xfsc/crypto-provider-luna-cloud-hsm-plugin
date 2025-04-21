package main

import (
	"fmt"
	"github.com/ThalesIgnite/crypto11"
)

func (c hsmController) withApiAndRandomReader() (*hsmController, error) {
	ctx, err := crypto11.Configure(c.config)
	if err != nil {
		fmt.Printf("failed configuring %v", err.Error())
		return nil, err
	}
	randReader, err := ctx.NewRandomReader()
	if err != nil {
		return nil, err
	}
	controller := &hsmController{api: ctx, config: c.config, signerOptions: c.signerOptions, rand: randReader}
	return controller, nil
}
