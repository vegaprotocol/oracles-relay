package main

import (
	"io/ioutil"

	"code.vegaprotocol.io/oracles-relay/coinbase"
	"github.com/pelletier/go-toml"
)

type Config struct {
	NodeAddr string `toml:"node_addr"`
	// The coinbase config is not mandatory
	// if nil, we do not start the worker
	Coinbase *coinbase.Config `toml:"coinbase"`
}

func loadConfig(path string) (*Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	config := Config{}
	if err := toml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}
