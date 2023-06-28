package utils

import (
	"fmt"

	"github.com/btcsuite/btcd/chaincfg"
)

func GetBtcNetworkParams(network string) (*chaincfg.Params, error) {
	switch network {
	case "testnet3":
		return &chaincfg.TestNet3Params, nil
	case "mainnet":
		return &chaincfg.MainNetParams, nil
	case "regtest":
		return &chaincfg.RegressionNetParams, nil
	case "simnet":
		return &chaincfg.SimNetParams, nil
	default:
		return nil, fmt.Errorf("unknown network %s", network)
	}
}
