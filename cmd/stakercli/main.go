package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/urfave/cli"
)

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "[btc-staker] %v\n", err)
	os.Exit(1)
}

func printRespJSON(resp interface{}) {
	jsonBytes, err := json.MarshalIndent(resp, "", "    ")
	if err != nil {
		fmt.Println("unable to decode response: ", err)
		return
	}

	fmt.Printf("%s\n", jsonBytes)
}

const (
	btcNetworkFlag = "btc-network"
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

func main() {
	app := cli.NewApp()
	app.Name = "stakercli"
	app.Usage = "btc staking controller"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  btcNetworkFlag,
			Usage: "btc network on which staking should take place",
			Value: "testnet3",
		},
	}

	app.Commands = append(app.Commands, scriptsCommands...)

	if err := app.Run(os.Args); err != nil {
		fatal(err)
	}
}
