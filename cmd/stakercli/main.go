package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/babylonchain/btc-staker/walletcontroller"
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
	btcNetworkFlag       = "btc-network"
	btcWalletHostFlag    = "btc-wallet-host"
	btcWalletRpcUserFlag = "btc-wallet-rpc-user"
	btcWalletRpcPassFlag = "btc-wallet-rpc-pass"
	btcWalletPassphrase  = "btc-wallet-passphrase"
)

func getWalletClientFromCtx(ctx *cli.Context) (*walletcontroller.RpcWalletController, error) {
	walletHost := ctx.String(btcWalletHostFlag)
	walletUser := ctx.String(btcWalletRpcUserFlag)
	walletPass := ctx.String(btcWalletRpcPassFlag)
	network := ctx.String(btcNetworkFlag)

	if !ctx.IsSet(btcWalletPassphrase) {
		return nil, fmt.Errorf("to interact with wallet it is necesary to provide wallet passphrase")
	}

	passphrase := ctx.String(btcWalletPassphrase)

	return walletcontroller.NewRpcWalletControllerFromArgs(
		walletHost,
		walletUser,
		walletPass,
		network,
		passphrase,
		true)
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
		cli.StringFlag{
			Name:  btcWalletHostFlag,
			Usage: "btc wallet rpc host",
			Value: "127.0.0.1:18554",
		},
		cli.StringFlag{
			Name:  btcWalletRpcUserFlag,
			Usage: "btc wallet rpc user",
			Value: "user",
		},
		cli.StringFlag{
			Name:  btcWalletRpcPassFlag,
			Usage: "btc wallet rpc password",
			Value: "pass",
		},
		cli.StringFlag{
			Name:  btcWalletRpcPassFlag,
			Usage: "btc wallet passphrase",
		},
	}

	app.Commands = append(app.Commands, scriptsCommands...)
	app.Commands = append(app.Commands, transactionCommands...)

	if err := app.Run(os.Args); err != nil {
		fatal(err)
	}
}
