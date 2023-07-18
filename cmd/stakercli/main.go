package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/babylonchain/btc-staker/babylonclient"
	"github.com/babylonchain/btc-staker/staker"
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
	btcNetworkFlag          = "btc-network"
	btcWalletHostFlag       = "btc-wallet-host"
	btcWalletRpcUserFlag    = "btc-wallet-rpc-user"
	btcWalletRpcPassFlag    = "btc-wallet-rpc-pass"
	btcWalletPassphraseFlag = "btc-wallet-passphrase"
)

func getStakerControllerFromCtx(ctx *cli.Context) (*staker.StakerController, error) {
	walletHost := ctx.String(btcWalletHostFlag)
	walletUser := ctx.String(btcWalletRpcUserFlag)
	walletPass := ctx.String(btcWalletRpcPassFlag)
	network := ctx.String(btcNetworkFlag)

	if !ctx.IsSet(btcWalletPassphraseFlag) {
		return nil, fmt.Errorf("to interact with wallet it is necesary to provide wallet passphrase")
	}

	passphrase := ctx.String(btcWalletPassphraseFlag)

	wc, err := walletcontroller.NewRpcWalletControllerFromArgs(
		walletHost,
		walletUser,
		walletPass,
		network,
		passphrase,
		true)

	if err != nil {
		return nil, err
	}

	// TODO: User real one
	bc := babylonclient.GetMockClient()

	return staker.NewStakerControllerFromClients(wc, bc)
}

func main() {
	app := cli.NewApp()
	app.Name = "stakercli"
	app.Usage = "Bitcoin staking controller"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  btcNetworkFlag,
			Usage: "Bitcoin network on which staking should take place",
			Value: "testnet3",
		},
		cli.StringFlag{
			Name:  btcWalletHostFlag,
			Usage: "Bitcoin wallet rpc host",
			Value: "127.0.0.1:18554",
		},
		cli.StringFlag{
			Name:  btcWalletRpcUserFlag,
			Usage: "Bitcoin wallet rpc user",
			Value: "user",
		},
		cli.StringFlag{
			Name:  btcWalletRpcPassFlag,
			Usage: "Bitcoin wallet rpc password",
			Value: "pass",
		},
		cli.StringFlag{
			Name:  btcWalletPassphraseFlag,
			Usage: "Bitcoin wallet passphrase",
		},
	}

	app.Commands = append(app.Commands, scriptsCommands...)
	app.Commands = append(app.Commands, transactionCommands...)
	app.Commands = append(app.Commands, daemonCommands...)
	app.Commands = append(app.Commands, adminCommands...)

	if err := app.Run(os.Args); err != nil {
		fatal(err)
	}
}
