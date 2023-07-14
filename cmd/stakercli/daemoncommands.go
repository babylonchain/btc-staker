package main

import (
	"context"
	"strconv"

	scfg "github.com/babylonchain/btc-staker/stakercfg"
	dc "github.com/babylonchain/btc-staker/stakerservice/client"
	"github.com/urfave/cli"
)

var daemonCommands = []cli.Command{
	{
		Name:      "daemon",
		ShortName: "dn",
		Usage:     "More advanced commands which require staker daemon to be running",
		Category:  "Daemon commands",
		Subcommands: []cli.Command{
			checkDaemonHealthCmd,
			listOutputsCmd,
			babylonValidatorsCmd,
		},
	},
}

const (
	stakingDaemonAddressFlag = "daemon-address"
)

var (
	defaultStakingDaemonAddress = "tcp://127.0.0.1:" + strconv.Itoa(scfg.DefaultRPCPort)
)

var checkDaemonHealthCmd = cli.Command{
	Name:      "check-health",
	ShortName: "ch",
	Usage:     "Check if staker daemon is running",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  stakingDaemonAddressFlag,
			Usage: "full address of the staker daemon in format tcp:://<host>:<port>",
			Value: defaultStakingDaemonAddress,
		},
	},
	Action: checkHealth,
}

var listOutputsCmd = cli.Command{
	Name:      "list-outputs",
	ShortName: "lo",
	Usage:     "List unspend outputs in connected wallet",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  stakingDaemonAddressFlag,
			Usage: "full address of the staker daemon in format tcp:://<host>:<port>",
			Value: defaultStakingDaemonAddress,
		},
	},
	Action: listOutputs,
}

var babylonValidatorsCmd = cli.Command{
	Name:      "babylon-validatos",
	ShortName: "bv",
	Usage:     "List current validators on babylon chain",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  stakingDaemonAddressFlag,
			Usage: "full address of the staker daemon in format tcp:://<host>:<port>",
			Value: defaultStakingDaemonAddress,
		},
	},
	Action: babylonValidators,
}

func checkHealth(ctx *cli.Context) error {
	daemonAddress := ctx.String(stakingDaemonAddressFlag)
	client, err := dc.NewStakerServiceJsonRpcClient(daemonAddress)
	if err != nil {
		return err
	}

	sctx := context.Background()

	health, err := client.Health(sctx)

	if err != nil {
		return err
	}

	printRespJSON(health)

	return nil
}

func listOutputs(ctx *cli.Context) error {
	daemonAddress := ctx.String(stakingDaemonAddressFlag)
	client, err := dc.NewStakerServiceJsonRpcClient(daemonAddress)
	if err != nil {
		return err
	}

	sctx := context.Background()

	outputs, err := client.ListOutputs(sctx)

	if err != nil {
		return err
	}

	printRespJSON(outputs)

	return nil
}

func babylonValidators(ctx *cli.Context) error {
	daemonAddress := ctx.String(stakingDaemonAddressFlag)
	client, err := dc.NewStakerServiceJsonRpcClient(daemonAddress)
	if err != nil {
		return err
	}

	sctx := context.Background()

	validators, err := client.BabylonValidators(sctx)

	if err != nil {
		return err
	}

	printRespJSON(validators)

	return nil
}
