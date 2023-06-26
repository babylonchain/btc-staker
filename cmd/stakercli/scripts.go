package main

import (
	"fmt"

	st "github.com/babylonchain/btc-staker/staker"
	"github.com/urfave/cli"
)

var scriptsCommands = []cli.Command{
	{
		Name:      "scripts",
		ShortName: "scr",
		Usage:     "Creating and managment of scripts necessary for staking",
		Category:  "Scripts",
		Subcommands: []cli.Command{
			generateStakingScript,
		},
	},
}

const (
	stakerKey     = "staker-key"
	stakerAddress = "staker-address"
	delegatorKey  = "delegator-key"
	juryKey       = "jury-key"
	stakingTime   = "staking-time"
)

var generateStakingScript = cli.Command{
	Name:      "generate-staking-script",
	ShortName: "gscr",
	Usage:     "Generate a staking script and staking taprot address",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  stakerKey,
			Usage: "hex encoded public key of the staker in bip340 format",
		},
		cli.StringFlag{
			Name:  stakerAddress,
			Usage: "bech32 encoded address of the staker",
		},
		cli.StringFlag{
			Name:     delegatorKey,
			Usage:    "hex encoded public key of the delegator in bip340 format",
			Required: true,
		},
		cli.StringFlag{
			Name:     juryKey,
			Usage:    "hex encoded public key of the jury in bip340 format",
			Required: true,
		},
		cli.Uint64Flag{
			Name:     stakingTime,
			Usage:    "staking time in blocks. Max value is 65535",
			Required: true,
		},
	},
	Action: genScript,
}

func genScript(ctx *cli.Context) error {
	switch {
	case ctx.IsSet(stakerKey) && ctx.IsSet(stakerAddress):
		return fmt.Errorf("only one of %s or %s can be set", stakerKey, stakerAddress)
	case !ctx.IsSet(stakerKey) && !ctx.IsSet(stakerAddress):
		return fmt.Errorf("one of %s or %s must be set", stakerKey, stakerAddress)
	}

	// TODO: support staker address, it requires connection to the wallet to retrieve the key
	if !ctx.IsSet(stakerAddress) {
		return fmt.Errorf("using staker address is not supported yet")
	}

	netParams, err := GetBtcNetworkParams(ctx.GlobalString(btcNetwork))

	if err != nil {
		return err
	}

	response, err := st.GenerateStakingScriptAndAddress(
		ctx.String(stakerKey),
		ctx.String(delegatorKey),
		ctx.String(juryKey),
		ctx.Uint64(stakingTime),
		netParams,
	)

	if err != nil {
		return err
	}

	printRespJSON(response)
	return nil
}
