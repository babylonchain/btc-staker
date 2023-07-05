package main

import (
	"fmt"

	st "github.com/babylonchain/btc-staker/staker"
	ut "github.com/babylonchain/btc-staker/utils"
	"github.com/btcsuite/btcd/btcutil"
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
	stakerKeyFlag     = "staker-key"
	stakerAddressFlag = "staker-address"
	delegatorKeyFlag  = "delegator-key"
	juryKeyFlag       = "jury-key"
	stakingTimeFlag   = "staking-time"
)

var generateStakingScript = cli.Command{
	Name:      "generate-staking-script",
	ShortName: "gscr",
	Usage:     "Generate a staking script and staking taproot address",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  stakerKeyFlag,
			Usage: "hex encoded Bitcoin public key of the staker in bip340 format",
		},
		cli.StringFlag{
			Name:  stakerAddressFlag,
			Usage: "bech32 encoded address of the staker",
		},
		cli.StringFlag{
			Name:     delegatorKeyFlag,
			Usage:    "hex encoded public key of the delegator in bip340 format",
			Required: true,
		},
		cli.StringFlag{
			Name:     juryKeyFlag,
			Usage:    "hex encoded public key of the jury in bip340 format",
			Required: true,
		},
		cli.Uint64Flag{
			Name:     stakingTimeFlag,
			Usage:    "staking time in Bitcoin blocks. Max value is 65535",
			Required: true,
		},
	},
	Action: genScript,
}

func genScript(ctx *cli.Context) error {
	switch {
	case ctx.IsSet(stakerKeyFlag) && ctx.IsSet(stakerAddressFlag):
		return fmt.Errorf("only one of %s or %s can be set", stakerKeyFlag, stakerAddressFlag)
	case !ctx.IsSet(stakerKeyFlag) && !ctx.IsSet(stakerAddressFlag):
		return fmt.Errorf("one of %s or %s must be set", stakerKeyFlag, stakerAddressFlag)
	}
	netParams, err := ut.GetBtcNetworkParams(ctx.GlobalString(btcNetworkFlag))

	if err != nil {
		return err
	}

	var stakerPkString string

	if ctx.IsSet(stakerAddressFlag) {
		stakerAddress := ctx.String(stakerAddressFlag)
		stakerAddressParsed, err := btcutil.DecodeAddress(stakerAddress, netParams)
		if err != nil {
			return err
		}

		ct, err := getStakerControllerFromCtx(ctx)

		if err != nil {
			return err
		}

		stakerPk, err := ct.Wc.AddressPublicKey(stakerAddressParsed)

		if err != nil {
			return nil
		}

		stakerPkString = st.EncodeSchnorrPkToHexString(stakerPk)
	} else {
		stakerPkString = ctx.String(stakerKeyFlag)
	}

	response, err := st.GenerateStakingScriptAndAddress(
		stakerPkString,
		ctx.String(delegatorKeyFlag),
		ctx.String(juryKeyFlag),
		ctx.Uint64(stakingTimeFlag),
		netParams,
	)

	if err != nil {
		return err
	}

	printRespJSON(response)
	return nil
}
