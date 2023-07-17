package main

import (
	st "github.com/babylonchain/btc-staker/staker"
	"github.com/urfave/cli"
)

var transactionCommands = []cli.Command{
	{
		Name:      "transactions",
		ShortName: "tr",
		Usage:     "Creation and management of transactions necessary for staking.",
		Category:  "Transactions",
		Subcommands: []cli.Command{
			createStakingTransactionCmd,
			sendStakingTransactionCmd,
		},
	},
}

const (
	stakingScriptFlag = "staking-script"
	stakingAmountFlag = "staking-amount"
)

var createStakingTransactionCmd = cli.Command{
	Name:      "create-staking-transaction",
	ShortName: "cst",
	Usage:     "Create and sign a staking transaction.",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  stakerAddressFlag,
			Usage: "Bech32 encoded Bitcoin address of the staker",
		},
		cli.StringFlag{
			Name:     stakingScriptFlag,
			Usage:    "Hex encoded valid staking script corresponding to the staker address",
			Required: true,
		},

		cli.Int64Flag{
			Name:     stakingAmountFlag,
			Usage:    "Staking amount in satoshis",
			Required: true,
		},
	},
	Action: createTx,
}

var sendStakingTransactionCmd = cli.Command{
	Name:      "send-staking-transaction",
	ShortName: "sst",
	Usage:     "Creates, signs, and sends staking transaction.",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  stakerAddressFlag,
			Usage: "Bech32 encoded Bitcoin address of the staker",
		},
		cli.StringFlag{
			Name:     stakingScriptFlag,
			Usage:    "Hex encoded valid staking script corresponding to the staker address",
			Required: true,
		},

		cli.Int64Flag{
			Name:     stakingAmountFlag,
			Usage:    "Staking amount in satoshis",
			Required: true,
		},
	},
	Action: sendTx,
}

func createTx(ctx *cli.Context) error {
	ct, err := getStakerControllerFromCtx(ctx)
	if err != nil {
		return err
	}

	if err != nil {
		return err
	}

	stakerAddress := ctx.String(stakerAddressFlag)
	stakingScript := ctx.String(stakingScriptFlag)
	stakingAmount := ctx.Int64(stakingAmountFlag)

	tx, err := ct.CreateStakingTransactionFromArgs(
		stakerAddress,
		stakingScript,
		stakingAmount,
	)

	if err != nil {
		return err
	}

	resp := st.CreateStakingTransactionResponse{
		TransactionHex: tx.TxHash().String(),
	}
	printRespJSON(resp)
	return nil
}

func sendTx(ctx *cli.Context) error {
	ct, err := getStakerControllerFromCtx(ctx)
	if err != nil {
		return err
	}

	if err != nil {
		return err
	}

	stakerAddress := ctx.String(stakerAddressFlag)
	stakingScript := ctx.String(stakingScriptFlag)
	stakingAmount := ctx.Int64(stakingAmountFlag)

	tx, hash, err := ct.SendStakingTransactionFromArgs(
		stakerAddress,
		stakingScript,
		stakingAmount,
	)

	if err != nil {
		return err
	}

	resp := st.SendTransactionResponse{
		TransactionHex:     tx.TxHash().String(),
		TransactionHashHex: hash.String(),
	}
	printRespJSON(resp)
	return nil
}
