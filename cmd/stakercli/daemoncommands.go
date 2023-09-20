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
		Usage:     "More advanced commands which require staker daemon to be running.",
		Category:  "Daemon commands",
		Subcommands: []cli.Command{
			checkDaemonHealthCmd,
			listOutputsCmd,
			babylonValidatorsCmd,
			stakeCmd,
			unstakeCmd,
			stakingDetailsCmd,
			listStakingTransactionsCmd,
			withdrawableTransactionsCmd,
			unbondCmd,
		},
	},
}

const (
	stakingDaemonAddressFlag   = "daemon-address"
	offsetFlag                 = "offset"
	limitFlag                  = "limit"
	validatorPkFlag            = "validator-pk"
	stakingTimeBlocksFlag      = "staking-time"
	stakingTransactionHashFlag = "staking-transaction-hash"
	feeRateFlag                = "fee-rate"
)

var (
	defaultStakingDaemonAddress = "tcp://127.0.0.1:" + strconv.Itoa(scfg.DefaultRPCPort)
)

var checkDaemonHealthCmd = cli.Command{
	Name:      "check-health",
	ShortName: "ch",
	Usage:     "Check if staker daemon is running.",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  stakingDaemonAddressFlag,
			Usage: "Full address of the staker daemon in format tcp:://<host>:<port>",
			Value: defaultStakingDaemonAddress,
		},
	},
	Action: checkHealth,
}

var listOutputsCmd = cli.Command{
	Name:      "list-outputs",
	ShortName: "lo",
	Usage:     "List unspent outputs in connected wallet.",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  stakingDaemonAddressFlag,
			Usage: "Full address of the staker daemon in format tcp:://<host>:<port>",
			Value: defaultStakingDaemonAddress,
		},
	},
	Action: listOutputs,
}

var babylonValidatorsCmd = cli.Command{
	Name:      "babylon-validators",
	ShortName: "bv",
	Usage:     "List current BTC validators on Babylon chain",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  stakingDaemonAddressFlag,
			Usage: "full address of the staker daemon in format tcp:://<host>:<port>",
			Value: defaultStakingDaemonAddress,
		},
		cli.IntFlag{
			Name:  offsetFlag,
			Usage: "offset of the first validator to return",
			Value: 0,
		},
		cli.IntFlag{
			Name:  limitFlag,
			Usage: "maximum number of validators to return",
			Value: 100,
		},
	},
	Action: babylonValidators,
}

var stakeCmd = cli.Command{
	Name:      "stake",
	ShortName: "st",
	Usage:     "Stake an amount of BTC to Babylon",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  stakingDaemonAddressFlag,
			Usage: "full address of the staker daemon in format tcp:://<host>:<port>",
			Value: defaultStakingDaemonAddress,
		},
		cli.StringFlag{
			Name:     stakerAddressFlag,
			Usage:    "BTC address of the staker in hex",
			Required: true,
		},
		cli.Int64Flag{
			Name:     stakingAmountFlag,
			Usage:    "Staking amount in satoshis",
			Required: true,
		},
		cli.StringFlag{
			Name:     validatorPkFlag,
			Usage:    "BTC public key of the validator in hex",
			Required: true,
		},
		cli.Int64Flag{
			Name:     stakingTimeBlocksFlag,
			Usage:    "Staking time in BTC blocks",
			Required: true,
		},
	},
	Action: stake,
}

var unstakeCmd = cli.Command{
	Name:      "unstake",
	ShortName: "ust",
	Usage:     "Spends staking transaction and sends funds back to staker; this can only be done after timelock of staking transaction expires",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  stakingDaemonAddressFlag,
			Usage: "full address of the staker daemon in format tcp:://<host>:<port>",
			Value: defaultStakingDaemonAddress,
		},
		cli.StringFlag{
			Name:     stakingTransactionHashFlag,
			Usage:    "Hash of original staking transaction in bitcoin hex format",
			Required: true,
		},
	},
	Action: unstake,
}

var unbondCmd = cli.Command{
	Name:      "unbond",
	ShortName: "ubd",
	Usage:     "initiates unbonding flow: build unbonding tx, send to babylon, wait for signatures, and send unbonding tx to bitcoin",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  stakingDaemonAddressFlag,
			Usage: "full address of the staker daemon in format tcp:://<host>:<port>",
			Value: defaultStakingDaemonAddress,
		},
		cli.StringFlag{
			Name:     stakingTransactionHashFlag,
			Usage:    "Hash of original staking transaction in bitcoin hex format",
			Required: true,
		},
		cli.IntFlag{
			Name:  feeRateFlag,
			Usage: "fee rate to pay for unbonding tx in sats/kb",
		},
	},
	Action: unbond,
}

var stakingDetailsCmd = cli.Command{
	Name:      "staking-details",
	ShortName: "sds",
	Usage:     "Displays details of staking transaction with given hash",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  stakingDaemonAddressFlag,
			Usage: "full address of the staker daemon in format tcp:://<host>:<port>",
			Value: defaultStakingDaemonAddress,
		},
		cli.StringFlag{
			Name:     stakingTransactionHashFlag,
			Usage:    "Hash of original staking transaction in bitcoin hex format",
			Required: true,
		},
	},
	Action: stakingDetails,
}

var listStakingTransactionsCmd = cli.Command{
	Name:      "list-staking-transactions",
	ShortName: "lst",
	Usage:     "List current staking transactions in db",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  stakingDaemonAddressFlag,
			Usage: "full address of the staker daemon in format tcp:://<host>:<port>",
			Value: defaultStakingDaemonAddress,
		},
		cli.IntFlag{
			Name:  offsetFlag,
			Usage: "offset of the first transactions to return",
			Value: 0,
		},
		cli.IntFlag{
			Name:  limitFlag,
			Usage: "maximum number of transactions to return",
			Value: 100,
		},
	},
	Action: listStakingTransactions,
}

var withdrawableTransactionsCmd = cli.Command{
	Name:      "withdrawable-transactions",
	ShortName: "wt",
	Usage:     "List current tranactions that can be withdrawn i.e funds can be transferred back to staker address",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  stakingDaemonAddressFlag,
			Usage: "full address of the staker daemon in format tcp:://<host>:<port>",
			Value: defaultStakingDaemonAddress,
		},
		cli.IntFlag{
			Name:  offsetFlag,
			Usage: "offset of the first transactions to return",
			Value: 0,
		},
		cli.IntFlag{
			Name:  limitFlag,
			Usage: "maximum number of transactions to return",
			Value: 100,
		},
	},
	Action: withdrawableTransactions,
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

	offset := ctx.Int(offsetFlag)

	if offset < 0 {
		return cli.NewExitError("Offset must be non-negative", 1)
	}

	limit := ctx.Int(limitFlag)

	if limit < 0 {
		return cli.NewExitError("Limit must be non-negative", 1)
	}

	validators, err := client.BabylonValidators(sctx, &offset, &limit)

	if err != nil {
		return err
	}

	printRespJSON(validators)

	return nil
}

func stake(ctx *cli.Context) error {
	daemonAddress := ctx.String(stakingDaemonAddressFlag)
	client, err := dc.NewStakerServiceJsonRpcClient(daemonAddress)
	if err != nil {
		return err
	}

	sctx := context.Background()

	stakerAddress := ctx.String(stakerAddressFlag)
	stakingAmount := ctx.Int64(stakingAmountFlag)
	validatorPk := ctx.String(validatorPkFlag)
	stakingTimeBlocks := ctx.Int64(stakingTimeFlag)

	results, err := client.Stake(sctx, stakerAddress, stakingAmount, validatorPk, stakingTimeBlocks)
	if err != nil {
		return err
	}

	printRespJSON(results)

	return nil
}

func unstake(ctx *cli.Context) error {
	daemonAddress := ctx.String(stakingDaemonAddressFlag)
	client, err := dc.NewStakerServiceJsonRpcClient(daemonAddress)
	if err != nil {
		return err
	}

	sctx := context.Background()

	stakingTransactionHash := ctx.String(stakingTransactionHashFlag)

	result, err := client.SpendStakingTransaction(sctx, stakingTransactionHash)
	if err != nil {
		return err
	}

	printRespJSON(result)

	return nil
}

func unbond(ctx *cli.Context) error {
	daemonAddress := ctx.String(stakingDaemonAddressFlag)
	client, err := dc.NewStakerServiceJsonRpcClient(daemonAddress)
	if err != nil {
		return err
	}

	sctx := context.Background()

	stakingTransactionHash := ctx.String(stakingTransactionHashFlag)

	feeRate := ctx.Int(feeRateFlag)

	if feeRate < 0 {
		return cli.NewExitError("Fee rate must be non-negative", 1)
	}

	var fr *int = nil
	if feeRate > 0 {
		fr = &feeRate
	}

	result, err := client.UnbondStaking(sctx, stakingTransactionHash, fr)
	if err != nil {
		return err
	}

	printRespJSON(result)

	return nil
}

func stakingDetails(ctx *cli.Context) error {
	daemonAddress := ctx.String(stakingDaemonAddressFlag)
	client, err := dc.NewStakerServiceJsonRpcClient(daemonAddress)
	if err != nil {
		return err
	}

	sctx := context.Background()

	stakingTransactionHash := ctx.String(stakingTransactionHashFlag)

	result, err := client.StakingDetails(sctx, stakingTransactionHash)
	if err != nil {
		return err
	}

	printRespJSON(result)

	return nil
}

func listStakingTransactions(ctx *cli.Context) error {
	daemonAddress := ctx.String(stakingDaemonAddressFlag)
	client, err := dc.NewStakerServiceJsonRpcClient(daemonAddress)
	if err != nil {
		return err
	}

	sctx := context.Background()

	offset := ctx.Int(offsetFlag)

	if offset < 0 {
		return cli.NewExitError("Offset must be non-negative", 1)
	}

	limit := ctx.Int(limitFlag)

	if limit < 0 {
		return cli.NewExitError("Limit must be non-negative", 1)
	}

	transactions, err := client.ListStakingTransactions(sctx, &offset, &limit)

	if err != nil {
		return err
	}

	printRespJSON(transactions)

	return nil
}

func withdrawableTransactions(ctx *cli.Context) error {
	daemonAddress := ctx.String(stakingDaemonAddressFlag)
	client, err := dc.NewStakerServiceJsonRpcClient(daemonAddress)
	if err != nil {
		return err
	}

	sctx := context.Background()

	offset := ctx.Int(offsetFlag)

	if offset < 0 {
		return cli.NewExitError("Offset must be non-negative", 1)
	}

	limit := ctx.Int(limitFlag)

	if limit < 0 {
		return cli.NewExitError("Limit must be non-negative", 1)
	}

	transactions, err := client.WithdrawableTransactions(sctx, &offset, &limit)

	if err != nil {
		return err
	}

	printRespJSON(transactions)

	return nil
}
