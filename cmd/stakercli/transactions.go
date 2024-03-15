package main

import (
	"encoding/hex"
	"fmt"

	"github.com/babylonchain/babylon/btcstaking"
	bbn "github.com/babylonchain/babylon/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/urfave/cli"
)

const (
	stakingAmountFlag      = "staking-amount"
	stakingTransactionFlag = "staking-transaction"
	magicBytesFlag         = "magic-bytes"
	covenantMembersPks     = "covenant-committee-pks"
	covenantQuorumFlag     = "covenant-quorum"
	networkFlagName        = "network"
)

var transactionCommands = []cli.Command{
	{
		Name:      "transaction",
		ShortName: "tr",
		Usage:     "Commands related to Babylon BTC transactions Staking/Unbonding/Slashing",
		Category:  "transaction commands",
		Subcommands: []cli.Command{
			checkPhase1StakingTransactionCmd,
		},
	},
}

var checkPhase1StakingTransactionCmd = cli.Command{
	Name:      "check-phase1-staking-transaction",
	ShortName: "cpst",
	Usage:     "Checks whether provided staking transactions is valid staking transaction",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:     stakingTransactionFlag,
			Usage:    "Staking transaction in hex",
			Required: true,
		},
		cli.StringFlag{
			Name:     magicBytesFlag,
			Usage:    "Magic bytes in op return output in hex",
			Required: true,
		},
		cli.StringSliceFlag{
			Name:     covenantMembersPks,
			Usage:    "BTC public keys of the covenant committee members",
			Required: true,
		},
		cli.Uint64Flag{
			Name:     covenantQuorumFlag,
			Usage:    "Required quorum for the covenant members",
			Required: true,
		},
		cli.StringFlag{
			Name:  networkFlagName,
			Usage: "Bitcoin network on which staking should take place",
			Value: chaincfg.TestNet3Params.Name,
		},
	},
	Action: checkPhase1StakingTransaction,
}

func getNetworkParams(network string) (*chaincfg.Params, error) {
	switch network {
	case chaincfg.TestNet3Params.Name:
		return &chaincfg.TestNet3Params, nil
	case chaincfg.MainNetParams.Name:
		return &chaincfg.MainNetParams, nil
	case chaincfg.RegressionNetParams.Name:
		return &chaincfg.RegressionNetParams, nil
	case chaincfg.SimNetParams.Name:
		return &chaincfg.SimNetParams, nil
	case chaincfg.SigNetParams.Name:
		return &chaincfg.SigNetParams, nil
	default:
		return nil, fmt.Errorf("unknown network: %s", network)
	}
}

func checkPhase1StakingTransaction(ctx *cli.Context) error {
	net := ctx.String(networkFlagName)

	currentParams, err := getNetworkParams(net)

	if err != nil {
		return err
	}

	stakingTxHex := ctx.String(stakingTransactionFlag)

	tx, _, err := bbn.NewBTCTxFromHex(stakingTxHex)

	if err != nil {
		return err
	}

	magicBytesHex := ctx.String(magicBytesFlag)

	magicBytes, err := hex.DecodeString(magicBytesHex)

	if err != nil {
		return err
	}

	covenantMembersPks := ctx.StringSlice(covenantMembersPks)

	var covenantPubKeys []*btcec.PublicKey

	for _, fpPk := range covenantMembersPks {

		fpPkBytes, err := hex.DecodeString(fpPk)
		if err != nil {
			return err
		}

		fpSchnorrKey, err := schnorr.ParsePubKey(fpPkBytes)
		if err != nil {
			return err
		}

		covenantPubKeys = append(covenantPubKeys, fpSchnorrKey)
	}

	covenantQuorum := uint32(ctx.Uint64(covenantQuorumFlag))

	_, err = btcstaking.ParseV0StakingTx(
		tx,
		magicBytes,
		covenantPubKeys,
		covenantQuorum,
		currentParams,
	)

	if err != nil {
		return err
	}

	fmt.Println("Provided transaction is valid staking transaction!")
	return nil
}
