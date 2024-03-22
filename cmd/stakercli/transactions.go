package main

import (
	"encoding/hex"
	"fmt"
	"math"

	"github.com/babylonchain/babylon/btcstaking"
	bbn "github.com/babylonchain/babylon/types"
	"github.com/babylonchain/btc-staker/utils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/urfave/cli"
)

const (
	stakingAmountFlag       = "staking-amount"
	stakingTransactionFlag  = "staking-transaction"
	magicBytesFlag          = "magic-bytes"
	covenantMembersPksFlag  = "covenant-committee-pks"
	covenantQuorumFlag      = "covenant-quorum"
	networkNameFlag         = "network"
	stakerPublicKeyFlag     = "staker-pk"
	finalityProviderKeyFlag = "finality-provider-pk"
)

var transactionCommands = []cli.Command{
	{
		Name:      "transaction",
		ShortName: "tr",
		Usage:     "Commands related to Babylon BTC transactions Staking/Unbonding/Slashing",
		Category:  "transaction commands",
		Subcommands: []cli.Command{
			checkPhase1StakingTransactionCmd,
			createPhase1StakingTransactionCmd,
		},
	},
}

func parseSchnorPubKeyFromCliCtx(ctx *cli.Context, flagName string) (*btcec.PublicKey, error) {
	pkHex := ctx.String(flagName)

	pkBytes, err := hex.DecodeString(pkHex)

	if err != nil {
		return nil, err
	}

	pk, err := schnorr.ParsePubKey(pkBytes)

	if err != nil {
		return nil, err
	}

	return pk, nil
}

func parseCovenantKeysFromCliCtx(ctx *cli.Context) ([]*btcec.PublicKey, error) {
	covenantMembersPks := ctx.StringSlice(covenantMembersPksFlag)

	var covenantPubKeys []*btcec.PublicKey

	for _, fpPk := range covenantMembersPks {

		fpPkBytes, err := hex.DecodeString(fpPk)
		if err != nil {
			return nil, err
		}

		fpSchnorrKey, err := schnorr.ParsePubKey(fpPkBytes)
		if err != nil {
			return nil, err
		}

		covenantPubKeys = append(covenantPubKeys, fpSchnorrKey)
	}

	return covenantPubKeys, nil
}

func parseMagicBytesFromCliCtx(ctx *cli.Context) ([]byte, error) {
	magicBytesHex := ctx.String(magicBytesFlag)

	magicBytes, err := hex.DecodeString(magicBytesHex)

	if err != nil {
		return nil, err
	}

	if len(magicBytes) != btcstaking.MagicBytesLen {
		return nil, fmt.Errorf("magic bytes should be of length %d", btcstaking.MagicBytesLen)
	}

	return magicBytes, nil
}

func parseStakingAmountFromCliCtx(ctx *cli.Context) (btcutil.Amount, error) {
	amt := ctx.Int64(stakingAmountFlag)

	if amt <= 0 {
		return 0, fmt.Errorf("staking amount should be greater than 0")
	}

	return btcutil.Amount(amt), nil
}

func parseStakingTimeBlocksFromCliCtx(ctx *cli.Context) (uint16, error) {
	timeBlocks := ctx.Int64(stakingTimeBlocksFlag)

	if timeBlocks <= 0 {
		return 0, fmt.Errorf("staking time blocks should be greater than 0")
	}

	if timeBlocks > math.MaxUint16 {
		return 0, fmt.Errorf("staking time blocks should be less or equal to %d", math.MaxUint16)
	}

	return uint16(timeBlocks), nil
}

var checkPhase1StakingTransactionCmd = cli.Command{
	Name:      "check-phase1-staking-transaction",
	ShortName: "cpst",
	Usage:     "Checks whether provided staking transactions is valid staking transaction (tx must be funded/have inputs)",
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
			Name:     covenantMembersPksFlag,
			Usage:    "BTC public keys of the covenant committee members",
			Required: true,
		},
		cli.Uint64Flag{
			Name:     covenantQuorumFlag,
			Usage:    "Required quorum for the covenant members",
			Required: true,
		},
		cli.StringFlag{
			Name:     networkNameFlag,
			Usage:    "Bitcoin network on which staking should take place one of (mainnet, testnet3, regtest, simnet, signet)",
			Required: true,
		},
	},
	Action: checkPhase1StakingTransaction,
}

func checkPhase1StakingTransaction(ctx *cli.Context) error {
	net := ctx.String(networkNameFlag)

	currentParams, err := utils.GetBtcNetworkParams(net)

	if err != nil {
		return err
	}

	stakingTxHex := ctx.String(stakingTransactionFlag)

	tx, _, err := bbn.NewBTCTxFromHex(stakingTxHex)

	if err != nil {
		return err
	}
	magicBytes, err := parseMagicBytesFromCliCtx(ctx)

	if err != nil {
		return err
	}

	covenantMembersPks, err := parseCovenantKeysFromCliCtx(ctx)

	if err != nil {
		return err
	}

	covenantQuorum := uint32(ctx.Uint64(covenantQuorumFlag))

	_, err = btcstaking.ParseV0StakingTx(
		tx,
		magicBytes,
		covenantMembersPks,
		covenantQuorum,
		currentParams,
	)

	if err != nil {
		return err
	}

	fmt.Println("Provided transaction is valid staking transaction!")
	return nil
}

var createPhase1StakingTransactionCmd = cli.Command{
	Name:      "create-phase1-staking-transaction",
	ShortName: "crpst",
	Usage:     "Creates unsigned and unfunded phase 1 staking transaction",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:     stakerPublicKeyFlag,
			Usage:    "staker public key in schnorr format (32 byte) in hex",
			Required: true,
		},
		cli.StringFlag{
			Name:     finalityProviderKeyFlag,
			Usage:    "finality provider public key in schnorr format (32 byte) in hex",
			Required: true,
		},
		cli.Int64Flag{
			Name:     stakingAmountFlag,
			Usage:    "Staking amount in satoshis",
			Required: true,
		},
		cli.Int64Flag{
			Name:     stakingTimeBlocksFlag,
			Usage:    "Staking time in BTC blocks",
			Required: true,
		},
		cli.StringFlag{
			Name:     magicBytesFlag,
			Usage:    "Magic bytes in op_return output in hex",
			Required: true,
		},
		cli.StringSliceFlag{
			Name:     covenantMembersPksFlag,
			Usage:    "BTC public keys of the covenant committee members",
			Required: true,
		},
		cli.Uint64Flag{
			Name:     covenantQuorumFlag,
			Usage:    "Required quorum for the covenant members",
			Required: true,
		},
		cli.StringFlag{
			Name:     networkNameFlag,
			Usage:    "Bitcoin network on which staking should take place one of (mainnet, testnet3, regtest, simnet, signet)",
			Required: true,
		},
	},
	Action: createPhase1StakingTransaction,
}

type CreatePhase1StakingTxResponse struct {
	StakingTxHex string `json:"staking_tx_hex"`
}

func createPhase1StakingTransaction(ctx *cli.Context) error {
	net := ctx.String(networkNameFlag)

	currentParams, err := utils.GetBtcNetworkParams(net)

	if err != nil {
		return err
	}

	stakerPk, err := parseSchnorPubKeyFromCliCtx(ctx, stakerPublicKeyFlag)

	if err != nil {
		return err
	}

	fpPk, err := parseSchnorPubKeyFromCliCtx(ctx, finalityProviderKeyFlag)

	if err != nil {
		return err
	}

	stakingAmount, err := parseStakingAmountFromCliCtx(ctx)

	if err != nil {
		return err
	}

	stakingTimeBlocks, err := parseStakingTimeBlocksFromCliCtx(ctx)

	if err != nil {
		return err
	}

	magicBytes, err := parseMagicBytesFromCliCtx(ctx)

	if err != nil {
		return err
	}

	covenantMembersPks, err := parseCovenantKeysFromCliCtx(ctx)

	if err != nil {
		return err
	}

	covenantQuorum := uint32(ctx.Uint64(covenantQuorumFlag))

	_, tx, err := btcstaking.BuildV0IdentifiableStakingOutputsAndTx(
		magicBytes,
		stakerPk,
		fpPk,
		covenantMembersPks,
		covenantQuorum,
		stakingTimeBlocks,
		stakingAmount,
		currentParams,
	)

	if err != nil {
		return err
	}

	serializedTx, err := utils.SerializeBtcTransaction(tx)

	if err != nil {
		return err
	}

	resp := CreatePhase1StakingTxResponse{
		StakingTxHex: hex.EncodeToString(serializedTx),
	}

	printRespJSON(resp)

	return nil
}
