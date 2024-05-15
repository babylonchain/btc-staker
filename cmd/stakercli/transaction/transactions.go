package transaction

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/babylonchain/babylon/btcstaking"
	bbn "github.com/babylonchain/babylon/types"
	"github.com/babylonchain/btc-staker/cmd/stakercli/helpers"
	"github.com/babylonchain/btc-staker/utils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/cometbft/cometbft/libs/os"
	"github.com/urfave/cli"
)

const (
	stakingTransactionFlag  = "staking-transaction"
	magicBytesFlag          = "magic-bytes"
	covenantMembersPksFlag  = "covenant-committee-pks"
	covenantQuorumFlag      = "covenant-quorum"
	networkNameFlag         = "network"
	stakerPublicKeyFlag     = "staker-pk"
	finalityProviderKeyFlag = "finality-provider-pk"
)

var TransactionCommands = []cli.Command{
	{
		Name:      "transaction",
		ShortName: "tr",
		Usage:     "Commands related to Babylon BTC transactions Staking/Unbonding/Slashing",
		Category:  "transaction commands",
		Subcommands: []cli.Command{
			checkPhase1StakingTransactionCmd,
			createPhase1StakingTransactionCmd,
			createPhase1UnbondingTransactionCmd,
			createPhase1StakingTransactionFromJsonCmd,
		},
	},
}

func parseSchnorPubKeyFromCliCtx(ctx *cli.Context, flagName string) (*btcec.PublicKey, error) {
	pkHex := ctx.String(flagName)
	return parseSchnorPubKeyFromHex(pkHex)
}

func parseSchnorPubKeyFromHex(pkHex string) (*btcec.PublicKey, error) {
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
	return parseCovenantKeysFromSlice(covenantMembersPks)
}

func parseCovenantKeysFromSlice(covenantMembersPks []string) ([]*btcec.PublicKey, error) {
	covenantPubKeys := make([]*btcec.PublicKey, len(covenantMembersPks))

	for i, fpPk := range covenantMembersPks {
		fpPkBytes, err := hex.DecodeString(fpPk)
		if err != nil {
			return nil, err
		}

		fpSchnorrKey, err := schnorr.ParsePubKey(fpPkBytes)
		if err != nil {
			return nil, err
		}

		covenantPubKeys[i] = fpSchnorrKey
	}

	return covenantPubKeys, nil
}

func parseMagicBytesFromCliCtx(ctx *cli.Context) ([]byte, error) {
	magicBytesHex := ctx.String(magicBytesFlag)
	return parseMagicBytesFromHex(magicBytesHex)
}

func parseMagicBytesFromHex(magicBytesHex string) ([]byte, error) {
	magicBytes, err := hex.DecodeString(magicBytesHex)
	if err != nil {
		return nil, err
	}

	if len(magicBytes) != btcstaking.MagicBytesLen {
		return nil, fmt.Errorf("magic bytes should be of length %d", btcstaking.MagicBytesLen)
	}

	return magicBytes, nil
}

func parseAmountFromCliCtx(ctx *cli.Context, flagName string) (btcutil.Amount, error) {
	amt := ctx.Int64(flagName)

	if amt <= 0 {
		return 0, fmt.Errorf("staking amount should be greater than 0")
	}

	return btcutil.Amount(amt), nil
}

func parseLockTimeBlocksFromCliCtx(ctx *cli.Context, flagName string) (uint16, error) {
	timeBlocks := ctx.Int64(flagName)

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
		cli.StringFlag{
			Name:  stakerPublicKeyFlag,
			Usage: "Optional staker pub key hex to match the staker pub key in tx",
		},
		cli.StringFlag{
			Name:  finalityProviderKeyFlag,
			Usage: "Optional finality provider public key hex to match the finality provider public key in tx",
		},
		cli.Int64Flag{
			Name:  helpers.StakingAmountFlag,
			Usage: "Optional staking amount in satoshis to match the amount spent in tx",
		},
		cli.Int64Flag{
			Name:  helpers.StakingTimeBlocksFlag,
			Usage: "Optional staking time in BTC blocks to match how long it was locked for",
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

	stakingTx, err := btcstaking.ParseV0StakingTx(
		tx,
		magicBytes,
		covenantMembersPks,
		covenantQuorum,
		currentParams,
	)
	if err != nil {
		return err
	}

	// verify if optional flags match.
	stakerPk := ctx.String(stakerPublicKeyFlag)
	if len(stakerPk) > 0 {
		stakerPkFromTx := schnorr.SerializePubKey(stakingTx.OpReturnData.StakerPublicKey.PubKey)
		stakerPkHexFromTx := hex.EncodeToString(stakerPkFromTx)
		if !strings.EqualFold(stakerPk, stakerPkHexFromTx) {
			return fmt.Errorf("staker pk in tx %s do not match with flag %s", stakerPkHexFromTx, stakerPk)
		}
	}

	fpPk := ctx.String(finalityProviderKeyFlag)
	if len(fpPk) > 0 {
		fpPkFromTx := schnorr.SerializePubKey(stakingTx.OpReturnData.FinalityProviderPublicKey.PubKey)
		fpPkHexFromTx := hex.EncodeToString(fpPkFromTx)
		if !strings.EqualFold(fpPk, fpPkHexFromTx) {
			return fmt.Errorf("finality provider pk in tx %s do not match with flag %s", fpPkHexFromTx, fpPk)
		}
	}

	timeBlocks := ctx.Int64(helpers.StakingTimeBlocksFlag)
	if timeBlocks > 0 && uint16(timeBlocks) != stakingTx.OpReturnData.StakingTime {
		return fmt.Errorf("staking time in tx %d do not match with flag %d", stakingTx.OpReturnData.StakingTime, timeBlocks)
	}

	amt := ctx.Int64(helpers.StakingAmountFlag)
	if amt > 0 && amt != stakingTx.StakingOutput.Value {
		return fmt.Errorf("staking amount in tx %d do not match with flag %d", tx.TxOut[0].Value, amt)
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
			Name:     helpers.StakingAmountFlag,
			Usage:    "Staking amount in satoshis",
			Required: true,
		},
		cli.Int64Flag{
			Name:     helpers.StakingTimeBlocksFlag,
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

var createPhase1StakingTransactionFromJsonCmd = cli.Command{
	Name:        "create-phase1-staking-transaction-json",
	ShortName:   "crpstjson",
	Usage:       "stakercli transaction create-phase1-staking-transaction-json [fullpath/to/inputBtcStakingTx.json]",
	Description: "Creates unsigned and unfunded phase 1 staking transaction",
	Action:      createPhase1StakingTransactionFromJson,
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

	stakingAmount, err := parseAmountFromCliCtx(ctx, helpers.StakingAmountFlag)

	if err != nil {
		return err
	}

	stakingTimeBlocks, err := parseLockTimeBlocksFromCliCtx(ctx, helpers.StakingTimeBlocksFlag)

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

	resp, err := MakeCreatePhase1StakingTxResponse(
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

	helpers.PrintRespJSON(*resp)
	return nil
}

func createPhase1StakingTransactionFromJson(ctx *cli.Context) error {
	inputFilePath := ctx.Args().First()
	if len(inputFilePath) == 0 {
		return errors.New("json file input is empty")
	}

	if !os.FileExists(inputFilePath) {
		return fmt.Errorf("json file input %s does not exist", inputFilePath)
	}

	bz, err := os.ReadFile(inputFilePath)
	if err != nil {
		return fmt.Errorf("error reading file %s: %w", inputFilePath, err)
	}

	var input InputBtcStakingTx
	if err := json.Unmarshal(bz, &input); err != nil {
		return fmt.Errorf("error parsing file content %s to struct %+v: %w", bz, input, err)
	}

	resp, err := input.ToCreatePhase1StakingTxResponse()
	if err != nil {
		return err
	}

	helpers.PrintRespJSON(*resp)
	return nil
}

// MakeCreatePhase1StakingTxResponse builds and serialize staking tx as hex response.
func MakeCreatePhase1StakingTxResponse(
	magicBytes []byte,
	stakerPk *btcec.PublicKey,
	fpPk *btcec.PublicKey,
	covenantMembersPks []*btcec.PublicKey,
	covenantQuorum uint32,
	stakingTimeBlocks uint16,
	stakingAmount btcutil.Amount,
	net *chaincfg.Params,
) (*CreatePhase1StakingTxResponse, error) {
	_, tx, err := btcstaking.BuildV0IdentifiableStakingOutputsAndTx(
		magicBytes,
		stakerPk,
		fpPk,
		covenantMembersPks,
		covenantQuorum,
		stakingTimeBlocks,
		stakingAmount,
		net,
	)
	if err != nil {
		return nil, err
	}

	serializedTx, err := utils.SerializeBtcTransaction(tx)
	if err != nil {
		return nil, err
	}

	return &CreatePhase1StakingTxResponse{
		StakingTxHex: hex.EncodeToString(serializedTx),
	}, nil
}

// createPhase1UnbondingTransactionCmd creates un-signed unbonding transaction based on
// provided valid phase1 staking transaction.
var createPhase1UnbondingTransactionCmd = cli.Command{
	Name:      "create-phase1-unbonding-transaction",
	ShortName: "crput",
	Usage:     "Creates unsigned phase 1 unbonding transaction",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:     stakingTransactionFlag,
			Usage:    "hex encoded staking transaction for which unbonding transaction will be created",
			Required: true,
		},
		cli.Int64Flag{
			Name:     helpers.UnbondingFee,
			Usage:    "unbonding fee in satoshis",
			Required: true,
		},
		cli.Int64Flag{
			Name:     helpers.UnbondingTimeFlag,
			Usage:    "Unbonding time in BTC blocks",
			Required: true,
		},
		cli.StringFlag{
			Name:     magicBytesFlag,
			Usage:    "Hex encoded magic bytes in staking transaction op return output",
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
	Action: createPhase1UnbondingTransaction,
}

type CreatePhase1UnbondingTxResponse struct {
	// bare hex of created unbonding transaction
	UnbondingTxHex string `json:"unbonding_tx_hex"`
	// base64 encoded psbt packet which can be used to sign the transaction using
	// staker bitcoind wallet using `walletprocesspsbt` rpc call
	UnbondingPsbtPacketBase64 string `json:"unbonding_psbt_packet_base64"`
}

func createPhase1UnbondingTransaction(ctx *cli.Context) error {
	net := ctx.String(networkNameFlag)

	currentParams, err := utils.GetBtcNetworkParams(net)

	if err != nil {
		return err
	}

	stakingTxHex := ctx.String(stakingTransactionFlag)

	stakingTx, _, err := bbn.NewBTCTxFromHex(stakingTxHex)

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

	stakingTxInfo, err := btcstaking.ParseV0StakingTx(
		stakingTx,
		magicBytes,
		covenantMembersPks,
		covenantQuorum,
		currentParams,
	)

	if err != nil {
		return fmt.Errorf("invalid staking transaction: %w", err)
	}

	unbondingFee, err := parseAmountFromCliCtx(ctx, helpers.UnbondingFee)

	if err != nil {
		return err
	}

	unbondingTimeBlocks, err := parseLockTimeBlocksFromCliCtx(ctx, helpers.UnbondingTimeFlag)

	if err != nil {
		return err
	}

	unbondingAmout := stakingTxInfo.StakingOutput.Value - int64(unbondingFee)

	if unbondingAmout <= 0 {
		return fmt.Errorf("invalid unbonding amount %d", unbondingAmout)
	}

	unbondingInfo, err := btcstaking.BuildUnbondingInfo(
		stakingTxInfo.OpReturnData.StakerPublicKey.PubKey,
		[]*btcec.PublicKey{stakingTxInfo.OpReturnData.FinalityProviderPublicKey.PubKey},
		covenantMembersPks,
		covenantQuorum,
		unbondingTimeBlocks,
		btcutil.Amount(unbondingAmout),
		currentParams,
	)

	if err != nil {
		return fmt.Errorf("error building unbonding info: %w", err)
	}

	stakingTxHash := stakingTx.TxHash()
	stakingTxInput := wire.NewTxIn(
		wire.NewOutPoint(
			&stakingTxHash,
			uint32(stakingTxInfo.StakingOutputIdx),
		),
		nil,
		nil,
	)

	unbondingPsbtPacket, err := psbt.New(
		[]*wire.OutPoint{&stakingTxInput.PreviousOutPoint},
		[]*wire.TxOut{unbondingInfo.UnbondingOutput},
		2,
		0,
		[]uint32{wire.MaxTxInSequenceNum},
	)

	if err != nil {
		return err
	}

	// re-build staking scripts to properly fill data necessary for signing
	// in psbt packet
	stakingScriptInfo, err := btcstaking.BuildStakingInfo(
		stakingTxInfo.OpReturnData.StakerPublicKey.PubKey,
		[]*btcec.PublicKey{stakingTxInfo.OpReturnData.FinalityProviderPublicKey.PubKey},
		covenantMembersPks,
		covenantQuorum,
		stakingTxInfo.OpReturnData.StakingTime,
		btcutil.Amount(stakingTxInfo.StakingOutput.Value),
		currentParams,
	)

	if err != nil {
		return err
	}

	unbondingPathInfo, err := stakingScriptInfo.UnbondingPathSpendInfo()

	if err != nil {
		return err
	}

	unbondingPathCtrlBlock, err := unbondingPathInfo.ControlBlock.ToBytes()

	if err != nil {
		return err
	}

	// Fill psbt packet with data which will make it possible for staker to sign
	// it using his bitcoind wallet
	unbondingPsbtPacket.Inputs[0].SighashType = txscript.SigHashDefault
	unbondingPsbtPacket.Inputs[0].WitnessUtxo = stakingTxInfo.StakingOutput
	unbondingPsbtPacket.Inputs[0].TaprootBip32Derivation = []*psbt.TaprootBip32Derivation{
		{
			XOnlyPubKey: stakingTxInfo.OpReturnData.StakerPublicKey.Marshall(),
		},
	}
	unbondingPsbtPacket.Inputs[0].TaprootLeafScript = []*psbt.TaprootTapLeafScript{
		{
			ControlBlock: unbondingPathCtrlBlock,
			Script:       unbondingPathInfo.RevealedLeaf.Script,
			LeafVersion:  unbondingPathInfo.RevealedLeaf.LeafVersion,
		},
	}

	unbondingTxBytes, err := utils.SerializeBtcTransaction(unbondingPsbtPacket.UnsignedTx)
	if err != nil {
		return err
	}

	unbondingPacketEncoded, err := unbondingPsbtPacket.B64Encode()

	if err != nil {
		return err
	}

	resp := &CreatePhase1UnbondingTxResponse{
		UnbondingTxHex:            hex.EncodeToString(unbondingTxBytes),
		UnbondingPsbtPacketBase64: unbondingPacketEncoded,
	}
	helpers.PrintRespJSON(resp)
	return nil
}
