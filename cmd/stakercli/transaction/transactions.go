package transaction

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/babylonchain/babylon/btcstaking"
	bbn "github.com/babylonchain/babylon/types"
	"github.com/babylonchain/btc-staker/cmd/stakercli/helpers"
	"github.com/babylonchain/btc-staker/utils"
	"github.com/babylonchain/networks/parameters/parser"
	"github.com/btcsuite/btcd/btcec/v2"
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
	networkNameFlag         = "network"
	stakerPublicKeyFlag     = "staker-pk"
	finalityProviderKeyFlag = "finality-provider-pk"
	txInclusionHeightFlag   = "tx-inclusion-height"
	magicBytesFlag          = "magic-bytes"
	covenantMembersPksFlag  = "covenant-committee-pks"
	covenantQuorumFlag      = "covenant-quorum"
)

var TransactionCommands = []cli.Command{
	{
		Name:      "transaction",
		ShortName: "tr",
		Usage:     "Commands related to Babylon BTC transactions Staking/Unbonding/Slashing",
		Category:  "transaction commands",
		Subcommands: []cli.Command{
			checkPhase1StakingTransactionCmd,
			createPhase1UnbondingTransactionCmd,
			createPhase1StakingTransactionCmd,
			createPhase1StakingTransactionWithParamsCmd,
		},
	},
}

var checkPhase1StakingTransactionCmd = cli.Command{
	Name:      "check-phase1-staking-transaction",
	ShortName: "cpst",
	Usage:     "stakercli transaction check-phase1-staking-transaction [fullpath/to/parameters.json]",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:     stakingTransactionFlag,
			Usage:    "Staking transaction in hex",
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

type StakingTxData struct {
	StakerPublicKeyHex           string `json:"staker_public_key_hex"`
	FinalityProviderPublicKeyHex string `json:"finality_provider_public_key_hex"`
	StakingAmount                int64  `json:"staking_amount"`
	StakingTimeBlocks            int64  `json:"staking_time_blocks"`
	// ParamsVersion is the version of the global parameters aginst which is valid
	ParamsVersion int64 `json:"params_version"`
}

type CheckPhase1StakingTxResponse struct {
	IsValid bool `json:"is_valid"`
	// StakingData will only be populated if the transaction is valid
	StakingData *StakingTxData `json:"staking_data"`
}

func validateTxAgainstParams(
	tx *wire.MsgTx,
	globalParams *parser.ParsedGlobalParams,
	net *chaincfg.Params) *CheckPhase1StakingTxResponse {

	for i := len(globalParams.Versions) - 1; i >= 0; i-- {
		params := globalParams.Versions[i]

		parsed, err := btcstaking.ParseV0StakingTx(
			tx,
			params.Tag,
			params.CovenantPks,
			params.CovenantQuorum,
			net,
		)
		if err != nil {
			continue
		}

		if parsed.OpReturnData.StakingTime < params.MinStakingTime || parsed.OpReturnData.StakingTime > params.MaxStakingTime {
			continue
		}

		if btcutil.Amount(parsed.StakingOutput.Value) < params.MinStakingAmount || btcutil.Amount(parsed.StakingOutput.Value) > params.MaxStakingAmount {
			continue
		}

		// At this point we know staking transaciton is valid against this version of global params
		return &CheckPhase1StakingTxResponse{
			IsValid: true,
			StakingData: &StakingTxData{
				StakerPublicKeyHex:           hex.EncodeToString(parsed.OpReturnData.StakerPublicKey.Marshall()),
				FinalityProviderPublicKeyHex: hex.EncodeToString(parsed.OpReturnData.FinalityProviderPublicKey.Marshall()),
				StakingAmount:                int64(parsed.StakingOutput.Value),
				StakingTimeBlocks:            int64(parsed.OpReturnData.StakingTime),
				ParamsVersion:                int64(params.Version),
			},
		}
	}

	return &CheckPhase1StakingTxResponse{
		IsValid: false,
	}
}

func checkPhase1StakingTransaction(ctx *cli.Context) error {
	inputFilePath := ctx.Args().First()
	if len(inputFilePath) == 0 {
		return errors.New("json file input is empty")
	}

	if !os.FileExists(inputFilePath) {
		return fmt.Errorf("json file input %s does not exist", inputFilePath)
	}

	globalParams, err := parser.NewParsedGlobalParamsFromFile(inputFilePath)

	if err != nil {
		return fmt.Errorf("error parsing file %s: %w", inputFilePath, err)
	}

	net := ctx.String(networkNameFlag)

	currentNetwork, err := utils.GetBtcNetworkParams(net)

	if err != nil {
		return err
	}

	stakingTxHex := ctx.String(stakingTransactionFlag)

	stakingTx, _, err := bbn.NewBTCTxFromHex(stakingTxHex)

	if err != nil {
		return err
	}

	resp := validateTxAgainstParams(stakingTx, globalParams, currentNetwork)

	helpers.PrintRespJSON(resp)

	return nil
}

var createPhase1StakingTransactionCmd = cli.Command{
	Name:      "create-phase1-staking-transaction",
	ShortName: "crpst",
	Usage:     "Creates unsigned and unfunded phase 1 staking transaction",
	Description: "Creates unsigned and unfunded phase 1 staking transaction." +
		"This method does not validate tx against global parameters, and is dedicated " +
		"for advanced use cases. For most cases use safer `create-phase1-staking-transaction-with-params`",
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

	resp := &CreatePhase1StakingTxResponse{
		StakingTxHex: hex.EncodeToString(serializedTx),
	}

	helpers.PrintRespJSON(*resp)
	return nil
}

var createPhase1StakingTransactionWithParamsCmd = cli.Command{
	Name:        "create-phase1-staking-transaction-with-params",
	ShortName:   "crpst",
	Usage:       "stakercli transaction create-phase1-staking-transaction-with-params [fullpath/to/parameters.json]",
	Description: "Creates unsigned and unfunded phase 1 staking transaction. It also validates the transaction against provided global parameters",
	Action:      createPhase1StakingTransactionWithParams,
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
		cli.Uint64Flag{
			Name:     txInclusionHeightFlag,
			Usage:    "Expected BTC height at which transaction will be included. This value is use important to chose correct global parameters for transaction",
			Required: true,
		},
		cli.StringFlag{
			Name:     networkNameFlag,
			Usage:    "Bitcoin network on which staking should take place one of (mainnet, testnet3, regtest, simnet, signet)",
			Required: true,
		},
	},
}

type CreatePhase1StakingTxResponse struct {
	StakingTxHex string `json:"staking_tx_hex"`
}

func createPhase1StakingTransactionWithParams(ctx *cli.Context) error {
	inputFilePath := ctx.Args().First()
	if len(inputFilePath) == 0 {
		return errors.New("json file input is empty")
	}

	if !os.FileExists(inputFilePath) {
		return fmt.Errorf("json file input %s does not exist", inputFilePath)
	}

	params, err := parser.NewParsedGlobalParamsFromFile(inputFilePath)

	if err != nil {
		return fmt.Errorf("error parsing file %s: %w", inputFilePath, err)

	}

	currentNetwork, err := utils.GetBtcNetworkParams(ctx.String(networkNameFlag))

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

	expectedHeight := ctx.Uint64(txInclusionHeightFlag)

	resp, err := MakeCreatePhase1StakingTxResponse(
		stakerPk,
		fpPk,
		stakingTimeBlocks,
		stakingAmount,
		params,
		expectedHeight,
		currentNetwork,
	)

	if err != nil {
		return fmt.Errorf("error building staking tx: %w", err)
	}

	helpers.PrintRespJSON(*resp)
	return nil
}

// MakeCreatePhase1StakingTxResponse builds and serialize staking tx as hex response.
func MakeCreatePhase1StakingTxResponse(
	stakerPk *btcec.PublicKey,
	fpPk *btcec.PublicKey,
	stakingTimeBlocks uint16,
	stakingAmount btcutil.Amount,
	gp *parser.ParsedGlobalParams,
	expectedInclusionHeight uint64,
	net *chaincfg.Params,
) (*CreatePhase1StakingTxResponse, error) {
	params := gp.GetVersionedGlobalParamsByHeight(expectedInclusionHeight)

	if params == nil {
		return nil, fmt.Errorf("no global params found for height %d", expectedInclusionHeight)
	}

	if stakingTimeBlocks < params.MinStakingTime || stakingTimeBlocks > params.MaxStakingTime {
		return nil, fmt.Errorf("provided staking time %d is out of bounds for params active at height %d", stakingTimeBlocks, expectedInclusionHeight)
	}

	if stakingAmount < params.MinStakingAmount || stakingAmount > params.MaxStakingAmount {
		return nil, fmt.Errorf("provided staking amount %d is out of bounds for params active at height %d", stakingAmount, expectedInclusionHeight)
	}

	_, tx, err := btcstaking.BuildV0IdentifiableStakingOutputsAndTx(
		params.Tag,
		stakerPk,
		fpPk,
		params.CovenantPks,
		params.CovenantQuorum,
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
	Usage:     "stakercli transaction create-phase1-unbonding-transaction [fullpath/to/parameters.json]",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:     stakingTransactionFlag,
			Usage:    "hex encoded staking transaction for which unbonding transaction will be created",
			Required: true,
		},
		cli.Uint64Flag{
			Name:     txInclusionHeightFlag,
			Usage:    "Inclusion height of the staking transactions. Necessary to chose correct global parameters for transaction",
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
	inputFilePath := ctx.Args().First()
	if len(inputFilePath) == 0 {
		return errors.New("json file input is empty")
	}

	if !os.FileExists(inputFilePath) {
		return fmt.Errorf("json file input %s does not exist", inputFilePath)
	}

	globalParams, err := parser.NewParsedGlobalParamsFromFile(inputFilePath)

	if err != nil {
		return fmt.Errorf("error parsing file %s: %w", inputFilePath, err)
	}

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

	stakingTxInclusionHeight := ctx.Uint64(txInclusionHeightFlag)

	paramsForHeight := globalParams.GetVersionedGlobalParamsByHeight(stakingTxInclusionHeight)

	if paramsForHeight == nil {
		return fmt.Errorf("no global params found for height %d", stakingTxInclusionHeight)
	}

	stakingTxInfo, err := btcstaking.ParseV0StakingTx(
		stakingTx,
		paramsForHeight.Tag,
		paramsForHeight.CovenantPks,
		paramsForHeight.CovenantQuorum,
		currentParams,
	)

	if err != nil {
		return fmt.Errorf("provided staking transaction is not valid: %w, for params at height %d", err, stakingTxInclusionHeight)
	}

	unbondingAmount := stakingTxInfo.StakingOutput.Value - int64(paramsForHeight.UnbondingFee)

	if unbondingAmount <= 0 {
		return fmt.Errorf(
			"staking output value is too low to create unbonding transaction. Stake amount: %d, Unbonding fee: %d",
			stakingTxInfo.StakingOutput.Value,
			paramsForHeight.UnbondingFee,
		)
	}

	unbondingInfo, err := btcstaking.BuildUnbondingInfo(
		stakingTxInfo.OpReturnData.StakerPublicKey.PubKey,
		[]*btcec.PublicKey{stakingTxInfo.OpReturnData.FinalityProviderPublicKey.PubKey},
		paramsForHeight.CovenantPks,
		paramsForHeight.CovenantQuorum,
		paramsForHeight.UnbondingTime,
		btcutil.Amount(unbondingAmount),
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
		paramsForHeight.CovenantPks,
		paramsForHeight.CovenantQuorum,
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
