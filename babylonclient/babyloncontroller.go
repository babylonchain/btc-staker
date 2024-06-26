package babylonclient

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	sdkErr "cosmossdk.io/errors"
	sdkmath "cosmossdk.io/math"
	"github.com/avast/retry-go/v4"
	bbnclient "github.com/babylonchain/babylon/client/client"
	"github.com/babylonchain/babylon/crypto/eots"
	bbntypes "github.com/babylonchain/babylon/types"
	bcctypes "github.com/babylonchain/babylon/x/btccheckpoint/types"
	btcctypes "github.com/babylonchain/babylon/x/btccheckpoint/types"
	btclctypes "github.com/babylonchain/babylon/x/btclightclient/types"
	btcstypes "github.com/babylonchain/babylon/x/btcstaking/types"
	bsctypes "github.com/babylonchain/babylon/x/btcstkconsumer/types"
	"github.com/babylonchain/btc-staker/stakercfg"
	"github.com/babylonchain/btc-staker/stakerdb"
	"github.com/babylonchain/btc-staker/utils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
	bq "github.com/cosmos/cosmos-sdk/types/query"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	sttypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	pv "github.com/cosmos/relayer/v2/relayer/provider"
	"github.com/sirupsen/logrus"
	"go.uber.org/zap"
)

var (
	// TODO: Maybe configurable?
	RtyAttNum = uint(5)
	RtyAtt    = retry.Attempts(RtyAttNum)
	RtyDel    = retry.Delay(time.Millisecond * 400)
	RtyErr    = retry.LastErrorOnly(true)
)

var (
	ErrInvalidBabylonExecution             = errors.New("message send to babylon was executed with error")
	ErrHeaderNotKnownToBabylon             = errors.New("btc header not known to babylon")
	ErrHeaderOnBabylonLCFork               = errors.New("btc header is on babylon btc light client fork")
	ErrFinalityProviderDoesNotExist        = errors.New("finality provider does not exist")
	ErrFinalityProviderIsSlashed           = errors.New("finality provider is slashed")
	ErrDelegationNotFound                  = errors.New("delegation not found")
	ErrInvalidValueReceivedFromBabylonNode = errors.New("invalid value received from babylon node")
)

type BabylonController struct {
	bbnClient *bbnclient.Client
	cfg       *stakercfg.BBNConfig
	btcParams *chaincfg.Params
	logger    *logrus.Logger
}

var _ BabylonClient = (*BabylonController)(nil)

func NewBabylonController(
	cfg *stakercfg.BBNConfig,
	btcParams *chaincfg.Params,
	logger *logrus.Logger,
	clientLogger *zap.Logger,
) (*BabylonController, error) {
	babylonConfig := stakercfg.BBNConfigToBabylonConfig(cfg)

	// TODO should be validated earlier
	if err := babylonConfig.Validate(); err != nil {
		return nil, err
	}

	bc, err := bbnclient.New(
		&babylonConfig,
		clientLogger,
	)

	if err != nil {
		return nil, err
	}

	// wrap to our type
	client := &BabylonController{
		bc,
		cfg,
		btcParams,
		logger,
	}

	return client, nil
}

type StakingTrackerResponse struct {
	SlashingAddress         btcutil.Address
	SlashingRate            sdkmath.LegacyDec
	MinComissionRate        sdkmath.LegacyDec
	CovenantPks             []*btcec.PublicKey
	CovenantQuruomThreshold uint32
	MinSlashingFee          btcutil.Amount
	MinUnbodningTime        uint16
}

type FinalityProviderInfo struct {
	BabylonPk secp256k1.PubKey
	BtcPk     btcec.PublicKey
}

type FinalityProvidersClientResponse struct {
	FinalityProviders []FinalityProviderInfo
	Total             uint64
}

type FinalityProviderClientResponse struct {
	FinalityProvider FinalityProviderInfo
}

// Copied from vigilante. Weirdly, there is only Stop function (no Start function ?)
func (bc *BabylonController) Stop() error {
	return bc.bbnClient.Stop()
}

func (bc *BabylonController) Params() (*StakingParams, error) {
	// TODO: uint64 are quite silly types for these params, probably uint8 or uint16 would be enough
	// as we do not expect finalization to be more than 255 or in super extreme 65535
	// TODO: it would probably be good to have separate methods for those
	var bccParams *bcctypes.Params
	if err := retry.Do(func() error {

		response, err := bc.bbnClient.BTCCheckpointParams()
		if err != nil {
			return err
		}
		bccParams = &response.Params
		return nil
	}, RtyAtt, RtyDel, RtyErr, retry.OnRetry(func(n uint, err error) {
		bc.logger.WithFields(logrus.Fields{
			"attempt":      n + 1,
			"max_attempts": RtyAttNum,
			"error":        err,
		}).Error("Failed to query babylon client for btc checkpoint params")
	})); err != nil {
		return nil, err
	}

	var stakingTrackerParams *StakingTrackerResponse
	if err := retry.Do(func() error {
		trackerParams, err := bc.QueryStakingTracker()
		if err != nil {
			return err
		}
		stakingTrackerParams = trackerParams
		return nil
	}, RtyAtt, RtyDel, RtyErr, retry.OnRetry(func(n uint, err error) {
		bc.logger.WithFields(logrus.Fields{
			"attempt":      n + 1,
			"max_attempts": RtyAttNum,
			"error":        err,
		}).Error("Failed to query babylon client for staking tracker params")
	})); err != nil {
		return nil, err
	}

	if bccParams.CheckpointFinalizationTimeout > math.MaxUint16 {
		return nil, fmt.Errorf("checkpoint finalization timeout is bigger than uint16: %w", ErrInvalidValueReceivedFromBabylonNode)
	}

	minUnbondingTime := sdkmath.Max[uint16](
		uint16(bccParams.CheckpointFinalizationTimeout),
		stakingTrackerParams.MinUnbodningTime,
	)

	return &StakingParams{
		ConfirmationTimeBlocks:    uint32(bccParams.BtcConfirmationDepth),
		FinalizationTimeoutBlocks: uint32(bccParams.CheckpointFinalizationTimeout),
		SlashingAddress:           stakingTrackerParams.SlashingAddress,
		CovenantPks:               stakingTrackerParams.CovenantPks,
		MinSlashingTxFeeSat:       stakingTrackerParams.MinSlashingFee,
		SlashingRate:              stakingTrackerParams.SlashingRate,
		CovenantQuruomThreshold:   stakingTrackerParams.CovenantQuruomThreshold,
		MinUnbondingTime:          minUnbondingTime,
	}, nil
}

func (bc *BabylonController) GetKeyAddress() sdk.AccAddress {
	// get key address, retrieves address based on key name which is configured in
	// cfg *stakercfg.BBNConfig. If this fails, it means we have misconfiguration problem
	// and we should panic.
	// This is checked at the start of BabylonController, so if it fails something is really wrong

	keyRec, err := bc.bbnClient.GetKeyring().Key(bc.cfg.Key)

	if err != nil {
		panic(fmt.Sprintf("Failed to get key address: %s", err))
	}

	addr, err := keyRec.GetAddress()

	if err != nil {
		panic(fmt.Sprintf("Failed to get key address: %s", err))
	}

	return addr
}

func (bc *BabylonController) getTxSigner() string {
	signer := bc.GetKeyAddress()
	prefix := bc.cfg.AccountPrefix
	return sdk.MustBech32ifyAddressBytes(prefix, signer)
}

func (bc *BabylonController) getPubKeyInternal() (*secp256k1.PubKey, error) {
	record, err := bc.bbnClient.GetKeyring().KeyByAddress(bc.GetKeyAddress())

	if err != nil {
		return nil, err
	}

	pubKey, err := record.GetPubKey()

	if err != nil {
		return nil, err
	}

	switch v := pubKey.(type) {
	case *secp256k1.PubKey:
		return v, nil
	default:
		return nil, fmt.Errorf("unsupported key type in keyring")
	}
}

func (bc *BabylonController) GetPubKey() *secp256k1.PubKey {
	pubKey, err := bc.getPubKeyInternal()

	if err != nil {
		panic(fmt.Sprintf("Failed to get public key: %v", err))
	}

	return pubKey
}

func (bc *BabylonController) Sign(msg []byte) ([]byte, error) {
	sign, kt, err := bc.bbnClient.GetKeyring().SignByAddress(bc.GetKeyAddress(), msg, signing.SignMode_SIGN_MODE_DIRECT)

	if err != nil {
		return nil, err
	}

	switch v := kt.(type) {
	case *secp256k1.PubKey:
		return sign, nil
	default:
		panic(fmt.Sprintf("Unsupported key type in keyring: %s", v.Type()))
	}
}

type DelegationData struct {
	StakingTransaction                   *wire.MsgTx
	StakingTransactionIdx                uint32
	StakingTransactionInclusionProof     []byte
	StakingTransactionInclusionBlockHash *chainhash.Hash
	StakingTime                          uint16
	StakingValue                         btcutil.Amount
	FinalityProvidersBtcPks              []*btcec.PublicKey
	SlashingTransaction                  *wire.MsgTx
	SlashingTransactionSig               *schnorr.Signature
	BabylonPk                            *secp256k1.PubKey
	StakerBtcPk                          *btcec.PublicKey
	BabylonPop                           *stakerdb.ProofOfPossession
	Ud                                   *UndelegationData
}

type UndelegationData struct {
	UnbondingTransaction         *wire.MsgTx
	UnbondingTxValue             btcutil.Amount
	UnbondingTxUnbondingTime     uint16
	SlashUnbondingTransaction    *wire.MsgTx
	SlashUnbondingTransactionSig *schnorr.Signature
}

type UndelegationRequest struct {
	StakingTxHash      chainhash.Hash
	StakerUnbondingSig *schnorr.Signature
}

type CovenantSignatureInfo struct {
	Signature *schnorr.Signature
	PubKey    *btcec.PublicKey
}

type UndelegationInfo struct {
	CovenantUnbondingSignatures []CovenantSignatureInfo
	UnbondingTransaction        *wire.MsgTx
	UnbondingTime               uint16
}

type DelegationInfo struct {
	Active           bool
	UndelegationInfo *UndelegationInfo
}

func delegationDataToMsg(signer string, dg *DelegationData) (*btcstypes.MsgCreateBTCDelegation, error) {
	if dg == nil {
		return nil, fmt.Errorf("nil delegation data")
	}

	if dg.Ud == nil {
		return nil, fmt.Errorf("nil undelegation data")
	}

	serizalizedStakingTransaction, err := utils.SerializeBtcTransaction(dg.StakingTransaction)

	if err != nil {
		return nil, err
	}

	inclusionBlockHash := bbntypes.NewBTCHeaderHashBytesFromChainhash(dg.StakingTransactionInclusionBlockHash)

	slashingTx, err := btcstypes.NewBTCSlashingTxFromMsgTx(dg.SlashingTransaction)

	if err != nil {
		return nil, err
	}

	slashingTxSig := bbntypes.NewBIP340SignatureFromBTCSig(dg.SlashingTransactionSig)

	if len(dg.FinalityProvidersBtcPks) == 0 {
		return nil, fmt.Errorf("received delegation data with no finality providers")
	}

	fpPksList := make([]bbntypes.BIP340PubKey, len(dg.FinalityProvidersBtcPks))

	for i, fpPk := range dg.FinalityProvidersBtcPks {
		fpPksList[i] = *bbntypes.NewBIP340PubKeyFromBTCPK(fpPk)
	}

	// Prepare undelegation data to be sent in message
	if dg.Ud.SlashUnbondingTransaction == nil ||
		dg.Ud.SlashUnbondingTransactionSig == nil ||
		dg.Ud.UnbondingTransaction == nil {
		return nil, fmt.Errorf("received unbonding data with nil field")
	}

	serializedUnbondingTransaction, err := utils.SerializeBtcTransaction(dg.Ud.UnbondingTransaction)

	if err != nil {
		return nil, err
	}

	slashUnbondingTx, err := btcstypes.NewBTCSlashingTxFromMsgTx(dg.Ud.SlashUnbondingTransaction)

	if err != nil {
		return nil, err
	}

	slashUnbondingTxSig := bbntypes.NewBIP340SignatureFromBTCSig(dg.Ud.SlashUnbondingTransactionSig)

	return &btcstypes.MsgCreateBTCDelegation{
		Signer:    signer,
		BabylonPk: dg.BabylonPk,
		Pop: &btcstypes.ProofOfPossession{
			// Note: this should be always safe conversion as we received data from our db
			BtcSigType: btcstypes.BTCSigType(dg.BabylonPop.BtcSigType),
			BabylonSig: dg.BabylonPop.BabylonSigOverBtcPk,
			BtcSig:     dg.BabylonPop.BtcSigOverBabylonSig,
		},
		BtcPk:        bbntypes.NewBIP340PubKeyFromBTCPK(dg.StakerBtcPk),
		FpBtcPkList:  fpPksList,
		StakingTime:  uint32(dg.StakingTime),
		StakingValue: int64(dg.StakingValue),
		// TODO: It is super bad that this thing (TransactionInfo) spread over whole babylon codebase, and it
		// is used in all modules, rpc, database etc.
		StakingTx: &bcctypes.TransactionInfo{
			Key: &bcctypes.TransactionKey{
				Index: dg.StakingTransactionIdx,
				Hash:  &inclusionBlockHash,
			},
			Transaction: serizalizedStakingTransaction,
			Proof:       dg.StakingTransactionInclusionProof,
		},
		SlashingTx: slashingTx,
		// Data related to unbonding
		DelegatorSlashingSig:          slashingTxSig,
		UnbondingTx:                   serializedUnbondingTransaction,
		UnbondingTime:                 uint32(dg.Ud.UnbondingTxUnbondingTime),
		UnbondingValue:                int64(dg.Ud.UnbondingTxValue),
		UnbondingSlashingTx:           slashUnbondingTx,
		DelegatorUnbondingSlashingSig: slashUnbondingTxSig,
	}, nil
}

func (bc *BabylonController) reliablySendMsgs(
	msgs []sdk.Msg,
) (*pv.RelayerTxResponse, error) {
	// TODO Empty errors ??
	return bc.bbnClient.ReliablySendMsgs(context.Background(), msgs, []*sdkErr.Error{}, []*sdkErr.Error{})
}

// TODO: for now return sdk.TxResponse, it will ease up debugging/testing
// ultimately we should create our own type ate
func (bc *BabylonController) Delegate(dg *DelegationData) (*pv.RelayerTxResponse, error) {
	signer := bc.getTxSigner()

	delegateMsg, err := delegationDataToMsg(signer, dg)

	if err != nil {
		return nil, err
	}

	return bc.reliablySendMsgs([]sdk.Msg{delegateMsg})
}

func (bc *BabylonController) Undelegate(
	req *UndelegationRequest,
) (*pv.RelayerTxResponse, error) {

	ubSig := bbntypes.NewBIP340SignatureFromBTCSig(req.StakerUnbondingSig)

	msg := &btcstypes.MsgBTCUndelegate{
		Signer:         bc.getTxSigner(),
		StakingTxHash:  req.StakingTxHash.String(),
		UnbondingTxSig: ubSig,
	}

	return bc.reliablySendMsgs([]sdk.Msg{msg})
}

func getQueryContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	return ctx, cancel
}

func (bc *BabylonController) QueryStakingTracker() (*StakingTrackerResponse, error) {
	ctx, cancel := getQueryContext(bc.cfg.Timeout)
	defer cancel()

	clientCtx := client.Context{Client: bc.bbnClient.RPCClient}
	queryClient := btcstypes.NewQueryClient(clientCtx)

	response, err := queryClient.Params(ctx, &btcstypes.QueryParamsRequest{})
	if err != nil {
		return nil, err
	}

	slashingAddress, err := btcutil.DecodeAddress(response.Params.SlashingAddress, bc.btcParams)
	if err != nil {
		return nil, err
	}

	// check this early than covenant config makes sense, so that rest of the
	// code can assume that:
	// 1. covenant quorum is less or equal to number of covenant pks
	// 2. covenant pks are not empty
	if len(response.Params.CovenantPks) == 0 {
		return nil, fmt.Errorf("empty list of covenant pks: %w", ErrInvalidValueReceivedFromBabylonNode)
	}

	if response.Params.CovenantQuorum > uint32(len(response.Params.CovenantPks)) {
		return nil, fmt.Errorf("covenant quorum is bigger than number of covenant pks: %w", ErrInvalidValueReceivedFromBabylonNode)
	}

	var covenantPks []*btcec.PublicKey

	for _, covenantPk := range response.Params.CovenantPks {
		covenantBtcPk, err := covenantPk.ToBTCPK()
		if err != nil {
			return nil, err
		}
		covenantPks = append(covenantPks, covenantBtcPk)
	}

	if response.Params.MinUnbondingTime > math.MaxUint16 {
		return nil, fmt.Errorf("min unbonding time is bigger than uint16: %w", ErrInvalidValueReceivedFromBabylonNode)
	}

	return &StakingTrackerResponse{
		SlashingAddress:         slashingAddress,
		SlashingRate:            response.Params.SlashingRate,
		MinComissionRate:        response.Params.MinCommissionRate,
		CovenantPks:             covenantPks,
		MinSlashingFee:          btcutil.Amount(response.Params.MinSlashingTxFeeSat),
		CovenantQuruomThreshold: response.Params.CovenantQuorum,
		MinUnbodningTime:        uint16(response.Params.MinUnbondingTime),
	}, nil
}

func (bc *BabylonController) QueryFinalityProviders(
	limit uint64,
	offset uint64) (*FinalityProvidersClientResponse, error) {
	ctx, cancel := getQueryContext(bc.cfg.Timeout)
	defer cancel()

	clientCtx := client.Context{Client: bc.bbnClient.RPCClient}
	queryClient := btcstypes.NewQueryClient(clientCtx)

	var response *btcstypes.QueryFinalityProvidersResponse
	if err := retry.Do(func() error {
		resp, err := queryClient.FinalityProviders(
			ctx,
			&btcstypes.QueryFinalityProvidersRequest{
				Pagination: &bq.PageRequest{
					Offset:     offset,
					Limit:      limit,
					CountTotal: true,
				},
			},
		)
		if err != nil {
			return err
		}
		response = resp
		return nil
	}, RtyAtt, RtyDel, RtyErr, retry.OnRetry(func(n uint, err error) {
		bc.logger.WithFields(logrus.Fields{
			"attempt":      n + 1,
			"max_attempts": RtyAttNum,
			"error":        err,
		}).Error("Failed to query babylon for the list of registered finality providers")
	})); err != nil {
		return nil, err
	}

	var finalityProviders []FinalityProviderInfo
	for _, finalityProvider := range response.FinalityProviders {
		// TODO: We actually need to use a query for ActiveFinalityProviders
		// instead of checking for the slashing condition
		if finalityProvider.SlashedBabylonHeight > 0 {
			continue
		}
		fpBtcKey, err := finalityProvider.BtcPk.ToBTCPK()
		if err != nil {
			return nil, fmt.Errorf("query finality providers error: %w", err)
		}
		fpBabylonPk := finalityProvider.BabylonPk

		fpInfo := FinalityProviderInfo{
			BabylonPk: *fpBabylonPk,
			BtcPk:     *fpBtcKey,
		}

		finalityProviders = append(finalityProviders, fpInfo)
	}

	return &FinalityProvidersClientResponse{
		FinalityProviders: finalityProviders,
		Total:             response.Pagination.Total,
	}, nil
}

func (bc *BabylonController) QueryFinalityProvider(btcPubKey *btcec.PublicKey) (*FinalityProviderClientResponse, error) {
	if btcPubKey == nil {
		return nil, fmt.Errorf("cannot query finality provider with nil btc public key")
	}

	ctx, cancel := getQueryContext(bc.cfg.Timeout)
	defer cancel()

	clientCtx := client.Context{Client: bc.bbnClient.RPCClient}

	queryClient := btcstypes.NewQueryClient(clientCtx)
	bscQueryClient := bsctypes.NewQueryClient(clientCtx)

	hexPubKey := hex.EncodeToString(schnorr.SerializePubKey(btcPubKey))

	var (
		slashedHeight uint64
		pk            *bbntypes.BIP340PubKey
		babylonPK     *secp256k1.PubKey
	)
	if err := retry.Do(func() error {
		// check if the finality provider is a Babylon one
		resp, err := queryClient.FinalityProvider(
			ctx,
			&btcstypes.QueryFinalityProviderRequest{
				FpBtcPkHex: hexPubKey,
			},
		)
		if err == nil {
			slashedHeight = resp.FinalityProvider.SlashedBabylonHeight
			pk = resp.FinalityProvider.BtcPk
			babylonPK = resp.FinalityProvider.BabylonPk
			return nil
		}

		// check if the finality provider is a consumer chain one
		bscResp, bscErr := bscQueryClient.FinalityProviderConsumer(
			ctx,
			&bsctypes.QueryFinalityProviderConsumerRequest{
				FpBtcPkHex: hexPubKey,
			},
		)
		if bscErr == nil {
			consumerFPResp, consumerFPErr := bscQueryClient.FinalityProvider(
				ctx,
				&bsctypes.QueryFinalityProviderRequest{
					ConsumerId: bscResp.ConsumerId,
					FpBtcPkHex: hexPubKey,
				},
			)
			if consumerFPErr != nil {
				return consumerFPErr
			}
			slashedHeight = consumerFPResp.FinalityProvider.SlashedBabylonHeight
			pk = consumerFPResp.FinalityProvider.BtcPk
			babylonPK = consumerFPResp.FinalityProvider.BabylonPk
			return nil
		}

		// the finality provider cannot be found
		if strings.Contains(err.Error(), btcstypes.ErrFpNotFound.Error()) &&
			strings.Contains(bscErr.Error(), btcstypes.ErrFpNotFound.Error()) {
			// if there is no finality provider with such key, we return unrecoverable error, as we not need to retry any more
			return retry.Unrecoverable(fmt.Errorf("failed to get finality provider with key: %s: %w", hexPubKey, ErrFinalityProviderDoesNotExist))
		}
		return err
	}, RtyAtt, RtyDel, RtyErr, retry.OnRetry(func(n uint, err error) {
		bc.logger.WithFields(logrus.Fields{
			"attempt":      n + 1,
			"max_attempts": RtyAttNum,
			"fpKey":        hexPubKey,
			"error":        err,
		}).Error("Failed to query babylon for the finality provider")
	})); err != nil {
		return nil, err
	}

	if slashedHeight > 0 {
		return nil, fmt.Errorf("failed to get finality provider with key: %s: %w", hexPubKey, ErrFinalityProviderIsSlashed)
	}

	btcPk, err := pk.ToBTCPK()

	if err != nil {
		return nil, fmt.Errorf("received malformed btc pk in babylon response: %w", err)
	}

	return &FinalityProviderClientResponse{
		FinalityProvider: FinalityProviderInfo{
			BabylonPk: *babylonPK,
			BtcPk:     *btcPk,
		},
	}, nil
}

func (bc *BabylonController) QueryHeaderDepth(headerHash *chainhash.Hash) (uint64, error) {
	ctx, cancel := getQueryContext(bc.cfg.Timeout)
	defer cancel()

	clientCtx := client.Context{Client: bc.bbnClient.RPCClient}
	queryClient := btclctypes.NewQueryClient(clientCtx)

	var response *btclctypes.QueryHeaderDepthResponse
	if err := retry.Do(func() error {
		depthResponse, err := queryClient.HeaderDepth(ctx, &btclctypes.QueryHeaderDepthRequest{Hash: headerHash.String()})
		if err != nil {
			return err
		}
		response = depthResponse
		return nil
	}, RtyAtt, RtyDel, RtyErr, retry.OnRetry(func(n uint, err error) {
		bc.logger.WithFields(logrus.Fields{
			"attempt":      n + 1,
			"max_attempts": RtyAttNum,
			"error":        err,
		}).Error("Failed to query babylon for the depth of the header")
	})); err != nil {

		// translate errors to locally handable ones
		if strings.Contains(err.Error(), btclctypes.ErrHeaderDoesNotExist.Error()) {
			return 0, fmt.Errorf("%s: %w", err.Error(), ErrHeaderNotKnownToBabylon)
		}

		// got unexpected error, return it
		return 0, err
	}

	return response.Depth, nil

}

// Insert BTC block header using rpc client
func (bc *BabylonController) InsertBtcBlockHeaders(headers []*wire.BlockHeader) (*pv.RelayerTxResponse, error) {
	msg := &btclctypes.MsgInsertHeaders{
		Signer:  bc.getTxSigner(),
		Headers: chainToChainBytes(headers),
	}

	return bc.reliablySendMsgs([]sdk.Msg{msg})
}

func chainToChainBytes(chain []*wire.BlockHeader) []bbntypes.BTCHeaderBytes {
	chainBytes := make([]bbntypes.BTCHeaderBytes, len(chain))
	for i, header := range chain {
		chainBytes[i] = bbntypes.NewBTCHeaderBytesFromBlockHeader(header)
	}
	return chainBytes
}

// Test methods for e2e testing
// RegisterFinalityProvider registers a BTC finality provider via a MsgCreateFinalityProvider to Babylon
// it returns tx hash and error
func (bc *BabylonController) RegisterFinalityProvider(
	bbnPubKey *secp256k1.PubKey,
	btcPubKey *bbntypes.BIP340PubKey,
	commission *sdkmath.LegacyDec,
	description *sttypes.Description,
	pop *btcstypes.ProofOfPossession,
	mpr *eots.MasterPublicRand,
	consumerID string,
) (*pv.RelayerTxResponse, error) {
	registerMsg := &btcstypes.MsgCreateFinalityProvider{
		Signer:        bc.getTxSigner(),
		Commission:    commission,
		BabylonPk:     bbnPubKey,
		BtcPk:         btcPubKey,
		Description:   description,
		Pop:           pop,
		MasterPubRand: mpr.MarshalBase58(),
		ConsumerId:    consumerID,
	}

	return bc.reliablySendMsgs([]sdk.Msg{registerMsg})
}

func (bc *BabylonController) QueryDelegationInfo(stakingTxHash *chainhash.Hash) (*DelegationInfo, error) {
	clientCtx := client.Context{Client: bc.bbnClient.RPCClient}
	queryClient := btcstypes.NewQueryClient(clientCtx)

	ctx, cancel := getQueryContext(bc.cfg.Timeout)
	defer cancel()

	var di *DelegationInfo
	if err := retry.Do(func() error {
		resp, err := queryClient.BTCDelegation(ctx, &btcstypes.QueryBTCDelegationRequest{
			StakingTxHashHex: stakingTxHash.String(),
		})
		if err != nil {
			if strings.Contains(err.Error(), btcstypes.ErrBTCDelegationNotFound.Error()) {
				// delegation is not found on babylon, do not retry further
				return retry.Unrecoverable(ErrDelegationNotFound)
			}

			return err
		}

		var udi *UndelegationInfo = nil

		if resp.BtcDelegation.UndelegationResponse != nil {
			var coventSigInfos []CovenantSignatureInfo

			for _, covenantSigInfo := range resp.BtcDelegation.UndelegationResponse.CovenantUnbondingSigList {
				covSig := covenantSigInfo
				sig, err := covSig.Sig.ToBTCSig()

				if err != nil {
					return retry.Unrecoverable(fmt.Errorf("malformed covenant sig: %s : %w", err.Error(),
						ErrInvalidValueReceivedFromBabylonNode))
				}

				pk, err := covSig.Pk.ToBTCPK()

				if err != nil {
					return retry.Unrecoverable(fmt.Errorf("malformed covenant pk: %s : %w", err.Error(),
						ErrInvalidValueReceivedFromBabylonNode))
				}

				sigInfo := CovenantSignatureInfo{
					Signature: sig,
					PubKey:    pk,
				}

				coventSigInfos = append(coventSigInfos, sigInfo)
			}

			tx, _, err := bbntypes.NewBTCTxFromHex(resp.BtcDelegation.UndelegationResponse.UnbondingTxHex)

			if err != nil {
				return retry.Unrecoverable(fmt.Errorf("malformed unbonding transaction: %s: %w", err.Error(), ErrInvalidValueReceivedFromBabylonNode))
			}

			if resp.BtcDelegation.UnbondingTime > math.MaxUint16 {
				return retry.Unrecoverable(fmt.Errorf("malformed unbonding time: %d: %w", resp.BtcDelegation.UnbondingTime, ErrInvalidValueReceivedFromBabylonNode))
			}

			udi = &UndelegationInfo{
				UnbondingTransaction:        tx,
				CovenantUnbondingSignatures: coventSigInfos,
				UnbondingTime:               uint16(resp.BtcDelegation.UnbondingTime),
			}
		}

		di = &DelegationInfo{
			Active:           resp.BtcDelegation.Active,
			UndelegationInfo: udi,
		}
		return nil
	}, RtyAtt, RtyDel, RtyErr, retry.OnRetry(func(n uint, err error) {
		bc.logger.WithFields(logrus.Fields{
			"attempt":      n + 1,
			"max_attempts": RtyAttNum,
			"error":        err,
		}).Error("Failed to query babylon for the staking transaction")
	})); err != nil {
		return nil, err
	}

	return di, nil
}

func (bc *BabylonController) IsTxAlreadyPartOfDelegation(stakingTxHash *chainhash.Hash) (bool, error) {
	_, err := bc.QueryDelegationInfo(stakingTxHash)

	if err != nil {
		if errors.Is(err, ErrDelegationNotFound) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

// Test methods for e2e testing
// Different babylon sig methods to support e2e testing
func (bc *BabylonController) SubmitCovenantSig(
	covPubKey *bbntypes.BIP340PubKey,
	stakingTxHash string,
	slashStakingAdaptorSigs [][]byte,
	unbondindgSig *bbntypes.BIP340Signature,
	slashUnbondingAdaptorSigs [][]byte,

) (*pv.RelayerTxResponse, error) {
	msg := &btcstypes.MsgAddCovenantSigs{
		Signer:                  bc.getTxSigner(),
		Pk:                      covPubKey,
		StakingTxHash:           stakingTxHash,
		SlashingTxSigs:          slashStakingAdaptorSigs,
		UnbondingTxSig:          unbondindgSig,
		SlashingUnbondingTxSigs: slashUnbondingAdaptorSigs,
	}

	return bc.reliablySendMsgs([]sdk.Msg{msg})
}

// Test methods for e2e testing
func (bc *BabylonController) RegisterConsumerChain(id, name, description string) (*pv.RelayerTxResponse, error) {
	msg := &bsctypes.MsgRegisterConsumer{
		Signer:              bc.getTxSigner(),
		ConsumerId:          id,
		ConsumerName:        name,
		ConsumerDescription: description,
	}

	return bc.reliablySendMsgs([]sdk.Msg{msg})
}

func (bc *BabylonController) QueryPendingBTCDelegations() ([]*btcstypes.BTCDelegationResponse, error) {
	ctx, cancel := getQueryContext(bc.cfg.Timeout)
	defer cancel()

	clientCtx := client.Context{Client: bc.bbnClient.RPCClient}
	queryClient := btcstypes.NewQueryClient(clientCtx)

	// query all the unsigned delegations
	queryRequest := btcstypes.QueryBTCDelegationsRequest{
		Status: btcstypes.BTCDelegationStatus_PENDING,
	}

	res, err := queryClient.BTCDelegations(ctx, &queryRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to query BTC delegations: %v", err)
	}

	return res.BtcDelegations, nil
}

func (bc *BabylonController) GetBBNClient() *bbnclient.Client {
	return bc.bbnClient
}

func (bc *BabylonController) InsertSpvProofs(submitter string, proofs []*btcctypes.BTCSpvProof) (*pv.RelayerTxResponse, error) {
	msg := &btcctypes.MsgInsertBTCSpvProof{
		Submitter: submitter,
		Proofs:    proofs,
	}

	res, err := bc.reliablySendMsgs([]sdk.Msg{msg})
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (bc *BabylonController) QueryBtcLightClientTip() (*btclctypes.BTCHeaderInfoResponse, error) {
	res, err := bc.bbnClient.QueryClient.BTCHeaderChainTip()
	if err != nil {
		return nil, fmt.Errorf("failed to query BTC tip: %v", err)
	}

	return res.Header, nil
}
