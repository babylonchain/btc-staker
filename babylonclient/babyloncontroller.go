package babylonclient

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	sdkErr "cosmossdk.io/errors"
	sdkmath "cosmossdk.io/math"
	"github.com/avast/retry-go/v4"
	bbn "github.com/babylonchain/babylon/app"
	bbntypes "github.com/babylonchain/babylon/types"
	bcctypes "github.com/babylonchain/babylon/x/btccheckpoint/types"
	btclctypes "github.com/babylonchain/babylon/x/btclightclient/types"
	btcstypes "github.com/babylonchain/babylon/x/btcstaking/types"
	"github.com/babylonchain/btc-staker/stakercfg"
	"github.com/babylonchain/btc-staker/stakerdb"
	"github.com/babylonchain/btc-staker/utils"
	bbnclient "github.com/babylonchain/rpc-client/client"
	"github.com/babylonchain/rpc-client/config"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
	bq "github.com/cosmos/cosmos-sdk/types/query"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	sttypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	pv "github.com/cosmos/relayer/v2/relayer/provider"
	"github.com/sirupsen/logrus"
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
	ErrValidatorDoesNotExist               = errors.New("validator does not exist")
	ErrValidatorIsSlashed                  = errors.New("validator is slashed")
	ErrDelegationNotFound                  = errors.New("delegation not found")
	ErrInvalidValueReceivedFromBabylonNode = errors.New("invalid value received from babylon node")
)

type BabylonController struct {
	Keybase   keyring.Keyring
	bbnClient *bbnclient.Client
	cfg       *stakercfg.BBNConfig
	btcParams *chaincfg.Params
	logger    *logrus.Logger
}

var _ BabylonClient = (*BabylonController)(nil)

// TODO: Expose it from rpc-client
func keyringFromConfig(bbnConfig *config.BabylonConfig) (keyring.Keyring, error) {
	tmpBabylon := bbn.NewTmpBabylonApp()

	keybase, err := keyring.New(
		bbnConfig.ChainID,
		bbnConfig.KeyringBackend,
		bbnConfig.KeyDirectory,
		os.Stdin,
		tmpBabylon.AppCodec(),
		[]keyring.Option{}...)

	if err != nil {
		return nil, err
	}

	return keybase, nil
}

func NewBabylonController(
	cfg *stakercfg.BBNConfig,
	btcParams *chaincfg.Params,
	logger *logrus.Logger,
) (*BabylonController, error) {
	babylonConfig := stakercfg.BBNConfigToBabylonConfig(cfg)

	// TODO should be validated earlier
	if err := babylonConfig.Validate(); err != nil {
		return nil, err
	}

	bc, err := bbnclient.New(
		&babylonConfig,
		logger,
	)

	if err != nil {
		return nil, err
	}

	kb, err := keyringFromConfig(&babylonConfig)

	if err != nil {
		return nil, err
	}

	// wrap to our type
	client := &BabylonController{
		kb,
		bc,
		cfg,
		btcParams,
		logger,
	}

	return client, nil
}

type StakingTrackerResponse struct {
	SlashingAddress btcutil.Address
	SlashingRate    sdkmath.LegacyDec
	CovenantPks     []btcec.PublicKey
	MinSlashingFee  btcutil.Amount
}

type ValidatorInfo struct {
	BabylonPk secp256k1.PubKey
	BtcPk     btcec.PublicKey
}

type ValidatorsClientResponse struct {
	Validators []ValidatorInfo
	Total      uint64
}

type ValidatorClientResponse struct {
	Validator ValidatorInfo
}

// Copied from vigilante. Weirdly, there is only Stop function (no Start function ?)
func (bc *BabylonController) Stop() {
	bc.bbnClient.Stop()
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

	return &StakingParams{
		ConfirmationTimeBlocks:    uint32(bccParams.BtcConfirmationDepth),
		FinalizationTimeoutBlocks: uint32(bccParams.CheckpointFinalizationTimeout),
		SlashingAddress:           stakingTrackerParams.SlashingAddress,
		CovenantPks:               stakingTrackerParams.CovenantPks,
		MinSlashingTxFeeSat:       stakingTrackerParams.MinSlashingFee,
		SlashingRate:              stakingTrackerParams.SlashingRate,
	}, nil
}

func (bc *BabylonController) GetKeyAddress() sdk.AccAddress {
	// get key address, retrieves address based on key name which is configured in
	// cfg *stakercfg.BBNConfig. If this fails, it means we have misconfiguration problem
	// and we should panic.
	// This is checked at the start of BabylonController, so if it fails something is really wrong

	keyRec, err := bc.Keybase.Key(bc.cfg.Key)

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
	record, err := bc.Keybase.KeyByAddress(bc.GetKeyAddress())

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
	sign, kt, err := bc.Keybase.SignByAddress(bc.GetKeyAddress(), msg, signing.SignMode_SIGN_MODE_DIRECT)

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
	// TODO: Support multiple validators
	ValidatorBtcPk         *btcec.PublicKey
	SlashingTransaction    *wire.MsgTx
	SlashingTransactionSig *schnorr.Signature
	BabylonPk              *secp256k1.PubKey
	StakerBtcPk            *btcec.PublicKey
	BabylonPop             *stakerdb.ProofOfPossession
}

type UndelegationData struct {
	UnbondingTransaction         *wire.MsgTx
	UnbondingTxValue             btcutil.Amount
	UnbondingTxUnbondingTime     uint16
	SlashUnbondingTransaction    *wire.MsgTx
	SlashUnbondingTransactionSig *schnorr.Signature
}

type CovenantSignatureInfo struct {
	Signature *schnorr.Signature
	PubKey    *btcec.PublicKey
}

type UndelegationInfo struct {
	CovenantUnbondingSignatures []CovenantSignatureInfo
	UnbondingTransaction        *wire.MsgTx
}

type DelegationInfo struct {
	Active           bool
	UndelegationInfo *UndelegationInfo
}

func delegationDataToMsg(signer string, dg *DelegationData) (*btcstypes.MsgCreateBTCDelegation, error) {
	if dg == nil {
		return nil, fmt.Errorf("nil delegation data")
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
		ValBtcPkList: []bbntypes.BIP340PubKey{*bbntypes.NewBIP340PubKeyFromBTCPK(dg.ValidatorBtcPk)},
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
		SlashingTx:   slashingTx,
		DelegatorSig: &slashingTxSig,
	}, nil
}

func undelegationDataToMsg(signer string, ud *UndelegationData) (*btcstypes.MsgBTCUndelegate, error) {
	if ud == nil {
		return nil, fmt.Errorf("nil unbonding data")
	}

	if ud.SlashUnbondingTransaction == nil ||
		ud.SlashUnbondingTransactionSig == nil ||
		ud.UnbondingTransaction == nil {
		return nil, fmt.Errorf("received unbonding data with nil field")
	}

	serializedUnbondingTransaction, err := utils.SerializeBtcTransaction(ud.UnbondingTransaction)

	if err != nil {
		return nil, err
	}

	slashUnbondindTx, err := btcstypes.NewBTCSlashingTxFromMsgTx(ud.SlashUnbondingTransaction)

	if err != nil {
		return nil, err
	}

	slashingTxSig := bbntypes.NewBIP340SignatureFromBTCSig(ud.SlashUnbondingTransactionSig)

	return &btcstypes.MsgBTCUndelegate{
		Signer:               signer,
		UnbondingTx:          serializedUnbondingTransaction,
		UnbondingValue:       int64(ud.UnbondingTxValue),
		UnbondingTime:        uint32(ud.UnbondingTxUnbondingTime),
		SlashingTx:           slashUnbondindTx,
		DelegatorSlashingSig: &slashingTxSig,
	}, nil
}

func (bc *BabylonController) reliablySendMsgs(
	msgs []sdk.Msg,
) (*pv.RelayerTxResponse, error) {
	return bc.bbnClient.ReliablySendMsgs(msgs, []*sdkErr.Error{}, []*sdkErr.Error{})
}

// TODO: for now return sdk.TxResponse, it will ease up debugging/testing
// ultimately we should create our own type ate
func (bc *BabylonController) Delegate(dg *DelegationData) (*pv.RelayerTxResponse, error) {
	delegateMsg, err := delegationDataToMsg(bc.getTxSigner(), dg)

	if err != nil {
		return nil, err
	}

	// TODO Empty errors ??
	return bc.bbnClient.ReliablySendMsg(delegateMsg, []*sdkErr.Error{}, []*sdkErr.Error{})
}

func (bc *BabylonController) Undelegate(ud *UndelegationData) (*pv.RelayerTxResponse, error) {
	unbondMsg, err := undelegationDataToMsg(bc.getTxSigner(), ud)

	if err != nil {
		return nil, err
	}

	// TODO Empty errors ??
	return bc.bbnClient.ReliablySendMsg(unbondMsg, []*sdkErr.Error{}, []*sdkErr.Error{})
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

	var covenantPks []btcec.PublicKey

	for _, covenantPk := range response.Params.CovenantPks {
		covenantBtcPk, err := covenantPk.ToBTCPK()
		if err != nil {
			return nil, err
		}
		covenantPks = append(covenantPks, *covenantBtcPk)
	}

	return &StakingTrackerResponse{
		SlashingAddress: slashingAddress,
		SlashingRate:    response.Params.SlashingRate,
		CovenantPks:     covenantPks,
		MinSlashingFee:  btcutil.Amount(response.Params.MinSlashingTxFeeSat),
	}, nil
}

func (bc *BabylonController) QueryValidators(
	limit uint64,
	offset uint64) (*ValidatorsClientResponse, error) {
	ctx, cancel := getQueryContext(bc.cfg.Timeout)
	defer cancel()

	clientCtx := client.Context{Client: bc.bbnClient.RPCClient}
	queryClient := btcstypes.NewQueryClient(clientCtx)

	var response *btcstypes.QueryBTCValidatorsResponse
	if err := retry.Do(func() error {
		resp, err := queryClient.BTCValidators(
			ctx,
			&btcstypes.QueryBTCValidatorsRequest{
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
		}).Error("Failed to query babylon for the list of registered validators")
	})); err != nil {
		return nil, err
	}

	var validators []ValidatorInfo
	for _, validator := range response.BtcValidators {
		// TODO: We actually need to use a query for ActiveBTCValidators
		// instead of checking for the slashing condition
		if validator.SlashedBabylonHeight > 0 {
			continue
		}
		validatorBtcKey, err := validator.BtcPk.ToBTCPK()
		if err != nil {
			return nil, fmt.Errorf("query validators error: %w", err)
		}
		validatorBabylonPk := validator.BabylonPk

		validatorInfo := ValidatorInfo{
			BabylonPk: *validatorBabylonPk,
			BtcPk:     *validatorBtcKey,
		}

		validators = append(validators, validatorInfo)
	}

	return &ValidatorsClientResponse{
		Validators: validators,
		Total:      response.Pagination.Total,
	}, nil
}

func (bc *BabylonController) QueryValidator(btcPubKey *btcec.PublicKey) (*ValidatorClientResponse, error) {
	if btcPubKey == nil {
		return nil, fmt.Errorf("cannot query validator with nil btc public key")
	}

	ctx, cancel := getQueryContext(bc.cfg.Timeout)
	defer cancel()

	clientCtx := client.Context{Client: bc.bbnClient.RPCClient}
	queryClient := btcstypes.NewQueryClient(clientCtx)

	hexPubKey := hex.EncodeToString(schnorr.SerializePubKey(btcPubKey))

	var response *btcstypes.QueryBTCValidatorResponse
	if err := retry.Do(func() error {
		resp, err := queryClient.BTCValidator(
			ctx,
			&btcstypes.QueryBTCValidatorRequest{
				ValBtcPkHex: hexPubKey,
			},
		)
		if err != nil {
			if strings.Contains(err.Error(), btcstypes.ErrBTCValNotFound.Error()) {
				// if there is no validator with such key, we return unrecoverable error, as we not need to retry any more
				return retry.Unrecoverable(fmt.Errorf("failed to get validator with key: %s: %w", hexPubKey, ErrValidatorDoesNotExist))
			}

			return err
		}
		response = resp
		return nil
	}, RtyAtt, RtyDel, RtyErr, retry.OnRetry(func(n uint, err error) {
		bc.logger.WithFields(logrus.Fields{
			"attempt":      n + 1,
			"max_attempts": RtyAttNum,
			"validator":    hexPubKey,
			"error":        err,
		}).Error("Failed to query babylon for the validator")
	})); err != nil {
		return nil, err
	}

	if response.BtcValidator.SlashedBabylonHeight > 0 {
		return nil, fmt.Errorf("failed to get validator with key: %s: %w", hexPubKey, ErrValidatorIsSlashed)
	}

	btcPk, err := response.BtcValidator.BtcPk.ToBTCPK()

	if err != nil {
		return nil, fmt.Errorf("received malformed btc pk in babylon response: %w", err)
	}

	return &ValidatorClientResponse{
		Validator: ValidatorInfo{
			BabylonPk: *response.BtcValidator.BabylonPk,
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

// RegisterValidator registers a BTC validator via a MsgCreateBTCValidator to Babylon
// it returns tx hash and error
func (bc *BabylonController) RegisterValidator(
	bbnPubKey *secp256k1.PubKey, btcPubKey *bbntypes.BIP340PubKey, commission *sdkmath.LegacyDec,
	description *sttypes.Description, pop *btcstypes.ProofOfPossession) (*pv.RelayerTxResponse, error) {
	registerMsg := &btcstypes.MsgCreateBTCValidator{
		Signer:      bc.getTxSigner(),
		Commission:  commission,
		BabylonPk:   bbnPubKey,
		BtcPk:       btcPubKey,
		Description: description,
		Pop:         pop,
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

		if resp.UndelegationInfo != nil {
			var coventSigInfos []CovenantSignatureInfo = make([]CovenantSignatureInfo, 0)

			for _, covenantSigInfo := range resp.UndelegationInfo.CovenantUnbondingSigList {
				sig, err := covenantSigInfo.Sig.ToBTCSig()

				if err != nil {
					if err != nil {
						return retry.Unrecoverable(fmt.Errorf("malformed covenant sig: %s : %w", err.Error(),
							ErrInvalidValueReceivedFromBabylonNode))
					}
				}

				pk, err := covenantSigInfo.Pk.ToBTCPK()

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

			tx, err := btcstypes.ParseBtcTx(resp.UndelegationInfo.UnbondingTx)

			if err != nil {
				return retry.Unrecoverable(fmt.Errorf("malformed unbonding transaction: %s: %w", err.Error(), ErrInvalidValueReceivedFromBabylonNode))
			}

			udi = &UndelegationInfo{
				UnbondingTransaction:        tx,
				CovenantUnbondingSignatures: coventSigInfos,
			}
		}

		di = &DelegationInfo{
			Active:           resp.Active,
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
	sig *bbntypes.BIP340Signature) (*pv.RelayerTxResponse, error) {
	msg := &btcstypes.MsgAddCovenantSig{
		Signer:        bc.getTxSigner(),
		Pk:            covPubKey,
		StakingTxHash: stakingTxHash,
		Sig:           sig,
	}

	return bc.reliablySendMsgs([]sdk.Msg{msg})
}

func (bc *BabylonController) SubmitCovenantUnbondingSigs(
	covPubKey *bbntypes.BIP340PubKey,
	stakingTxHash string,
	unbondingSig *bbntypes.BIP340Signature,
	slashUnbondingSig *bbntypes.BIP340Signature,
) (*pv.RelayerTxResponse, error) {
	msg := &btcstypes.MsgAddCovenantUnbondingSigs{
		Signer:                 bc.getTxSigner(),
		Pk:                     covPubKey,
		StakingTxHash:          stakingTxHash,
		UnbondingTxSig:         unbondingSig,
		SlashingUnbondingTxSig: slashUnbondingSig,
	}

	return bc.reliablySendMsgs([]sdk.Msg{msg})
}

func (bc *BabylonController) QueryPendingBTCDelegations() ([]*btcstypes.BTCDelegation, error) {
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

func (bc *BabylonController) QueryValidatorDelegations(validatorBtcPubKey *btcec.PublicKey) ([]*btcstypes.BTCDelegation, error) {
	ctx, cancel := getQueryContext(bc.cfg.Timeout)
	defer cancel()

	clientCtx := client.Context{Client: bc.bbnClient.RPCClient}

	queryClient := btcstypes.NewQueryClient(clientCtx)

	key := bbntypes.NewBIP340PubKeyFromBTCPK(validatorBtcPubKey)

	// query all the unsigned delegations
	queryRequest := &btcstypes.QueryBTCValidatorDelegationsRequest{
		ValBtcPkHex: key.MarshalHex(),
	}
	res, err := queryClient.BTCValidatorDelegations(ctx, queryRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to query BTC delegations: %v", err)
	}

	var delegations []*btcstypes.BTCDelegation

	for _, dels := range res.BtcDelegatorDelegations {
		delegations = append(delegations, dels.Dels...)
	}

	return delegations, nil
}
