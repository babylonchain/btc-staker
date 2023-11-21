package babylonclient

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/avast/retry-go/v4"
	bbntypes "github.com/babylonchain/babylon/types"
	bcctypes "github.com/babylonchain/babylon/x/btccheckpoint/types"
	btclctypes "github.com/babylonchain/babylon/x/btclightclient/types"
	btcstypes "github.com/babylonchain/babylon/x/btcstaking/types"
	"github.com/babylonchain/btc-staker/stakercfg"
	"github.com/babylonchain/btc-staker/stakerdb"
	"github.com/babylonchain/btc-staker/utils"
	"github.com/babylonchain/rpc-client/query"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
	grpctypes "github.com/cosmos/cosmos-sdk/types/grpc"
	bq "github.com/cosmos/cosmos-sdk/types/query"
	sttypes "github.com/cosmos/cosmos-sdk/x/staking/types"
	"github.com/sirupsen/logrus"
	lensclient "github.com/strangelove-ventures/lens/client"
	lensquery "github.com/strangelove-ventures/lens/client/query"
	"google.golang.org/grpc/metadata"
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

func newLensClient(ccc *lensclient.ChainClientConfig, kro ...keyring.Option) (*lensclient.ChainClient, error) {
	// attach the supported algorithms to the keyring options
	keyringOptions := []keyring.Option{}
	keyringOptions = append(keyringOptions, func(options *keyring.Options) {
		options.SupportedAlgos = keyring.SigningAlgoList{hd.Secp256k1}
		options.SupportedAlgosLedger = keyring.SigningAlgoList{hd.Secp256k1}
	})
	keyringOptions = append(keyringOptions, kro...)

	cc := &lensclient.ChainClient{
		KeyringOptions: keyringOptions,
		Config:         ccc,
		Codec:          lensclient.MakeCodec(ccc.Modules, []string{}),
	}
	if err := cc.Init(); err != nil {
		return nil, err
	}

	if _, err := cc.GetKeyAddress(); err != nil {
		return nil, err
	}

	return cc, nil
}

type BabylonController struct {
	*lensclient.ChainClient
	*query.QueryClient
	cfg       *stakercfg.BBNConfig
	btcParams *chaincfg.Params
	logger    *logrus.Logger
}

var _ BabylonClient = (*BabylonController)(nil)

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

	// create a Tendermint/Cosmos client for Babylon
	cc, err := newLensClient(babylonConfig.Unwrap())
	if err != nil {
		return nil, err
	}

	// create a queryClient so that the Client inherits all query functions
	queryClient, err := query.NewWithClient(cc.RPCClient, cfg.Timeout)
	if err != nil {
		return nil, err
	}

	// wrap to our type
	client := &BabylonController{
		cc,
		queryClient,
		cfg,
		btcParams,
		logger,
	}

	return client, nil
}

type StakingTrackerResponse struct {
	SlashingAddress btcutil.Address
	SlashingRate    sdk.Dec
	CovenantPk      btcec.PublicKey
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
	if bc.ChainClient.RPCClient != nil && bc.ChainClient.RPCClient.IsRunning() {
		<-bc.ChainClient.RPCClient.Quit()
	}
}

func (bc *BabylonController) Params() (*StakingParams, error) {
	// TODO: uint64 are quite silly types for these params, probably uint8 or uint16 would be enough
	// as we do not expect finalization to be more than 255 or in super extreme 65535
	// TODO: it would probably be good to have separate methods for those
	var bccParams *bcctypes.Params
	if err := retry.Do(func() error {
		response, err := bc.QueryClient.BTCCheckpointParams()
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
		CovenantPk:                stakingTrackerParams.CovenantPk,
		MinSlashingTxFeeSat:       stakingTrackerParams.MinSlashingFee,
		SlashingRate:              stakingTrackerParams.SlashingRate,
	}, nil
}

func (bc *BabylonController) GetKeyAddress() sdk.AccAddress {
	// get key address, retrieves address based on key name which is configured in
	// cfg *stakercfg.BBNConfig. If this fails, it means we have misconfiguration problem
	// and we should panic.
	// This is checked at the start of BabylonController, so if it fails something is really wrong
	addr, err := bc.ChainClient.GetKeyAddress()

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
	sign, kt, err := bc.Keybase.SignByAddress(bc.GetKeyAddress(), msg)

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
	StakingTransactionScript             []byte
	StakingTransactionInclusionProof     []byte
	StakingTransactionInclusionBlockHash *chainhash.Hash
	SlashingTransaction                  *wire.MsgTx
	SlashingTransactionSig               *schnorr.Signature
	BabylonPk                            *secp256k1.PubKey
	BabylonPop                           *stakerdb.ProofOfPossession
}

type UndelegationData struct {
	UnbondingTransaction         *wire.MsgTx
	UnbondingTransactionScript   []byte
	SlashUnbondingTransaction    *wire.MsgTx
	SlashUnbondingTransactionSig *schnorr.Signature
}

type UndelegationInfo struct {
	CovenantUnbondingSignature  *schnorr.Signature
	ValidatorUnbondingSignature *schnorr.Signature
	UnbondingTransaction        *wire.MsgTx
	UnbondingTransactionScript  []byte
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
		StakingTx: &btcstypes.BabylonBTCTaprootTx{
			Tx:     serizalizedStakingTransaction,
			Script: dg.StakingTransactionScript,
		},
		// TODO: It is super bad that this thing (TransactionInfo) spread over whole babylon codebase, and it
		// is used in all modules, rpc, database etc.
		StakingTxInfo: &bcctypes.TransactionInfo{
			Key: &bcctypes.TransactionKey{
				Index: dg.StakingTransactionIdx,
				Hash:  &inclusionBlockHash,
			},
			// TODO: tranasction second time ? why ?
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
		ud.UnbondingTransaction == nil ||
		ud.UnbondingTransactionScript == nil {
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
		Signer: signer,
		UnbondingTx: &btcstypes.BabylonBTCTaprootTx{
			Tx:     serializedUnbondingTransaction,
			Script: ud.UnbondingTransactionScript,
		},
		SlashingTx:           slashUnbondindTx,
		DelegatorSlashingSig: &slashingTxSig,
	}, nil
}

func (bc *BabylonController) reliablySendMsgs(msgs []sdk.Msg, errorMsg string) (*sdk.TxResponse, error) {
	ctx := context.Background()

	// TODO: Consider using differnt client (maybe CosmosProvider from releayer impl?) this one is not particularly
	// great as it bundles all the functionality: builidng tx, signing, broadcasting to mempool, waiting for inclusion in block
	// therefore this operation can tak a lot of time i.e at most cfg.BlockTimeout
	var response *sdk.TxResponse
	err := retry.Do(func() error {
		resp, err := bc.ChainClient.SendMsgs(ctx, msgs, "")

		// Case when transaction was sucesffully broadcasted and included in block
		// but execution failed. Do not retry in this case, and return ErrInvalidBabylonExecution type to
		// the caller
		if err != nil && resp != nil {
			response = resp
			return retry.Unrecoverable(fmt.Errorf("%s: %w", err.Error(), ErrInvalidBabylonExecution))
		}

		if err != nil && resp == nil {
			// Our transactions was correct, but it was not included in the block for cfg.BlockTimeout
			// no point in retrying
			if errors.Is(err, lensclient.ErrTimeoutAfterWaitingForTxBroadcast) {
				return retry.Unrecoverable(err)
			}
			return err
		}

		response = resp
		return nil
	}, RtyAtt, RtyDel, RtyErr, retry.OnRetry(func(n uint, err error) {
		bc.logger.WithFields(logrus.Fields{
			"attempt":      n + 1,
			"max_attempts": RtyAttNum,
			"error":        err,
		}).Error(errorMsg)
	}))

	return response, err
}

// TODO: for now return sdk.TxResponse, it will ease up debugging/testing
// ultimately we should create our own type ate
func (bc *BabylonController) Delegate(dg *DelegationData) (*sdk.TxResponse, error) {
	delegateMsg, err := delegationDataToMsg(bc.getTxSigner(), dg)

	if err != nil {
		return nil, err
	}

	return bc.reliablySendMsgs([]sdk.Msg{delegateMsg}, "Failed to send delegation transaction to babylon node")
}

func (bc *BabylonController) Undelegate(ud *UndelegationData) (*sdk.TxResponse, error) {
	unbondMsg, err := undelegationDataToMsg(bc.getTxSigner(), ud)

	if err != nil {
		return nil, err
	}

	return bc.reliablySendMsgs([]sdk.Msg{unbondMsg}, "Failed to send undelegate transaction to babylon node")
}

func getQueryContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	defaultOptions := lensquery.DefaultOptions()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	strHeight := strconv.Itoa(int(defaultOptions.Height))
	ctx = metadata.AppendToOutgoingContext(ctx, grpctypes.GRPCBlockHeightHeader, strHeight)
	return ctx, cancel
}

func (bc *BabylonController) QueryStakingTracker() (*StakingTrackerResponse, error) {
	ctx, cancel := getQueryContext(bc.cfg.Timeout)
	defer cancel()

	clientCtx := client.Context{Client: bc.QueryClient.RPCClient}
	queryClient := btcstypes.NewQueryClient(clientCtx)

	response, err := queryClient.Params(ctx, &btcstypes.QueryParamsRequest{})
	if err != nil {
		return nil, err
	}

	slashingAddress, err := btcutil.DecodeAddress(response.Params.SlashingAddress, bc.btcParams)
	if err != nil {
		return nil, err
	}

	covenantPk, err := response.Params.CovenantPk.ToBTCPK()
	if err != nil {
		return nil, err
	}

	return &StakingTrackerResponse{
		SlashingAddress: slashingAddress,
		SlashingRate:    response.Params.SlashingRate,
		CovenantPk:      *covenantPk,
		MinSlashingFee:  btcutil.Amount(response.Params.MinSlashingTxFeeSat),
	}, nil
}

func (bc *BabylonController) QueryValidators(
	limit uint64,
	offset uint64) (*ValidatorsClientResponse, error) {
	ctx, cancel := getQueryContext(bc.cfg.Timeout)
	defer cancel()

	clientCtx := client.Context{Client: bc.QueryClient.RPCClient}
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

	clientCtx := client.Context{Client: bc.QueryClient.RPCClient}
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

	clientCtx := client.Context{Client: bc.QueryClient.RPCClient}
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
func (bc *BabylonController) InsertBtcBlockHeaders(headers []*wire.BlockHeader) (*sdk.TxResponse, error) {
	msg := &btclctypes.MsgInsertHeaders{
		Signer:  bc.getTxSigner(),
		Headers: chainToChainBytes(headers),
	}

	return bc.reliablySendMsgs([]sdk.Msg{msg}, "Failed to send block headers to babylon node")
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
	bbnPubKey *secp256k1.PubKey, btcPubKey *bbntypes.BIP340PubKey, commission *sdk.Dec,
	description *sttypes.Description, pop *btcstypes.ProofOfPossession) (*sdk.TxResponse, error) {
	registerMsg := &btcstypes.MsgCreateBTCValidator{
		Signer:      bc.getTxSigner(),
		Commission:  commission,
		BabylonPk:   bbnPubKey,
		BtcPk:       btcPubKey,
		Description: description,
		Pop:         pop,
	}

	return bc.reliablySendMsgs([]sdk.Msg{registerMsg}, "Failed to send validator registration transaction to babylon node")
}

func (bc *BabylonController) QueryDelegationInfo(stakingTxHash *chainhash.Hash) (*DelegationInfo, error) {
	clientCtx := client.Context{Client: bc.QueryClient.RPCClient}
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
			var covenantSig *schnorr.Signature = nil
			if resp.UndelegationInfo.CovenantUnbondingSig != nil {
				jsig, err := resp.UndelegationInfo.CovenantUnbondingSig.ToBTCSig()
				if err != nil {
					return retry.Unrecoverable(fmt.Errorf("malformed covenant sig: %s : %w", err.Error(),
						ErrInvalidValueReceivedFromBabylonNode))
				}
				covenantSig = jsig
			}

			var validatorSig *schnorr.Signature = nil
			if resp.UndelegationInfo.ValidatorUnbondingSig != nil {
				vsig, err := resp.UndelegationInfo.ValidatorUnbondingSig.ToBTCSig()
				if err != nil {
					return retry.Unrecoverable(fmt.Errorf("malformed validator sig: %s: %w", err.Error(), ErrInvalidValueReceivedFromBabylonNode))
				}
				validatorSig = vsig
			}

			tx, err := resp.UndelegationInfo.UnbondingTx.ToMsgTx()

			if err != nil {
				return retry.Unrecoverable(fmt.Errorf("malformed unbonding transaction: %s: %w", err.Error(), ErrInvalidValueReceivedFromBabylonNode))
			}

			udi = &UndelegationInfo{
				CovenantUnbondingSignature:  covenantSig,
				ValidatorUnbondingSignature: validatorSig,
				UnbondingTransaction:        tx,
				UnbondingTransactionScript:  resp.UndelegationInfo.UnbondingTx.Script,
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
	btcPubKey *bbntypes.BIP340PubKey,
	delPubKey *bbntypes.BIP340PubKey,
	stakingTxHash string,
	sig *bbntypes.BIP340Signature) (*sdk.TxResponse, error) {
	msg := &btcstypes.MsgAddCovenantSig{
		Signer:        bc.getTxSigner(),
		ValPk:         btcPubKey,
		DelPk:         delPubKey,
		StakingTxHash: stakingTxHash,
		Sig:           sig,
	}

	return bc.reliablySendMsgs([]sdk.Msg{msg}, "failed to submit jury sig")
}

func (bc *BabylonController) SubmitCovenantUnbondingSigs(
	btcPubKey *bbntypes.BIP340PubKey,
	delPubKey *bbntypes.BIP340PubKey,
	stakingTxHash string,
	unbondingSig *bbntypes.BIP340Signature,
	slashUnbondingSig *bbntypes.BIP340Signature,
) (*sdk.TxResponse, error) {
	msg := &btcstypes.MsgAddCovenantUnbondingSigs{
		Signer:                 bc.getTxSigner(),
		ValPk:                  btcPubKey,
		DelPk:                  delPubKey,
		StakingTxHash:          stakingTxHash,
		UnbondingTxSig:         unbondingSig,
		SlashingUnbondingTxSig: slashUnbondingSig,
	}

	return bc.reliablySendMsgs([]sdk.Msg{msg}, "failed to submit jury unbonding sig")
}

func (bc *BabylonController) SubmitValidatorUnbondingSig(
	valPubKey *bbntypes.BIP340PubKey,
	delPubKey *bbntypes.BIP340PubKey,
	stakingTxHash string,
	sig *bbntypes.BIP340Signature) (*sdk.TxResponse, error) {

	msg := &btcstypes.MsgAddValidatorUnbondingSig{
		Signer:         bc.getTxSigner(),
		ValPk:          valPubKey,
		DelPk:          delPubKey,
		StakingTxHash:  stakingTxHash,
		UnbondingTxSig: sig,
	}

	return bc.reliablySendMsgs([]sdk.Msg{msg}, "failed to submit validator unbonding sig")
}

func (bc *BabylonController) QueryPendingBTCDelegations() ([]*btcstypes.BTCDelegation, error) {
	ctx, cancel := getQueryContext(bc.cfg.Timeout)
	defer cancel()

	clientCtx := client.Context{Client: bc.QueryClient.RPCClient}
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

	clientCtx := client.Context{Client: bc.QueryClient.RPCClient}

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
