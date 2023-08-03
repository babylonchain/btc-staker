package babylonclient

import (
	"context"
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
	ErrInvalidBabylonDelegation = errors.New("sent invalid babylon delegation")
	ErrHeaderNotKnownToBabylon  = errors.New("btc header not known to babylon")
	ErrHeaderOnBabylonLCFork    = errors.New("btc header is on babylon btc light client fork")
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
	JuryPk          btcec.PublicKey
}

type ValidatorInfo struct {
	BabylonPk secp256k1.PubKey
	BtcPk     btcec.PublicKey
}

type ValidatorsClientResponse struct {
	Validators []ValidatorInfo
	Total      uint64
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
		ComfirmationTimeBlocks:    uint32(bccParams.BtcConfirmationDepth),
		FinalizationTimeoutBlocks: uint32(bccParams.CheckpointFinalizationTimeout),
		SlashingAddress:           stakingTrackerParams.SlashingAddress,
		JuryPk:                    stakingTrackerParams.JuryPk,
		// TODO: Currently hardcoded on babylon level.
		MinSlashingTxFeeSat: 1,
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
	BabylonEcdsaSigOverBtcPk             []byte
	BtcSchnorrSigOverBabylonSig          []byte
}

func delegationDataToMsg(signer string, dg *DelegationData) (*btcstypes.MsgCreateBTCDelegation, error) {

	schnorSig, err := bbntypes.NewBIP340Signature(dg.BtcSchnorrSigOverBabylonSig)

	if err != nil {
		return nil, err
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
			BabylonSig: dg.BabylonEcdsaSigOverBtcPk,
			BtcSig:     schnorSig,
		},
		StakingTx: &btcstypes.StakingTx{
			Tx:            serizalizedStakingTransaction,
			StakingScript: dg.StakingTransactionScript,
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

func (bc *BabylonController) reliablySendMsgs(msgs []sdk.Msg, errorMsg string) (*sdk.TxResponse, error) {
	ctx := context.Background()

	// TODO: Consider using differnt client (maybe CosmosProvider from releayer impl?) this one is not particularly
	// great as it bundles all the functionality: builidng tx, signing, broadcasting to mempool, waiting for inclusion in block
	// therefore this operation can tak a lot of time i.e at most cfg.BlockTimeout
	var response *sdk.TxResponse
	if err := retry.Do(func() error {
		resp, err := bc.ChainClient.SendMsgs(ctx, msgs, "")
		if err != nil {
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
	})); err != nil {
		return nil, err
	}

	return response, nil
}

// TODO: for now return sdk.TxResponse, it will ease up debugging/testing
// ultimately we should create our own type ate
func (bc *BabylonController) Delegate(dg *DelegationData) (*sdk.TxResponse, error) {
	delegateMsg, err := delegationDataToMsg(bc.getTxSigner(), dg)

	if err != nil {
		return nil, err
	}

	response, err := bc.reliablySendMsgs([]sdk.Msg{delegateMsg}, "Failed to send delegation transaction to babylon node")

	if err != nil {
		return nil, err
	}

	if response.Code != 0 {
		// This quite specific case in which we send delegation to babylon, it was included in the block
		// but it execution failed. It is a bit criticial error, as we are wasting gas on invalid transaction
		// we return error and response so that caller decides what to do with it.
		return response, ErrInvalidBabylonDelegation
	}

	return response, nil
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

	juryPk, err := response.Params.JuryPk.ToBTCPK()

	if err != nil {
		return nil, err
	}

	return &StakingTrackerResponse{
		SlashingAddress: slashingAddress,
		JuryPk:          *juryPk,
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
		if validator.Slashed {
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

		if strings.Contains(err.Error(), btclctypes.ErrHeaderOnFork.Error()) {
			return 0, fmt.Errorf("%s: %w", err.Error(), ErrHeaderOnBabylonLCFork)
		}

		// got unexpected error, return it
		return 0, err
	}

	return response.Depth, nil

}

// Insert BTC block header using rpc client
func (bc *BabylonController) InsertBtcBlockHeaders(headers []*wire.BlockHeader) (*sdk.TxResponse, error) {
	// convert to []sdk.Msg type
	imsgs := []sdk.Msg{}
	for _, h := range headers {
		headerBytes := bbntypes.NewBTCHeaderBytesFromBlockHeader(h)
		msg := btclctypes.MsgInsertHeader{
			Header: &headerBytes,
			Signer: bc.getTxSigner(),
		}

		imsgs = append(imsgs, &msg)
	}

	return bc.reliablySendMsgs(imsgs, "Failed to send block headers to babylon node")
}
