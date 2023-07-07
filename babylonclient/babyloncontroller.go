package babylonclient

import (
	"context"
	"fmt"
	"strconv"
	"time"

	bbntypes "github.com/babylonchain/babylon/types"
	bcctypes "github.com/babylonchain/babylon/x/btccheckpoint/types"
	"github.com/babylonchain/babylon/x/btcstaking/types"
	"github.com/babylonchain/btc-staker/stakercfg"
	"github.com/babylonchain/rpc-client/query"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	secp256k1 "github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
	grpctypes "github.com/cosmos/cosmos-sdk/types/grpc"
	lensclient "github.com/strangelove-ventures/lens/client"
	lensquery "github.com/strangelove-ventures/lens/client/query"
	"google.golang.org/grpc/metadata"
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
	return cc, nil
}

type BabylonController struct {
	*lensclient.ChainClient
	*query.QueryClient
	cfg       *stakercfg.BBNConfig
	btcParams *chaincfg.Params
}

var _ BabylonClient = (*BabylonController)(nil)

func NewBabylonController(
	cfg *stakercfg.BBNConfig,
	btcParams *chaincfg.Params,
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
	}

	return client, nil
}

type StakingTrackerResonse struct {
	SlashingAddress btcutil.Address
	JuryPk          btcec.PublicKey
}

// Copied from vigilante. Weirdly, there is only Stop function (no Start function ?)
func (bc *BabylonController) Stop() {
	if bc.ChainClient.RPCClient != nil && bc.ChainClient.RPCClient.IsRunning() {
		<-bc.ChainClient.RPCClient.Quit()
	}
}

func (bc *BabylonController) Params() (*StakingParams, error) {
	// TODO: uint64 are quite silly types for these params, pobably uint8 or uint16 would be enough
	// as we do not expect finalization to be more than 255 or in super extreme 65535
	// TODO: it would probably be good to have separate methods for those
	params, err := bc.QueryClient.BTCCheckpointParams()

	if err != nil {
		return nil, err
	}

	stakingTrackerParams, err := bc.QueryStakingTracker()

	if err != nil {
		if err != nil {
			return nil, err
		}
	}

	return &StakingParams{
		ComfirmationTimeBlocks:    uint32(params.Params.BtcConfirmationDepth),
		FinalizationTimeoutBlocks: uint32(params.Params.CheckpointFinalizationTimeout),
		SlashingAddress:           stakingTrackerParams.SlashingAddress,
		JuryPk:                    stakingTrackerParams.JuryPk,
		// TODO: Currently hardcoded on babylon level.
		MinSlashingTxFeeSat: 1,
	}, nil
}

func (bc *BabylonController) GetKeyAddress() sdk.AccAddress {
	// get key addres, retrieves address based on key name which is configured in
	// cfg *stakercfg.BBNConfig. If this fails, it mean we have misconfiguration problem
	// and we should panic.
	// TODO: Check this earlier and panic earlier
	addr, err := bc.ChainClient.GetKeyAddress()

	if err != nil {
		panic(fmt.Sprintf("Failed to get key address: %s", err))
	}

	return addr
}

func (bc *BabylonController) GetPubKey() *secp256k1.PubKey {
	address := bc.GetKeyAddress()
	record, err := bc.Keybase.KeyByAddress(address)

	if err != nil {
		panic(fmt.Sprintf("Failed to get key record: %s", err))
	}

	pubKey, err := record.GetPubKey()

	if err != nil {
		panic(fmt.Sprintf("Failed to get pubkey: %s", err))
	}

	switch v := pubKey.(type) {
	case *secp256k1.PubKey:
		return v
	default:
		panic("Unsupported key type in keyring")
	}
}

func (bc *BabylonController) Sign(msg []byte, address sdk.AccAddress) ([]byte, *secp256k1.PubKey, error) {
	sign, kt, err := bc.Keybase.SignByAddress(address, msg)

	if err != nil {
		return nil, nil, err
	}

	switch v := kt.(type) {
	case *secp256k1.PubKey:
		return sign, v, nil
	default:
		panic("Unsupported key type in keyring")
	}
}

type DelegationData struct {
	StakingTransaction               *wire.MsgTx
	StakingTransactionIdx            uint32
	StakingTransactionScript         []byte
	StakingTransactionInclusionProof []byte
	SlashingTransaction              *wire.MsgTx
	SlashingTransactionsSig          *schnorr.Signature
	BabylonPk                        *secp256k1.PubKey
	BabylonEcdsaSigOverBtcPk         []byte
	BtcSchnorrSigOverBabylonSig      []byte
}

func delegationDataToMsg(dg *DelegationData) (*types.MsgCreateBTCDelegation, error) {

	schnorSig, err := bbntypes.NewBIP340Signature(dg.BtcSchnorrSigOverBabylonSig)

	if err != nil {
		return nil, err

	}

	serizalizedStakingTransaction, err := SerializeBtcTransaction(dg.StakingTransaction)

	if err != nil {
		return nil, err
	}

	serializedSlashingTransaction, err := SerializeBtcTransaction(dg.SlashingTransaction)

	if err != nil {
		return nil, err
	}

	hash := dg.StakingTransaction.TxHash()
	// TODO: why do we need to convert it to header hash ?
	bcctypesHash := bbntypes.NewBTCHeaderHashBytesFromChainhash(&hash)

	slashingTx := types.BTCSlashingTx(serializedSlashingTransaction)
	slashingTxSig := bbntypes.BIP340Signature(dg.SlashingTransactionsSig.Serialize())

	return &types.MsgCreateBTCDelegation{
		BabylonPk: dg.BabylonPk,
		Pop: &types.ProofOfPossession{
			BabylonSig: dg.BabylonEcdsaSigOverBtcPk,
			BtcSig:     &schnorSig,
		},
		StakingTx: &types.StakingTx{
			Tx:            serizalizedStakingTransaction,
			StakingScript: dg.StakingTransactionScript,
		},
		// TODO: It is super bad that this thing (TransactionInfo) spread over whole babylon codebase, and it
		// is used in all modules, rpc, database etc.
		StakingTxInfo: &bcctypes.TransactionInfo{
			Key: &bcctypes.TransactionKey{
				Index: dg.StakingTransactionIdx,
				Hash:  &bcctypesHash,
			},
			// TODO: tranasction second time ? why ?
			Transaction: serizalizedStakingTransaction,
			Proof:       dg.StakingTransactionInclusionProof,
		},
		SlashingTx:   &slashingTx,
		DelegatorSig: &slashingTxSig,
	}, nil
}

// TODO: for now return sdk.TxResponse, it will ease up debugging/testing
// ultimately we should create our own type ate
func (bc *BabylonController) Delegate(dg *DelegationData) (*sdk.TxResponse, error) {
	delegateMsg, err := delegationDataToMsg(dg)

	if err != nil {
		return nil, err
	}

	// Internal context for now, this means delegate is non cancellable for external callers
	ctx := context.Background()
	res, err := bc.ChainClient.SendMsg(ctx, delegateMsg, "")
	if err != nil {
		return nil, err
	}
	return res, err
}

func getQueryContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	defaultOptions := lensquery.DefaultOptions()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	strHeight := strconv.Itoa(int(defaultOptions.Height))
	ctx = metadata.AppendToOutgoingContext(ctx, grpctypes.GRPCBlockHeightHeader, strHeight)
	return ctx, cancel
}

func (bc *BabylonController) QueryStakingTracker() (*StakingTrackerResonse, error) {
	ctx, cancel := getQueryContext(bc.cfg.Timeout)
	defer cancel()

	clientCtx := client.Context{Client: bc.QueryClient.RPCClient}
	queryClient := types.NewQueryClient(clientCtx)

	response, err := queryClient.Params(ctx, &types.QueryParamsRequest{})

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

	return &StakingTrackerResonse{
		SlashingAddress: slashingAddress,
		JuryPk:          *juryPk,
	}, nil
}
