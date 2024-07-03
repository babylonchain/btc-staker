package babylonclient

import (
	"fmt"

	sdkmath "cosmossdk.io/math"
	"github.com/babylonchain/babylon/testutil/datagen"
	"github.com/babylonchain/babylon/x/btcstaking/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
	pv "github.com/cosmos/relayer/v2/relayer/provider"
)

type StakingParams struct {
	// K-deep
	ConfirmationTimeBlocks uint32
	// W-deep
	FinalizationTimeoutBlocks uint32

	// Minimum amount of satoshis required for slashing transaction
	MinSlashingTxFeeSat btcutil.Amount

	// Bitcoin public key of the current covenant
	CovenantPks []*btcec.PublicKey

	// Address to which slashing transactions are sent
	SlashingAddress btcutil.Address

	// The rate at which the staked funds will be slashed, expressed as a decimal.
	SlashingRate sdkmath.LegacyDec

	// Convenant quorum threshold
	CovenantQuruomThreshold uint32

	// Minimum unbonding time required by bayblon
	MinUnbondingTime uint16
}

// SingleKeyCosmosKeyring represents a keyring that supports only one pritvate/public key pair
type SingleKeyKeyring interface {
	Sign(msg []byte) ([]byte, error)
	GetKeyAddress() sdk.AccAddress
	GetPubKey() *secp256k1.PubKey
}

type BabylonClient interface {
	SingleKeyKeyring
	Params() (*StakingParams, error)
	Delegate(dg *DelegationData) (*pv.RelayerTxResponse, error)
	Undelegate(req *UndelegationRequest) (*pv.RelayerTxResponse, error)
	QueryFinalityProviders(limit uint64, offset uint64) (*FinalityProvidersClientResponse, error)
	QueryFinalityProvider(btcPubKey *btcec.PublicKey) (*FinalityProviderClientResponse, error)
	QueryHeaderDepth(headerHash *chainhash.Hash) (uint64, error)
	IsTxAlreadyPartOfDelegation(stakingTxHash *chainhash.Hash) (bool, error)
	QueryDelegationInfo(stakingTxHash *chainhash.Hash) (*DelegationInfo, error)
}

type MockBabylonClient struct {
	ClientParams           *StakingParams
	babylonKey             *secp256k1.PrivKey
	SentMessages           chan *types.MsgCreateBTCDelegation
	ActiveFinalityProvider *FinalityProviderInfo
}

var _ BabylonClient = (*MockBabylonClient)(nil)

func (m *MockBabylonClient) Params() (*StakingParams, error) {
	return m.ClientParams, nil
}

func (m *MockBabylonClient) Sign(msg []byte) ([]byte, error) {
	sig, err := m.babylonKey.Sign(msg)

	if err != nil {
		return nil, err
	}
	return sig, nil
}

func (m *MockBabylonClient) GetKeyAddress() sdk.AccAddress {
	address := m.babylonKey.PubKey().Address()

	return sdk.AccAddress(address)
}

func (m *MockBabylonClient) GetPubKey() *secp256k1.PubKey {
	pk := m.babylonKey.PubKey()

	switch v := pk.(type) {
	case *secp256k1.PubKey:
		return v
	default:
		panic("Unsupported key type in keyring")
	}
}

func (m *MockBabylonClient) Delegate(dg *DelegationData) (*pv.RelayerTxResponse, error) {
	msg, err := delegationDataToMsg(dg)
	if err != nil {
		return nil, err
	}

	m.SentMessages <- msg

	return &pv.RelayerTxResponse{Code: 0}, nil
}

func (m *MockBabylonClient) QueryFinalityProviders(limit uint64, offset uint64) (*FinalityProvidersClientResponse, error) {
	return &FinalityProvidersClientResponse{
		FinalityProviders: []FinalityProviderInfo{*m.ActiveFinalityProvider},
		Total:             1,
	}, nil
}

func (m *MockBabylonClient) QueryFinalityProvider(btcPubKey *btcec.PublicKey) (*FinalityProviderClientResponse, error) {
	if m.ActiveFinalityProvider.BtcPk.IsEqual(btcPubKey) {
		return &FinalityProviderClientResponse{
			FinalityProvider: *m.ActiveFinalityProvider,
		}, nil
	} else {
		return nil, ErrFinalityProviderDoesNotExist
	}
}

func (m *MockBabylonClient) QueryHeaderDepth(headerHash *chainhash.Hash) (uint64, error) {
	// return always confirmed depth
	return uint64(m.ClientParams.ConfirmationTimeBlocks) + 1, nil
}

func (m *MockBabylonClient) IsTxAlreadyPartOfDelegation(stakingTxHash *chainhash.Hash) (bool, error) {
	return false, nil
}

func (m *MockBabylonClient) QueryDelegationInfo(stakingTxHash *chainhash.Hash) (*DelegationInfo, error) {
	return nil, fmt.Errorf("delegation do not exist")
}

func (m *MockBabylonClient) Undelegate(
	req *UndelegationRequest) (*pv.RelayerTxResponse, error) {
	return &pv.RelayerTxResponse{Code: 0}, nil
}

func GetMockClient() *MockBabylonClient {
	covenantPk, err := btcec.NewPrivateKey()
	if err != nil {
		panic(err)
	}

	priv := secp256k1.GenPrivKey()

	slashingAddress, _ := btcutil.NewAddressPubKey(covenantPk.PubKey().SerializeCompressed(), &chaincfg.SimNetParams)

	fpBtcPrivKey, err := btcec.NewPrivateKey()
	if err != nil {
		panic(err)
	}

	vi := FinalityProviderInfo{
		BabylonAddr: datagen.GenRandomAccount().GetAddress(),
		BtcPk:       *fpBtcPrivKey.PubKey(),
	}

	return &MockBabylonClient{
		ClientParams: &StakingParams{
			ConfirmationTimeBlocks:    2,
			FinalizationTimeoutBlocks: 5,
			MinSlashingTxFeeSat:       btcutil.Amount(1000),
			CovenantPks:               []*btcec.PublicKey{covenantPk.PubKey()},
			SlashingAddress:           slashingAddress,
			SlashingRate:              sdkmath.LegacyNewDecWithPrec(1, 1), // 1 * 10^{-1} = 0.1
		},
		babylonKey:             priv,
		SentMessages:           make(chan *types.MsgCreateBTCDelegation),
		ActiveFinalityProvider: &vi,
	}
}
