package babylonclient

import (
	"github.com/babylonchain/babylon/x/btcstaking/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	secp256k1 "github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

type StakingParams struct {
	// K-deep
	ComfirmationTimeBlocks uint32
	// W-deep
	FinalizationTimeoutBlocks uint32

	// Minimum amount of satoshis required for slashing transaction
	MinSlashingTxFeeSat btcutil.Amount

	// Bitcoin public key of the current jury
	JuryPk btcec.PublicKey

	// Address to which slashing transactions are sent
	SlashingAddress btcutil.Address
}

type BabylonClient interface {
	Params() (*StakingParams, error)
	Sign(msg []byte, address sdk.AccAddress) ([]byte, *secp256k1.PubKey, error)
	GetKeyAddress() sdk.AccAddress
	GetPubKey() *secp256k1.PubKey
	Delegate(dg *DelegationData) (*sdk.TxResponse, error)
}

type MockBabylonClient struct {
	ClientParams *StakingParams
	babylonKey   *secp256k1.PrivKey
	SentMessages chan *types.MsgCreateBTCDelegation
}

var _ BabylonClient = (*MockBabylonClient)(nil)

func (m *MockBabylonClient) Params() (*StakingParams, error) {
	return m.ClientParams, nil
}

func (m *MockBabylonClient) Sign(msg []byte, address sdk.AccAddress) ([]byte, *secp256k1.PubKey, error) {
	sig, err := m.babylonKey.Sign(msg)

	if err != nil {
		return nil, nil, err
	}

	pubKey := m.babylonKey.PubKey().(*secp256k1.PubKey)

	return sig, pubKey, nil
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

func (m *MockBabylonClient) Delegate(dg *DelegationData) (*sdk.TxResponse, error) {
	msg, err := delegationDataToMsg(dg)

	if err != nil {
		return nil, err
	}

	m.SentMessages <- msg

	return &sdk.TxResponse{Code: 0}, nil
}

func GetMockClient() *MockBabylonClient {
	juryPk, err := btcec.NewPrivateKey()

	if err != nil {
		panic(err)
	}

	priv := secp256k1.GenPrivKey()

	slashingAddress, _ := btcutil.NewAddressPubKey(juryPk.PubKey().SerializeCompressed(), &chaincfg.SimNetParams)

	return &MockBabylonClient{
		ClientParams: &StakingParams{
			ComfirmationTimeBlocks:    2,
			FinalizationTimeoutBlocks: 5,
			MinSlashingTxFeeSat:       btcutil.Amount(1000),
			JuryPk:                    *juryPk.PubKey(),
			SlashingAddress:           slashingAddress,
		},
		babylonKey:   priv,
		SentMessages: make(chan *types.MsgCreateBTCDelegation),
	}
}
