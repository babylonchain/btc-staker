package babylonclient

import (
	"fmt"

	"github.com/babylonchain/babylon/x/btcstaking/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

type StakingParams struct {
	// K-deep
	ConfirmationTimeBlocks uint32
	// W-deep
	FinalizationTimeoutBlocks uint32

	// Minimum amount of satoshis required for slashing transaction
	MinSlashingTxFeeSat btcutil.Amount

	// Bitcoin public key of the current jury
	JuryPk btcec.PublicKey

	// Address to which slashing transactions are sent
	SlashingAddress btcutil.Address

	SlashingRate sdk.Dec
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
	Delegate(dg *DelegationData) (*sdk.TxResponse, error)
	Undelegate(ud *UndelegationData) (*sdk.TxResponse, error)
	QueryValidators(limit uint64, offset uint64) (*ValidatorsClientResponse, error)
	QueryValidator(btcPubKey *btcec.PublicKey) (*ValidatorClientResponse, error)
	QueryHeaderDepth(headerHash *chainhash.Hash) (uint64, error)
	IsTxAlreadyPartOfDelegation(stakingTxHash *chainhash.Hash) (bool, error)
	QueryDelegationInfo(stakingTxHash *chainhash.Hash) (*DelegationInfo, error)
}

type MockBabylonClient struct {
	ClientParams    *StakingParams
	babylonKey      *secp256k1.PrivKey
	SentMessages    chan *types.MsgCreateBTCDelegation
	ActiveValidator *ValidatorInfo
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

func (m *MockBabylonClient) Delegate(dg *DelegationData) (*sdk.TxResponse, error) {
	msg, err := delegationDataToMsg("signer", dg)

	if err != nil {
		return nil, err
	}

	m.SentMessages <- msg

	return &sdk.TxResponse{Code: 0}, nil
}

func (m *MockBabylonClient) QueryValidators(limit uint64, offset uint64) (*ValidatorsClientResponse, error) {
	return &ValidatorsClientResponse{
		Validators: []ValidatorInfo{*m.ActiveValidator},
		Total:      1,
	}, nil
}

func (m *MockBabylonClient) QueryValidator(btcPubKey *btcec.PublicKey) (*ValidatorClientResponse, error) {
	if m.ActiveValidator.BtcPk.IsEqual(btcPubKey) {
		return &ValidatorClientResponse{
			Validator: *m.ActiveValidator,
		}, nil
	} else {
		return nil, ErrValidatorDoesNotExist
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

func (m *MockBabylonClient) Undelegate(ud *UndelegationData) (*sdk.TxResponse, error) {
	return &sdk.TxResponse{Code: 0}, nil
}

func GetMockClient() *MockBabylonClient {
	juryPk, err := btcec.NewPrivateKey()

	if err != nil {
		panic(err)
	}

	priv := secp256k1.GenPrivKey()

	slashingAddress, _ := btcutil.NewAddressPubKey(juryPk.PubKey().SerializeCompressed(), &chaincfg.SimNetParams)

	validatorBtcPrivKey, err := btcec.NewPrivateKey()

	if err != nil {
		panic(err)
	}

	validatorBabylonPrivKey := secp256k1.GenPrivKey()
	validatorBabylonPubKey := validatorBabylonPrivKey.PubKey().(*secp256k1.PubKey)

	vi := ValidatorInfo{
		BabylonPk: *validatorBabylonPubKey,
		BtcPk:     *validatorBtcPrivKey.PubKey(),
	}

	return &MockBabylonClient{
		ClientParams: &StakingParams{
			ConfirmationTimeBlocks:    2,
			FinalizationTimeoutBlocks: 5,
			MinSlashingTxFeeSat:       btcutil.Amount(1000),
			JuryPk:                    *juryPk.PubKey(),
			SlashingAddress:           slashingAddress,
		},
		babylonKey:      priv,
		SentMessages:    make(chan *types.MsgCreateBTCDelegation),
		ActiveValidator: &vi,
	}
}
