package babylonclient

import (
	"fmt"

	"github.com/babylonchain/babylon/crypto/bip322"
	bbn "github.com/babylonchain/babylon/types"
	btcstypes "github.com/babylonchain/babylon/x/btcstaking/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

type BabylonBtcPopType int

const (
	SchnorrType BabylonBtcPopType = iota
	Bip322Type
	EcdsaType
)

type BabylonPop struct {
	popType BabylonBtcPopType
	BtcSig  []byte
}

// NewBabylonPop Generic constructor for BabylonPop that do as little validation
// as possible. It assumes passed btcSigOverBbnAddr is matching the popType `t`
func NewBabylonPop(t BabylonBtcPopType, btcSigOverBbnAddr []byte) (*BabylonPop, error) {
	if len(btcSigOverBbnAddr) == 0 {
		return nil, fmt.Errorf("cannot create BabylonPop with empty signatures")
	}

	return &BabylonPop{
		popType: t,
		BtcSig:  btcSigOverBbnAddr,
	}, nil
}

// NewBabylonBip322Pop build proper BabylonPop in BIP322 style, it verifies the
// the bip322 signature validity
func NewBabylonBip322Pop(
	msg []byte,
	w wire.TxWitness,
	a btcutil.Address) (*BabylonPop, error) {
	// TODO: bip322.Verify does not use it last parameter and this parameter should
	// be removed from the function signature upstream.
	// after that, we can remove the nil parameter here
	if err := bip322.Verify(msg, w, a, nil); err != nil {
		return nil, fmt.Errorf("invalid bip322 pop parameters: %w", err)
	}

	serializedWitness, err := bip322.SerializeWitness(w)

	if err != nil {
		return nil, fmt.Errorf("failed to serialize bip322 witness: %w", err)
	}

	bip322Sig := btcstypes.BIP322Sig{
		Sig:     serializedWitness,
		Address: a.EncodeAddress(),
	}

	m, err := bip322Sig.Marshal()

	if err != nil {
		return nil, fmt.Errorf("failed to serialize btcstypes.BIP322Sig proto: %w", err)
	}

	return NewBabylonPop(Bip322Type, m)
}

func NewBTCSigType(t BabylonBtcPopType) (btcstypes.BTCSigType, error) {
	switch t {
	case SchnorrType:
		return btcstypes.BTCSigType_BIP340, nil
	case Bip322Type:
		return btcstypes.BTCSigType_BIP322, nil
	case EcdsaType:
		return btcstypes.BTCSigType_ECDSA, nil
	default:
		return btcstypes.BTCSigType_BIP340, fmt.Errorf("unknown pop type")
	}
}

func IntToPopType(t int) (BabylonBtcPopType, error) {
	switch t {
	case 0:
		return SchnorrType, nil
	case 1:
		return Bip322Type, nil
	case 2:
		return EcdsaType, nil
	default:
		return SchnorrType, fmt.Errorf("uknown pop type")
	}
}

func (pop *BabylonPop) PopTypeNum() uint32 {
	return uint32(pop.popType)
}

func (pop *BabylonPop) ToBtcStakingPop() (*btcstypes.ProofOfPossessionBTC, error) {
	popType, err := NewBTCSigType(pop.popType)

	if err != nil {
		return nil, err
	}

	return &btcstypes.ProofOfPossessionBTC{
		BtcSigType: popType,
		BtcSig:     pop.BtcSig,
	}, nil
}

func (pop *BabylonPop) ValidatePop(
	bbnAddr sdk.AccAddress,
	btcPk *btcec.PublicKey,
	net *chaincfg.Params,
) error {
	if btcPk == nil || net == nil {
		return fmt.Errorf("cannot validate pop with nil parameters")
	}

	bPop, err := pop.ToBtcStakingPop()

	if err != nil {
		return err
	}

	btcPkBabylonFormat := bbn.NewBIP340PubKeyFromBTCPK(btcPk)
	return bPop.Verify(
		bbnAddr,
		btcPkBabylonFormat,
		net,
	)
}
