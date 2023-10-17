package babylonclient

import (
	"fmt"

	bbn "github.com/babylonchain/babylon/types"
	btcstypes "github.com/babylonchain/babylon/x/btcstaking/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
)

type BabylonBtcPopType int

const (
	SchnorrType BabylonBtcPopType = iota
	Bip322Type
	EcdsaType
)

type BabylonPop struct {
	popType                  BabylonBtcPopType
	BabylonEcdsaSigOverBtcPk []byte
	BtcSig                   []byte
}

func NewBabylonPop(t BabylonBtcPopType, babylonSig []byte, btcSig []byte) (*BabylonPop, error) {
	if len(babylonSig) == 0 || len(btcSig) == 0 {
		return nil, fmt.Errorf("cannot create BabylonPop with empty signatures")
	}

	return &BabylonPop{
		popType:                  t,
		BabylonEcdsaSigOverBtcPk: babylonSig,
		BtcSig:                   btcSig,
	}, nil
}

func BabylonPopTypeToSigType(t BabylonBtcPopType) (btcstypes.BTCSigType, error) {
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

func (pop *BabylonPop) ToBtcStakingPop() (*btcstypes.ProofOfPossession, error) {
	popType, err := BabylonPopTypeToSigType(pop.popType)

	if err != nil {
		return nil, err
	}

	return &btcstypes.ProofOfPossession{
		BtcSigType: popType,
		BabylonSig: pop.BabylonEcdsaSigOverBtcPk,
		BtcSig:     pop.BtcSig,
	}, nil
}

func (pop *BabylonPop) ValidatePop(
	babylonPk *secp256k1.PubKey,
	btcPk *btcec.PublicKey,
	net *chaincfg.Params,
) error {
	if babylonPk == nil || btcPk == nil || net == nil {
		return fmt.Errorf("cannot validate pop with nil parameters")
	}

	bPop, err := pop.ToBtcStakingPop()

	if err != nil {
		return err
	}

	btcPkBabylonFormat := bbn.NewBIP340PubKeyFromBTCPK(btcPk)

	return bPop.Verify(
		babylonPk,
		btcPkBabylonFormat,
		net,
	)
}
