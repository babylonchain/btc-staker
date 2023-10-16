package babylonclient

import (
	"fmt"

	bbn "github.com/babylonchain/babylon/types"
	btcstypes "github.com/babylonchain/babylon/x/btcstaking/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
)

type BtcSigType int

// TODO: Add support for ecdsa sig type
const (
	SchnorrType BtcSigType = iota
	Bip322Type
)

type BabylonPop struct {
	BtcSigType               BtcSigType
	BabylonEcdsaSigOverBtcPk []byte
	BtcSig                   []byte
}

func NewBabylonPop(t BtcSigType, babylonSig []byte, btcSig []byte) (*BabylonPop, error) {
	if len(babylonSig) == 0 || len(btcSig) == 0 {
		return nil, fmt.Errorf("cannot create BabylonPop with empty signatures")
	}

	return &BabylonPop{
		BtcSigType:               t,
		BabylonEcdsaSigOverBtcPk: babylonSig,
		BtcSig:                   btcSig,
	}, nil
}

func BabylonPopTypeToSigType(t BtcSigType) (btcstypes.BTCSigType, error) {
	switch t {
	case SchnorrType:
		return btcstypes.BTCSigType_BIP340, nil
	case Bip322Type:
		return btcstypes.BTCSigType_BIP322, nil
	default:
		return btcstypes.BTCSigType_BIP340, fmt.Errorf("Unknown pop type")
	}
}

func IntToPopType(t int) (BtcSigType, error) {
	switch t {
	case 0:
		return SchnorrType, nil
	case 1:
		return Bip322Type, nil
	default:
		return SchnorrType, fmt.Errorf("uknown pop type")
	}
}

func IntToSigType(t int) (btcstypes.BTCSigType, error) {
	popType, err := IntToPopType(t)

	if err != nil {
		return btcstypes.BTCSigType_BIP340, err
	}

	return BabylonPopTypeToSigType(popType)
}

func (pop *BabylonPop) ToBtcStakingPop() (*btcstypes.ProofOfPossession, error) {
	var popType btcstypes.BTCSigType
	switch pop.BtcSigType {
	case SchnorrType:
		popType = btcstypes.BTCSigType_BIP340
	case Bip322Type:
		popType = btcstypes.BTCSigType_BIP322
	default:
		return nil, fmt.Errorf("unknown pop type")
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

	switch bPop.BtcSigType {
	case btcstypes.BTCSigType_BIP322:
		if err := bPop.VerifyBIP322(babylonPk, btcPkBabylonFormat, net); err != nil {
			return err
		}
	case btcstypes.BTCSigType_BIP340:
		if err := bPop.Verify(babylonPk, btcPkBabylonFormat, net); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown pop type")
	}

	return nil
}
