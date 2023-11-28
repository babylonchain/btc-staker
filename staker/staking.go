package staker

import (
	"encoding/hex"
	"fmt"
	"math"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

func EncodeSchnorrPkToHexString(pk *btcec.PublicKey) string {
	return hex.EncodeToString(schnorr.SerializePubKey(pk))
}

func ParseSchnorrPk(key string) (*btcec.PublicKey, error) {
	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		return nil, err
	}

	pk, err := schnorr.ParsePubKey(keyBytes)

	if err != nil {
		return nil, err
	}

	return pk, nil
}

func ParseStakingTime(stakingTime uint64) (uint16, error) {
	if stakingTime > math.MaxUint16 {
		return 0, fmt.Errorf("staking time %d is too big", stakingTime)
	}

	return uint16(stakingTime), nil
}
