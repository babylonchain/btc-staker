package staker

import (
	"encoding/hex"
	"fmt"
	"math"

	staking "github.com/babylonchain/babylon/btcstaking"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg"
)

func EncodeSchnorrPk(pk *btcec.PublicKey) string {
	return hex.EncodeToString(schnorr.SerializePubKey(pk))
}

func ParseSchnorPk(key string) (*btcec.PublicKey, error) {
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

func ParseStakingScriptData(
	stakerPk string,
	delegatorPk string,
	juryPk string,
	stakingTime uint64) (*staking.StakingScriptData, error) {

	stakerKey, err := ParseSchnorPk(stakerPk)
	if err != nil {
		return nil, err
	}

	delegatorKey, err := ParseSchnorPk(delegatorPk)

	if err != nil {
		return nil, err
	}

	juryKey, err := ParseSchnorPk(juryPk)

	if err != nil {
		return nil, err
	}

	stakingTimeParsed, err := ParseStakingTime(stakingTime)

	if err != nil {
		return nil, err
	}

	return staking.NewStakingScriptData(
		stakerKey,
		delegatorKey,
		juryKey,
		stakingTimeParsed,
	)
}

// GenerateStakingScriptAndAddress generates staking script and address for the given staker, delegator, jury and staking time
func GenerateStakingScriptAndAddress(
	stakerPk string,
	delegatorPk string,
	juryPk string,
	stakingTime uint64,
	net *chaincfg.Params) (*GenerateScriptResponse, error) {

	scriptData, err := ParseStakingScriptData(
		stakerPk,
		delegatorPk,
		juryPk,
		stakingTime,
	)

	if err != nil {
		return nil, err
	}

	script, err := scriptData.BuildStakingScript()

	if err != nil {
		return nil, err
	}

	address, err := staking.TaprootAddressForScript(
		script,
		staking.UnspendableKeyPathInternalPubKey(),
		net,
	)

	if err != nil {
		return nil, err
	}

	return &GenerateScriptResponse{
		Script:  hex.EncodeToString(script),
		Address: address.EncodeAddress(),
	}, nil
}
