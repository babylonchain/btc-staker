package transaction

import (
	"fmt"

	"github.com/babylonchain/btc-staker/utils"
	"github.com/btcsuite/btcd/btcutil"
)

// InputBtcStakingTx json input structure to create a staking tx from json
type InputBtcStakingTx struct {
	// BtcNetwork type of btc network to use
	// Needs to be one of "testnet3", "mainnet", "regtest", "simnet", "signet".
	BtcNetwork string `json:"btc_network"`
	// StakerPublicKeyHex SchnorPubKey hex encoded.
	StakerPublicKeyHex string `json:"staker_public_key_hex"`
	// CovenantMembersPkHex covenant members SchnorPubKey hex encoded.
	CovenantMembersPkHex []string `json:"covenant_members_pk_hex"`
	// FinalityProviderPublicKeyHex SchnorPubKey hex encoded.
	FinalityProviderPublicKeyHex string `json:"finality_provider_public_key_hex"`
	// StakingAmount the amount to be staked in satoshi.
	// A single StakingAmount is equal to 1e-8 of a bitcoin.
	StakingAmount int64 `json:"staking_amount"`
	// StakingTimeBlocks number of blocks to keep the staking amount locked.
	StakingTimeBlocks uint16 `json:"staking_time_blocks"`
	// MagicBytesHex magic bytes hex encoded.
	MagicBytesHex string `json:"magic_bytes"`
	// CovenantQuorum the number of covenant required as quorum.
	CovenantQuorum uint32 `json:"covenant_quorum"`
}

// ToCreatePhase1StakingTxResponse from the data input parses and builds parameters to create and serialize response tx structure.
func (tx InputBtcStakingTx) ToCreatePhase1StakingTxResponse() (*CreatePhase1StakingTxResponse, error) {
	magicBytes, err := parseMagicBytesFromHex(tx.MagicBytesHex)
	if err != nil {
		return nil, fmt.Errorf("error parsing magic bytes %s: %w", tx.MagicBytesHex, err)
	}

	stakerPk, err := parseSchnorPubKeyFromHex(tx.StakerPublicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("error parsing staker pub key %s: %w", tx.StakerPublicKeyHex, err)
	}

	fpPk, err := parseSchnorPubKeyFromHex(tx.FinalityProviderPublicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("error parsing finality provider pub key %s: %w", tx.FinalityProviderPublicKeyHex, err)
	}

	covenantMembersPks, err := parseCovenantKeysFromSlice(tx.CovenantMembersPkHex)
	if err != nil {
		return nil, fmt.Errorf("error parsing covenant members pub key %s: %w", tx.CovenantMembersPkHex, err)
	}

	btcNetworkParams, err := utils.GetBtcNetworkParams(tx.BtcNetwork)
	if err != nil {
		return nil, fmt.Errorf("error parsing btc network %s: %w", tx.BtcNetwork, err)
	}

	return MakeCreatePhase1StakingTxResponse(
		magicBytes,
		stakerPk,
		fpPk,
		covenantMembersPks,
		tx.CovenantQuorum,
		tx.StakingTimeBlocks,
		btcutil.Amount(tx.StakingAmount),
		btcNetworkParams,
	)
}
