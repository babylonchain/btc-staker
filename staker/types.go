package staker

import (
	cl "github.com/babylonchain/btc-staker/babylonclient"
	"github.com/babylonchain/btc-staker/stakerdb"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/wire"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
)

// babylonPopToDbPop receives already validated pop from external sources and converts it to database representation
func babylonPopToDbPop(pop *cl.BabylonPop) *stakerdb.ProofOfPossession {
	return &stakerdb.ProofOfPossession{
		BtcSigType:           uint32(pop.BtcSigType),
		BabylonSigOverBtcPk:  pop.BabylonEcdsaSigOverBtcPk,
		BtcSigOverBabylonSig: pop.BtcSig,
	}
}

func createDelegationData(
	inclusionBlock *wire.MsgBlock,
	stakingTxIdx uint32,
	storedTx *stakerdb.StoredTransaction,
	slashingTx *wire.MsgTx,
	slashingTxSignature *schnorr.Signature,
	babylonPubKey *secp256k1.PubKey,
	stakingTxInclusionProof []byte,
) *cl.DelegationData {
	inclusionBlockHash := inclusionBlock.BlockHash()

	dg := cl.DelegationData{
		StakingTransaction:                   storedTx.StakingTx,
		StakingTransactionIdx:                stakingTxIdx,
		StakingTransactionScript:             storedTx.TxScript,
		StakingTransactionInclusionProof:     stakingTxInclusionProof,
		StakingTransactionInclusionBlockHash: &inclusionBlockHash,
		SlashingTransaction:                  slashingTx,
		SlashingTransactionSig:               slashingTxSignature,
		BabylonPk:                            babylonPubKey,
		BabylonPop:                           storedTx.Pop,
	}

	return &dg
}
