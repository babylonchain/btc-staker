package staker

import (
	"github.com/babylonchain/btc-staker/babylonclient"
	"github.com/babylonchain/btc-staker/stakerdb"
)

// BabylonPopToDbPop receives already validated pop from external sources and converts it to database representation
func BabylonPopToDbPop(pop *babylonclient.BabylonPop) *stakerdb.ProofOfPossession {
	return &stakerdb.ProofOfPossession{
		BtcSigType:           uint32(pop.BtcSigType),
		BabylonSigOverBtcPk:  pop.BabylonEcdsaSigOverBtcPk,
		BtcSigOverBabylonSig: pop.BtcSig,
	}
}
