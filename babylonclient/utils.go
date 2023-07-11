package babylonclient

import (
	babylontypes "github.com/babylonchain/babylon/types"
	btcctypes "github.com/babylonchain/babylon/x/btccheckpoint/types"
	"github.com/babylonchain/btc-staker/utils"
	"github.com/btcsuite/btcd/wire"
)

func GenerateProof(block *wire.MsgBlock, txIdx uint32) ([]byte, error) {

	headerBytes := babylontypes.NewBTCHeaderBytesFromBlockHeader(&block.Header)

	var txsBytes [][]byte
	for _, tx := range block.Transactions {
		bytes, err := utils.SerializeBtcTransaction(tx)

		if err != nil {
			return nil, err
		}

		txsBytes = append(txsBytes, bytes)
	}

	proof, err := btcctypes.SpvProofFromHeaderAndTransactions(&headerBytes, txsBytes, uint(txIdx))

	if err != nil {
		return nil, err
	}

	return proof.MerkleNodes, nil
}
