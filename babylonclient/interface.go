package babylonclient

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
)

type StakingParams struct {
	// K-deep
	ComfirmationTimeBlocks uint32
	// W-deep
	FinalizationTimeoutBlocks uint32

	// Minimum amount of satoshis required for slashing transaction
	MinSlashingTxFeeSat btcutil.Amount

	// Bitcoin public key of the current jury
	JuryPk btcec.PublicKey
}

type BabylonClient interface {
	Params() (*StakingParams, error)
}

type MockBabylonClient struct {
	ClientParams *StakingParams
}

var _ BabylonClient = (*MockBabylonClient)(nil)

func (m *MockBabylonClient) Params() (*StakingParams, error) {
	return m.ClientParams, nil
}

func GetMockClient() *MockBabylonClient {
	juryPk, err := btcec.NewPrivateKey()

	if err != nil {
		panic(err)
	}

	return &MockBabylonClient{
		ClientParams: &StakingParams{
			ComfirmationTimeBlocks:    2,
			FinalizationTimeoutBlocks: 5,
			MinSlashingTxFeeSat:       btcutil.Amount(1000),
			JuryPk:                    *juryPk.PubKey(),
		},
	}
}
