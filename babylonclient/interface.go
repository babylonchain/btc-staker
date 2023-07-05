package babylonclient

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
)

type StakingParams struct {
	// K-deep
	ComfirmationTimeBlocks uint32
	// W-deep
	MinmumStakingTimeBlocks uint32

	// Minimum amount of satoshis required for slashing transaction
	MinSlashingTxFeeSat btcutil.Amount

	// Bitcoin public key of the current jury
	JuryPk btcec.PublicKey
}

type BabylonClient interface {
	Params() (*StakingParams, error)
}

type MockBabylonClient struct {
	CurrentParams *StakingParams
}

var _ BabylonClient = (*MockBabylonClient)(nil)

func (m *MockBabylonClient) Params() (*StakingParams, error) {
	return m.CurrentParams, nil
}

func GetMockClient() *MockBabylonClient {
	juryPk, err := btcec.NewPrivateKey()

	if err != nil {
		panic(err)
	}

	return &MockBabylonClient{
		CurrentParams: &StakingParams{
			ComfirmationTimeBlocks:  6,
			MinmumStakingTimeBlocks: 100,
			MinSlashingTxFeeSat:     btcutil.Amount(10000),
			JuryPk:                  *juryPk.PubKey(),
		},
	}
}
