package stakerservice

type ResultHealth struct{}

type ResultStake struct {
	TxHash string `json:"txHash"`
}

type StakingDetails struct {
	StakingTxHash string `json:"stakingTxHash"`
	StakerAddress string `json:"stakerAddress"`
	StakingScript string `json:"stakingScript"`
	StakingState  string `json:"stakingState"`
}

type OutputDetail struct {
	Amount  string `json:"amount"`
	Address string `json:"address"`
}

type OutputsResponse struct {
	Outputs []OutputDetail `json:"outputs"`
}
type SpendTxDetails struct {
	TxHash string `json:"txHash"`
}

type ValidatorInfoResponse struct {
	// Hex encoded Babylon public secp256k1 key in compressed format
	BabylonPublicKey string `json:"babylonPublicKey"`
	// Hex encoded Bitcoin public secp256k1 key in BIP340 format
	BtcPublicKey string `json:"btcPublicKey"`
}

type ValidatorsResponse struct {
	Validators          []ValidatorInfoResponse `json:"validators"`
	TotalValidatorCount string                  `json:"totalValidatorCount"`
}

type ListStakingTransactionsResponse struct {
	Transactions          []StakingDetails `json:"transactions"`
	TotalTransactionCount string           `json:"totalTransactionCount"`
}
