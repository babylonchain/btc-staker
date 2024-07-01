package stakerservice

type ResultHealth struct{}

type ResultStake struct {
	TxHash string `json:"tx_hash"`
}

type StakingDetails struct {
	StakingTxHash  string `json:"staking_tx_hash"`
	StakerAddress  string `json:"staker_address"`
	StakingState   string `json:"staking_state"`
	Watched        bool   `json:"watched"`
	TransactionIdx string `json:"transaction_idx"`
}

type OutputDetail struct {
	Amount  string `json:"amount"`
	Address string `json:"address"`
}

type OutputsResponse struct {
	Outputs []OutputDetail `json:"outputs"`
}
type SpendTxDetails struct {
	TxHash  string `json:"tx_hash"`
	TxValue string `json:"tx_value"`
}

type FinalityProviderInfoResponse struct {
	// bech 32 encoded Babylon address
	BabylonAddress string `json:"babylon_address"`
	// Hex encoded Bitcoin public secp256k1 key in BIP340 format
	BtcPublicKey string `json:"bitcoin_public_Key"`
}

type FinalityProvidersResponse struct {
	FinalityProviders           []FinalityProviderInfoResponse `json:"finality_providers"`
	TotalFinalityProvidersCount string                         `json:"total_finality_providers_count"`
}

type ListStakingTransactionsResponse struct {
	Transactions          []StakingDetails `json:"transactions"`
	TotalTransactionCount string           `json:"total_transaction_count"`
}

type UnbondingResponse struct {
	UnbondingTxHash string `json:"unbonding_tx_hash"`
}

type WithdrawableTransactionsResponse struct {
	Transactions                     []StakingDetails `json:"transactions"`
	LastWithdrawableTransactionIndex string           `json:"last_transaction_index"`
	TotalTransactionCount            string           `json:"total_transaction_count"`
}
