package staker

type GenerateScriptResponse struct {
	Script  string `json:"script"`
	Address string `json:"address"`
}

type CreateStakingTransactionResponse struct {
	TransactionHex string `json:"transactionHex"`
}

type SendTransactionResponse struct {
	TransactionHashHex string `json:"transactionHashHex"`
	TransactionHex     string `json:"transactionHex"`
}
