package stakerservice

type ResultHealth struct{}

type ResultStake struct {
	TxHash string `json:"txHash"`
}

type StakingDetails struct {
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
