package types

type FeeEstimationMode int

const (
	StaticFeeEstimation FeeEstimationMode = iota
	DynamicFeeEstimation
)
