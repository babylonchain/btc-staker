package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type StakerMetrics struct {
	Registry                        *prometheus.Registry
	ValidReceivedDelegationRequests prometheus.Counter
	DelegationsConfirmedOnBtc       prometheus.Counter
	DelegationsSentToBabylon        prometheus.Counter
	DelegationsActivatedOnBabylon   prometheus.Counter
	NumberOfFatalErrors             prometheus.Counter
	CurrentBtcBlockHeight           prometheus.Gauge
}

func NewStakerMetrics() *StakerMetrics {
	registry := prometheus.NewRegistry()
	registerer := promauto.With(registry)

	metrics := &StakerMetrics{
		Registry: registry,
		ValidReceivedDelegationRequests: registerer.NewCounter(prometheus.CounterOpts{
			Name: "staker_valid_received_delegation_requests",
			Help: "Total number of received valid delegation requests",
		}),
		DelegationsConfirmedOnBtc: registerer.NewCounter(prometheus.CounterOpts{
			Name: "staker_delegations_confirmed_on_btc",
			Help: "Total number of delegations confirmed on btc",
		}),
		DelegationsSentToBabylon: registerer.NewCounter(prometheus.CounterOpts{
			Name: "staker_delegations_send_to_babylon",
			Help: "Total number of delegations sent to babylon",
		}),
		DelegationsActivatedOnBabylon: registerer.NewCounter(prometheus.CounterOpts{
			Name: "staker_delegations_activated_on_babylon",
			Help: "Total number of delegations activated on babylon",
		}),
		NumberOfFatalErrors: registerer.NewCounter(prometheus.CounterOpts{
			Name: "staker_number_of_fatal_errors",
			Help: "Total number of fatal errors received",
		}),
		CurrentBtcBlockHeight: registerer.NewGauge(prometheus.GaugeOpts{
			Name: "staker_current_btc_block_height",
			Help: "Current block height of the btc chain",
		}),
	}
	return metrics
}
