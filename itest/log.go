package e2etest

import (
	"github.com/babylonchain/btc-staker/stakercfg"
)

var (
	zapLogger, _ = stakercfg.NewRootLogger("auto", "debug")
)
