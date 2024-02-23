package metrics

import (
	"errors"
	"net/http"
	_ "net/http/pprof"
	"regexp"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

func Start(logger *logrus.Logger, addr string, reg *prometheus.Registry) {
	go start(logger, addr, reg)
}

func start(logger *logrus.Logger, addr string, reg *prometheus.Registry) {
	// Add Go module build info.
	reg.MustRegister(collectors.NewBuildInfoCollector())
	reg.MustRegister(collectors.NewGoCollector(
		collectors.WithGoCollectorRuntimeMetrics(collectors.GoRuntimeMetricsRule{Matcher: regexp.MustCompile("/.*")})),
	)

	// Expose the registered metrics via HTTP.
	http.Handle("/metrics", promhttp.HandlerFor(
		reg,
		promhttp.HandlerOpts{
			// Opt into OpenMetrics to support exemplars.
			EnableOpenMetrics: true,
		},
	))

	logger.Infof("Successfully started Prometheus metrics server at %s", addr)

	err := http.ListenAndServe(addr, nil)

	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Errorf("prometheus server got err: %v", err)
	}
}
