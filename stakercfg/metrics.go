package stakercfg

import (
	"fmt"
	"net"
)

const (
	defaultMetricsServerPort = 2112
	defaultMetricsHost       = "127.0.0.1"
)

// MetricsConfig defines the server's basic configuration
type MetricsConfig struct {
	// IP of the prometheus server
	Host string `long:"host" description:"host of prometheus server."`
	// Port of the prometheus server
	ServerPort int `long:"server-pornt" description:"port of prometheus server."`
}

func (cfg *MetricsConfig) Validate() error {
	if cfg.ServerPort < 0 || cfg.ServerPort > 65535 {
		return fmt.Errorf("invalid port: %d", cfg.ServerPort)
	}

	ip := net.ParseIP(cfg.Host)
	if ip == nil {
		return fmt.Errorf("invalid host: %v", cfg.Host)
	}

	return nil
}

func DefaultMetricsConfig() MetricsConfig {
	return MetricsConfig{
		ServerPort: defaultMetricsServerPort,
		Host:       defaultMetricsHost,
	}
}
