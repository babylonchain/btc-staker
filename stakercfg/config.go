package stakercfg

type ChainConfig struct {
	Network string
}

func DefaultChainConfig() ChainConfig {
	return ChainConfig{
		Network: "testnet3",
	}
}

type WalletConfig struct {
	WalletName string
	WalletPass string
}

func DefaultWalletConfig() WalletConfig {
	return WalletConfig{
		WalletName: "wallet",
		WalletPass: "walletpass",
	}
}

type WalletRpcConfig struct {
	Host       string
	User       string
	Pass       string
	DisableTls bool
}

func DefaultWalletRpcConfig() WalletRpcConfig {
	return WalletRpcConfig{
		DisableTls: true,
		Host:       "localhost:18556",
		User:       "rpcuser",
		Pass:       "rpcpass",
	}
}

type StakerConfig struct {
	WalletConfig    *WalletConfig
	WalletRpcConfig *WalletRpcConfig
	ChainConfig     *ChainConfig
}

func DefaultStakerConfig() StakerConfig {
	rpcConf := DefaultWalletRpcConfig()
	walletConf := DefaultWalletConfig()
	chainCfg := DefaultChainConfig()
	return StakerConfig{
		WalletConfig:    &walletConf,
		WalletRpcConfig: &rpcConf,
		ChainConfig:     &chainCfg,
	}
}
