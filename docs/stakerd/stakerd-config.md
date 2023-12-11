## Prerequisites

#### 1. Create a Babylon keyring with funds

The `stakerd` daemon requires a keyring with loaded Babylon tokens to pay for the
transactions. Follow this
guide [Getting Testnet Tokens](https://docs.babylonchain.io/docs/user-guides/btc-timestamping-testnet/getting-funds)
to create a keyring and request funds.

#### 2. Start Bitcoin node with wallet

The `stakerd` daemon requires a running Bitcoin node with a wallet. You can configure
the daemon to connect to either `bitcoind` or `btcd` node types.

Follow the official guides to install and run the Bitcoin node:

- [bitcoind](https://bitcoin.org/en/bitcoin-core)
- [btcd](https://github.com/btcsuite/btcd)

## Staker daemon (`stakerd`) configuration

`stakercli` tool serves as a control plane for the Staker Daemon.

Initialize the home directory for the Staker Daemon and dump the default
configuration file to the specified directory.

```bash
$ stakercli admin dump-config --config-file-dir /path/to/stakerd-home/
```

After initialization, the home directory will have the following structure

```bash
$ ls /path/to/vald-home/
    ├── stakerd.conf
```

If the `--config-file-dir` flag is not specified, then the default home directory
will be used. For different operating systems, those are:

- **MacOS** `~/Library/Application Support/Stakerd`
- **Linux** `~/.Stakerd`
- **Windows** `C:\Users\<username>\AppData\Local\Stakerd`

Below are some important parameters of the `stakerd.conf` file.

#### Babylon configuration

**Note:**
The `Key` parameter in the config below is the name of the key in the keyring to use
for signing transactions. Use the key name you created
in [Create a Babylon keyring with funds](#create-a-babylon-keyring-with-funds)

```bash
[babylon]
# Name of the key in the keyring to use for signing transactions
Key = node0

# Chain id of the chain (Babylon)
ChainID = chain-test

# Address of the chain's RPC server (Babylon)
RPCAddr = http://localhost:26657

# Address of the chain's GRPC server (Babylon)
GRPCAddr = https://localhost:9090

# Type of keyring to use,
# supported backends - (os|file|kwallet|pass|test|memory)
# ref https://docs.cosmos.network/v0.46/run-node/keyring.html#available-backends-for-the-keyring
KeyringBackend = test

# Directory to store staker keys in
KeyDirectory = /Users/<user>/Library/Application Support/Stakerd
```

To change the babylon rpc/grpc address, you can set

```bash
RPCAddr = https://rpc.devnet.babylonchain.io:443
GRPCAddr = https://grpc.devnet.babylonchain.io:443
```

#### BTC Node configuration

```bash
[btcnodebackend]
# type of node to connect to {bitcoind, btcd}
Nodetype = btcd

# type of wallet to connect to {bitcoind, btcwallet}
WalletType = btcwallet

# fee mode to use for fee estimation {static, dynamic}. In dynamic mode fee will be estimated using backend node
FeeMode = static

[chain]
# btc network to run on
Network = simnet
```

#### BTC Wallet configuration

```bash
[walletconfig]
# name of the wallet to sign Bitcoin transactions
WalletName = wallet

# passphrase to unlock the wallet
WalletPass = walletpass

[walletrpcconfig]
# location of the wallet rpc server
Host = localhost:18556

# user auth for the wallet rpc server
User = rpcuser

# password auth for the wallet rpc server
Pass = rpcpass

# disables tls for the wallet rpc client
DisableTls = true
```

#### BTC Node type specific configuration

If you selected `btcd` as the node type, then you can configure the btcd node using
the following parameters.

```bash
[btcd]
# The daemon's rpc listening address. 
RPCHost = 127.0.0.1:18334

# Username for RPC connections
RPCUser = user

# Password for RPC connections
RPCPass = pass
```

If you selected `bitcoind` as the node type, then you can configure it using the
following parameters.

```bash
[bitcoind]
# The daemon's rpc listening address
RPCHost = 127.0.0.1:8334

# Username for RPC connections
RPCUser = user

# Password for RPC connections
RPCPass = pass
```

To see the complete list of configuration options, check the `stakerd.conf` file.
