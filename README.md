# BTC Staker

## 1. Overview

BTC-Staker is a toolset designed for seamless Bitcoin staking. It consists of two
components:

1. `stakerd` - The `stakerd` daemon manages connections to the Babylon and Bitcoin
   nodes.

2. `stakercli` - The `stakercli` is a command line interface (CLI) to facilitate
   interaction with the `stakerd` daemon . It enables users to stake funds, withdraw
   funds, unbond staked funds, retrieve the active finality providers set in Babylon,
   and more. It serves as an intuitive interface for effortless control and
   monitoring of your Bitcoin staking activities.

## 2. Installation

### Prerequisites

This project requires Go version 1.21 or later.

Install Go by following the instructions on
the [official Go installation guide](https://golang.org/doc/install).

Install essential tools and packages needed to compile and build the binaries.

```bash
sudo apt install build-essential
```

### Downloading the code

To get started, clone the repository to your local machine from Github:

```bash
$ git clone git@github.com:babylonchain/btc-staker.git
```

You can choose a specific version from
the [official releases page](https://github.com/babylonchain/btcstaker/releases)

```bash
$ cd btc-staker # cd into the project directory
$ git checkout <release-tag>
````

### Building and installing the binary

At the top-level directory of the project

```bash
$ make install 
```

The above command will build and install the following binaries to
`$GOPATH/bin`:

- `stakerd`: The daemon program for the btc-staker
- `stakercli`: The CLI tool for interacting with the stakerd.

If your shell cannot find the installed binaries, make sure `$GOPATH/bin` is in
the `$PATH` of your shell. Usually these commands will do the job

```bash
export PATH=$HOME/go/bin:$PATH
echo 'export PATH=$HOME/go/bin:$PATH' >> ~/.profile
```

To build without installing,

```bash
$ make build
```

The above command will put the built binaries in a build directory with the following
structure:

```bash
 $ ls build
     ├── stakerd
     └── stakercli
```

## 3. Setting up BTC Staker

### Prerequisites

#### 1. Create a Babylon keyring with funds

The `stakerd` daemon requires a keyring with loaded Babylon tokens to pay for the
transactions. Follow this
[guide](https://docs.babylonchain.io/docs/user-guides/btc-timestamping-testnet/getting-funds)
to create a keyring and request funds.

#### 2. Start Bitcoin node with wallet

The `stakerd` daemon requires a running Bitcoin node and a wallet loaded with signet
Bitcoins. You can configure the daemon to connect to either `bitcoind`
or `btcd` node types.

Follow the official guides to install and run the Bitcoin node, also make sure to run
the Bitcoin node on the same network as the one the Babylon node connects to.:

- ##### Bitcoin Core (bitcoind)
    - Official Bitcoin Core
      website: [Bitcoin core](https://bitcoin.org/en/bitcoin-core/)

    - For information on Signet, you can
      check [this](https://en.bitcoin.it/wiki/Signet) wiki page.

    - Currently we only support Bitcoin Core
      version [24.1](https://bitcoincore.org/en/releases/24.1/)

- ##### btcd

  GitHub repository for btcd: [btcd](https://github.com/btcsuite/btcd)

### Staker daemon (`stakerd`) configuration

`stakercli` tool serves as a control plane for the Staker Daemon.

Initialize the home directory for the Staker Daemon and dump the default
configuration file to the specified directory.

```bash
$ stakercli admin dump-config --config-file-dir /path/to/stakerd-home/
```

After initialization, the home directory will have the following structure

```bash
$ ls /path/to/stakerd-home/
    ├── stakerd.conf
```

If the `--config-file-dir` flag is not specified, then the default home directory
will be used. For different operating systems, those are:

- **MacOS** `~/Library/Application Support/Stakerd`
- **Linux** `~/.Stakerd`
- **Windows** `C:\Users\<username>\AppData\Local\Stakerd`

In the following, we go through important parameters of the `stakerd.conf` file.

#### Babylon configuration

**Notes:**

1. The `Key` parameter in the config below is the name of the key in the keyring to
   use for signing transactions. Use the key name you created
   in [Create a Babylon keyring with funds](#create-a-babylon-keyring-with-funds)
2. Ensure that the `KeyringDirectory` is set to the location where the keyring is
   stored.
3. Make sure to use the  `test` keyring backend.

```bash
[babylon]
# Name of the key in the keyring to use for signing transactions
Key = btc-staker

# Chain id of the chain (Babylon)
ChainID = chain-test

# Address of the chain's RPC server (Babylon)
RPCAddr = http://localhost:26657

# Address of the chain's GRPC server (Babylon)
GRPCAddr = https://localhost:9090

# Type of keyring backend to use 
KeyringBackend = test

# Adjustment factor when using gas estimation
GasAdjustment = 1.2

# Comma separated minimum gas prices to accept for transactions
GasPrices = 0.01ubbn

# Directory to store staker keys in
KeyDirectory = /Users/<user>/Library/Application Support/Stakerd
```

**Additional Notes:**

1. To change the babylon rpc/grpc address, you can set

   ```bash
   RPCAddr = https://rpc.devnet.babylonchain.io:443
   GRPCAddr = https://grpc.devnet.babylonchain.io:443
   ```

2. If you encounter any gas-related errors while performing staking operations,
   consider adjusting the `GasAdjustment` and `GasPrices` parameters. For example,
   you can set:

   ```bash
   GasAdjustment = 1.5
   GasPrices = 0.002ubbn
   ```

#### BTC Node configuration

**Notes:**

1. BTC configuration should reflect the BTC node that we're running and the network
   Babylon connects to.
2. You can use this [faucet](https://signet.bc-2.jp/) to receive signet BTC.

```bash
[chain]
# btc network to run on
Network = signet

[btcnodebackend]
# type of node to connect to {bitcoind, btcd}
Nodetype = bitcoind

# type of wallet to connect to {bitcoind, btcwallet}
WalletType = bitcoind

# fee mode to use for fee estimation {static, dynamic}. In dynamic mode fee will be estimated using backend node
FeeMode = static
```

#### BTC Wallet configuration

**Notes:**
Make sure you create a BTC wallet, name it appropriately, and load it with enough
signet BTC.

```bash
[walletconfig]
# name of the wallet to sign Bitcoin transactions
WalletName = btcstaker

# passphrase to unlock the wallet
WalletPass = walletpass

[walletrpcconfig]
# location of the wallet rpc server
# note: in case of bitcoind, the wallet host is same as the rpc host
Host = localhost:18556

# user auth for the wallet rpc server
# note: in case of bitcoind, the wallet rpc credentials are same as rpc credentials
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
# note: P2P port for signet is 38332
# for other networks, check the ref below'
# https://github.com/btcsuite/btcd/blob/17fdc5219b363c98df12e3ed7849a14f4820d93f/params.go#L23
RPCHost = 127.0.0.1:38332

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
# note: P2P port for signet is 38332/38333
# mainnet 8332/8334
# testnet 18332/18333
# regtest 18443
# ref - https://github.com/bitcoin/bitcoin/blob/03752444cd54df05a731557968d5a9f33a55c55c/src/chainparamsbase.cpp#L39
RPCHost = 127.0.0.1:38332

# Username for RPC connections
RPCUser = user

# Password for RPC connections
RPCPass = pass
```

To see the complete list of configuration options, check the `stakerd.conf` file.

## 4. Starting staker daemon

You can start the staker daemon using the following command:

```bash
$ stakerd
```

This will start the RPC server at the address specified in the configuration under
the `RawRPCListeners` field. A custom address can also be specified using
the `--rpclisten` flag.

```bash
$ stakerd --rpclisten 'localhost:8082'

time="2023-12-08T11:48:04+05:30" level=info msg="Starting StakerApp"
time="2023-12-08T11:48:04+05:30" level=info msg="Connecting to node backend: btcd"
```

All the available CLI options can be viewed using the `--help` flag. These options
can also be set in the configuration file.

## 5. Staking operations with stakercli

The following guide will show how to stake, withdraw, and unbond Bitcoin.

### Stake Bitcoin

#### 1. List active BTC finality providers on Babylon

Find the BTC public key of the finality provider you intend to stake to.

When staking, specify the BTC public key of a single finality provider using the
`--finality-providers-pks` flag in the `stake` command.

**Note** Make sure to use only one finality provider BTC public key in
the `--finality-providers-pks` flag of the
`stake`
command, as multiple providers are not currently supported.

```bash
$ stakercli daemon babylon-finality-providers
{
    "finality_providers": [
        {
            "babylon_public_Key": "0294092d0266c8d26544291b692e13f1e4fcba7829c5445ff99fcb3aefb23fe7cd",
            "bitcoin_public_Key": "3328782c63404386d9cd905dba5a35975cba629e48192cea4a348937e865d312"
        }
    ],
    "total_finality_providers_count": "1"
}
```

#### 2. Obtain the BTC address from the BTC wallet

Find the BTC address that has sufficient Bitcoin balance that you want to stake from.

**Note**: In case you don't have addresses with adequate balances, you can use the
faucet to receive signet BTC. Visit the faucet [link](https://signet.bc-2.jp/) to
acquire signet BTC.

```bash
$ stakercli daemon list-outputs
{
  "outputs": [
    {
      "amount": "10 BTC",
      "address": "bcrt1q56ehztys752uzg7fzpear08l5mw8w2kxgz7644"
    },
    {
      "amount": "10 BTC",
      "address": "bcrt1ql94x9v78ag7qx896f0axka809u55pla8cywsvn"
    }
  ]
}
```

#### 3. Stake Bitcoin

Stake Bitcoin to the finality provider of your choice. The `--staking-time` flag
specifies the timelock of the staking transaction in BTC blocks.
The `--staking-amount`
flag specifies the amount in satoshis to stake.

```bash
$ stakercli daemon stake \
  --staker-address bcrt1q56ehztys752uzg7fzpear08l5mw8w2kxgz7644 \
  --staking-amount 1000000 \
  --finality-providers-pks 3328782c63404386d9cd905dba5a35975cba629e48192cea4a348937e865d312 \
  --staking-time 100

# Transaction details
{
  "tx_hash": "6bf442a2e864172cba73f642ced10c178f6b19097abde41608035fb26a601b10"
}
```

**Note**: You can self delegate i.e. stake to your own finality provider. Follow
the [finality provider registration guide](https://github.com/babylonchain/finality-provider/blob/dev/docs/finality-provider.md#4-create-and-register-a-finality-provider)
to create and register a finality provider to Babylon. Once the finality provider is
registered, you can use your finality provider BTC public key in
the `--finality-providers-pks` flag of the `stake`
command.

### Unbond staked funds

The `unbond` cmd initiates the unbonding flow which involves communication with the
Babylon chain, Covenant emulators, and the BTC chain. It

1. Build the unbonding transaction and send it to the Babylon chain
2. Wait for the signatures from the covenant emulators
3. Send the unbonding transaction to the BTC chain

`--staking-transaction-hash` is the transaction hash from the response of `stake`
command.

```bash
$ stakercli daemon unbond \
  --staking-transaction-hash 6bf442a2e864172cba73f642ced10c178f6b19097abde41608035fb26a601b10
```

**Note**:

1. You can also use this cmd to get the list of all staking transactions in db.
   ```bash
   stakercli daemon list-staking-transactions
   ```
2. There is a minimum unbonding time currently set to 50 BTC blocks. After this
   period, the unbonding timelock will expire, and the staked funds will be unbonded.

### Withdraw staked funds

The staker can withdraw the staked funds after the timelock of the staking or
unbonding transaction expires.

`--staking-transaction-hash` is the transaction hash from the response of `stake`
command.

```bash
$ stakercli daemon unstake \
  --staking-transaction-hash 6bf442a2e864172cba73f642ced10c178f6b19097abde41608035fb26a601b10
```

**Note**:
You can also use this cmd to get the list of all withdrawable staking transactions in
db.

```bash
stakercli daemon withdrawable-transactions
```
