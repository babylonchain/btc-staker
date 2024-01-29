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
git clone https://github.com/babylonchain/btc-staker.git
```

You can choose a specific version from
the [official releases page](https://github.com/babylonchain/btcstaker/releases)

```bash
cd btc-staker # cd into the project directory
git checkout <release-tag>
````

### Building and installing the binary

At the top-level directory of the project

```bash
make install
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
make build
```

The above command will put the built binaries in a build directory with the following
structure:

```bash
 ls build
     ├── stakerd
     └── stakercli
```

## 3. Setting up BTC Staker

### Prerequisites

#### 1. Create a Babylon keyring (keyring backend: test) with funds

The `stakerd` daemon requires a keyring with loaded Babylon tokens to pay for the
transactions. Follow this
[guide](https://docs.babylonchain.io/docs/user-guides/btc-staking-testnet/getting-funds)
to create a keyring and request funds.

#### 2. Start Bitcoin node with wallet

The `stakerd` daemon requires a running Bitcoin node and a **legacy** wallet loaded
with signet Bitcoins.

You can configure `stakerd` daemon to connect to either
`bitcoind` or `btcd` node types. While both are compatible, we recommend
using `bitcoind`. Ensure that you are using legacy wallets, as `stakerd` daemon
doesn't currently support descriptor wallets.

Below, we'll guide you through setting up a signet `bitcoind` node and a legacy
wallet:

#### 2.1. Download and Extract Bitcoin Binary:

```bash
# Download Bitcoin Core binary
wget https://bitcoincore.org/bin/bitcoin-core-26.0/bitcoin-26.0-x86_64-linux-gnu.tar.gz

# Extract the downloaded archive
tar -xvf bitcoin-26.0-x86_64-linux-gnu.tar.gz

# Provide execution permissions to binaries
chmod +x bitcoin-26.0/bin/bitcoind
chmod +x bitcoin-26.0/bin/bitcoin-cli
```

#### 2.2. Create and start a Systemd Service:

Please update the following configurations in the provided file:

1. Replace `<rpcuser>` and `<rpcpass>` with your own values. These credentials will
   also be utilized in the btc-staker configuration file later on.
2. Ensure that the `<user>` is set to the machine user. In the guide below, it's set
   to ubuntu.
3. Note that `deprecatedrpc=create_bdb` is necessary to enable the creation of a
   legacy wallet, which has been deprecated in the latest core version. For more
   information, refer to the Bitcoin Core 26.0 release
   page [here](https://bitcoincore.org/en/releases/26.0/)
   and this [link](https://github.com/bitcoin/bitcoin/pull/28597).
4. If you want to enable remote connections to the node, you can add
   `rpcallowip=0.0.0.0/0` and `rpcbind=0.0.0.0` to the bitcoind command.

```bash 
# Create the service file
sudo tee /etc/systemd/system/bitcoind.service >/dev/null <<EOF
[Unit]
Description=bitcoin signet node
After=network.target

[Service]
User=<user>
Type=simple
ExecStart=/home/ubuntu/bitcoin-26.0/bin/bitcoind \
    -deprecatedrpc=create_bdb \
    -signet \
    -server \
    -rpcport=38332 \
    -rpcuser=<your_rpc_username> \
    -rpcpassword=<your_rpc_password>
Restart=on-failure
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
```

```bash
# Start the service
sudo systemctl daemon-reload
sudo systemctl enable bitcoind
sudo systemctl start bitcoind
```

```bash
# Check the status and logs of the service
systemctl status bitcoind
journalctl -u bitcoind -f
```

#### 2.3. Create legacy wallet and generate address:

#### 2.3.1. Create a legacy wallet:

```bash
~/bitcoin-26.0/bin/bitcoin-cli -signet \
    -rpcuser=<your_rpc_username> \
    -rpcpassword=<your_rpc_password> \
    -rpcport=38332 \
    -named createwallet \
    wallet_name=btcstaker \
    passphrase="<passphrase>" \
    load_on_startup=true \
    descriptors=false
```

- Ensure use the same rpc `rpcuser`, `rpcpassword`, `rpcport` that you used while
  setting up the bitcoind systemd service.
- `-named createwallet` indicates that a new wallet should be created with the
  provided name.
- `wallet_name=btcstaker` specifies the name of the new wallet and `<passphrase>` is
  your wallet pass phrase, replace with your own passphrase. Ensure you use the
  wallet and passphrase configured here in [walletconfig](#btc-wallet-configuration)
  section of the `stakerd.conf` file.
- Setting `load_on_startup=true` ensures that the wallet automatically loads during
  system startup.
- `descriptors=false` disables descriptors, which are not supported by BTC Staker at
  present.

#### 2.3.2. Load the wallet:

```bash
~/bitcoin-26.0/bin/bitcoin-cli -signet \
    -rpcuser=<your_rpc_username> \
    -rpcpassword=<your_rpc_password> \
    -rpcport=38332 \
    loadwallet "btcstaker"
```

- Ensure use the same rpc `rpcuser`, `rpcpassword`, `rpcport` that you used while
  setting up the bitcoind systemd service.
- `loadwallet "btcstaker"` loads the wallet with the name `btcstaker`.

#### 2.3.3 Generate a new address for the wallet

```bash
~/bitcoin-26.0/bin/bitcoin-cli -signet \
    -rpcuser=<your_rpc_username> \
    -rpcpassword=<your_rpc_password> \
    -rpcport=38332 \
    getnewaddress
```

- Ensure use the same rpc `rpcuser`, `rpcpassword`, `rpcport` that you used while
  setting up the bitcoind systemd service.
- `getnewaddress` generates a new btc address for the wallet, this will be used to
  request funds from the faucet.

#### 2.4. Request signet BTC from faucet:

Use the faucet [link](https://signet.bc-2.jp/) to request signet BTC to the address
generated in the previous step. You can use the following command to check the
balance. Ensure use the same rpc `rpcuser`, `rpcpassword`, `rpcport` that you used
while setting up the bitcoind systemd service.

```bash
# Replace $TXID with the transaction id you received from the faucet
~/bitcoin-26.0/bin/bitcoin-cli -signet \
    -rpcuser=<your_rpc_username> \
    -rpcpassword=<your_rpc_password> \
    -rpcport=38332 \
    gettransaction $TXID

# Once the transaction is confirmed, you can check the balance
~/bitcoin-26.0/bin/bitcoin-cli -signet \
    -rpcuser=<your_rpc_username> \
    -rpcpassword=<your_rpc_password> \
    -rpcport=38332 \
    getbalance
```

**Notes**:

1. Ensure to run the Bitcoin node on the same network as the one the Babylon node
   connects to. For Babylon testnet, we are using BTC Signet.
2. If you prefer not to run your own Bitcoin node, you can find an RPC to connect to.
3. Expected sync times for the BTC node are as follows: Signet takes less than 1
   hour, testnet takes a few hours, and mainnet could take a few days.
4. Ensure that you use a legacy (non-descriptor) wallet, as BTC Staker doesn't
   currently support descriptor wallets.
5. You can also use `bitcoin.conf` instead of using flags in the `bitcoind` cmd.
   Please check the Bitcoin signet [wiki](https://en.bitcoin.it/wiki/Signet) and this
   manual [here](https://manpages.org/bitcoinconf/5) to learn how to
   set `bitcoin.conf`. Ensure you have configured the `bitcoind.conf` correctly and
   set all the required parameters as shown in the systemd service file above.

### Staker daemon (`stakerd`) configuration

`stakercli` tool serves as a control plane for the Staker Daemon.

Initialize the home directory for the Staker Daemon and dump the default
configuration file to the specified directory.

```bash
stakercli admin dump-config --config-file-dir /path/to/stakerd-home/
```

After initialization, the home directory will have the following structure

```bash
ls /path/to/stakerd-home/
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
   in [Create a Babylon keyring with funds](#1-create-a-babylon-keyring-keyring-backend-test-with-funds).
2. Ensure that the `KeyringDirectory` is set to the location where the keyring is
   stored.
3. Ensure to use the `test` keyring backend
4. Ensure you use the correct `ChainID` for the network you're connecting to. For
   example, for Babylon devnet, the chain ID is `bbn-dev-5`.
5. To change the Babylon RPC/GRPC address, update the following:

    ```bash
    RPCAddr = https://rpc.devnet.babylonchain.io:443 # rpc node address
    GRPCAddr = https://grpc.devnet.babylonchain.io:443 # grpc node address
    ```
   The above addresses are for Babylon devnet.
6. If you encounter any gas-related errors while performing staking operations,
   consider adjusting the `GasAdjustment` and `GasPrices` parameters. For example,
   you can set:

   ```bash
   GasAdjustment = 1.5
   GasPrices = 0.002ubbn
   ```

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

**Note:**
Make sure you create a BTC wallet, name it appropriately, and load it with enough
signet BTC.

```bash
[walletconfig]
# name of the wallet to sign Bitcoin transactions. This should be the same as set in createwallet command in bitcoind.
WalletName = btcstaker

# passphrase to unlock the wallet
WalletPass = walletpass

[walletrpcconfig]
# location of the wallet rpc server
# note: in case of bitcoind, the wallet host is same as the rpc host
Host = localhost:38332

# user auth for the wallet rpc server
# note: in case of bitcoind, the wallet rpc credentials are same as rpc credentials
# this should be the same as set in the bitcoind daemon
User = your_rpc_username

# password auth for the wallet rpc server. This should be the same as set in the bitcoind daemon
Pass = your_rpc_password

# disables tls for the wallet rpc client
DisableTls = true
```

#### BTC Node type specific configuration

Make sure to replace the following important parameters related to `bitcoind` as per
your setup.

```bash
[bitcoind]
# The daemon's rpc listening address
# note: P2P port for signet is 38332/38333
# mainnet 8332/8333
# testnet 18332/18333
# regtest 18443
# ref - https://github.com/bitcoin/bitcoin/blob/03752444cd54df05a731557968d5a9f33a55c55c/src/chainparamsbase.cpp#L39
RPCHost = 127.0.0.1:38332

# Username for RPC connections. This should be the same as set in the bitcoind daemon
RPCUser = your_rpc_username

# Password for RPC connections. This should be the same as set in the bitcoind daemon
RPCPass = your_rpc_password

# The address listening for ZMQ connections to deliver raw block notifications
ZMQPubRawBlock = tcp://127.0.0.1:29001

# The address listening for ZMQ connections to deliver raw transaction notifications
ZMQPubRawTx = tcp://127.0.0.1:29002
```

To see the complete list of configuration options, check the `stakerd.conf` file.

## 4. Starting staker daemon

You can start the staker daemon using the following command:

```bash
stakerd
```

This will start the RPC server at the address specified in the configuration under
the `RawRPCListeners` field. A custom address can also be specified using
the `--rpclisten` flag.

```bash
stakerd --rpclisten 'localhost:15812'

time="2023-12-08T11:48:04+05:30" level=info msg="Starting StakerApp"
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
stakercli daemon babylon-finality-providers
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
stakercli daemon list-outputs
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
stakercli daemon stake \
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

`--staking-transaction-hash` is the transaction hash from the response of the `stake`
command.

```bash
stakercli daemon unbond \
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
stakercli daemon unstake \
  --staking-transaction-hash 6bf442a2e864172cba73f642ced10c178f6b19097abde41608035fb26a601b10
```

**Note**:
You can also use this cmd to get the list of all withdrawable staking transactions in
db.

```bash
stakercli daemon withdrawable-transactions
```
