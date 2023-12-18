## Prerequisites

1. **Install Binaries:**
   Follow the instructions in
   the [installation section](../../README.md#2-installation) to install the required
   binaries.

2. **Start Bitcoin and Babylon Node:**
   The Staker daemon requires connection to both a running Bitcoin node and a Babylon
   node with a wallet to facilitate transactions.

    - Ensure a Bitcoin node is running, and a wallet loaded with testnet bitcoin is
      available.
    - Establish a connection to a Babylon node equipped with a keyring containing
      loaded funds. For enhanced security, consider running your own Babylon node.

   For detailed instructions, refer
   to [Staker Daemon Configuration](stakerd/stakerd-config.md#2-start-bitcoin-node-with-wallet)
   guide.

3. **Configure Staker Daemon:**
   Follow the [Staker Daemon Configuration](stakerd/stakerd-config.md) guide.

4. **Start Staker Daemon:**
   Follow the [Staker Daemon Startup Guide](stakerd/stakerd-startup-guide.md)

## Staking operations

The following guide will show how to stake, withdraw, and unbond Bitcoin.

### 1. Stake Bitcoin

#### 1. List active BTC finality providers on Babylon

Find the public key of the finality provider you want to stake to. You can stake to multiple
finality providers by specifying public keys in the `--finality-providers-pks` flag of the `stake`
command.

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

Stake Bitcoin to the finality provider(s) of your choice. The `--staking-time` flag specifies
the timelock of the staking transaction in BTC blocks. The `--staking-amount`
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
to create and register a finality provider to Babylon. Once the finality provider is registered, you
can use your finality provider BTC public key in the `--finality-providers-pks` flag of the `stake`
command.

### 2. Withdraw staked funds

The staker can withdraw the staked funds after the timelock of the staking or
unbonding transaction expires.

`--staking-transaction-hash` is the hash from response of `stake` command.

```bash
$ stakercli daemon unstake \
  --staking-transaction-hash 6bf442a2e864172cba73f642ced10c178f6b19097abde41608035fb26a601b10
```

### 3. Unbond staked funds

The `unbond` cmd initiates unbonding flow which involves communication with the
Babylon chain, Covenant emulators, and the BTC chain. It

1. Build the unbonding transaction and send it to the Babylon chain
2. Wait for the signatures from the covenant emulators
3. Send the unbonding transaction to the BTC chain

`--staking-transaction-hash` is the hash from response of `stake` command.

```bash
$ stakercli daemon unbond \
  --staking-transaction-hash 6bf442a2e864172cba73f642ced10c178f6b19097abde41608035fb26a601b10
```