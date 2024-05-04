# Phase1 Staking Transaction

The phase-1 staking transaction is a
[Bitcoin Staking transaction](https://github.com/babylonchain/babylon/blob/v0.8.5/docs/staking-script.md)
that includes an additional `OP_RETURN` field containing
the staking parameters to enable for easy identification
and taproot decoding through observing the Bitcoin ledger.

## Requirements

- [stakercli](../README.md#3-btc-staker-installation)
- [bitcoin-cli](../README.md#21-download-and-extract-bitcoin-binary)
- [jq](https://jqlang.github.io/jq/download/)

The generation of a phase-1 staking transaction does not require
an active `stakerd` daemon that connects to a Babylon node.
It can be generated in offline mode without any external connections.

The generation of the phase-1 staking transaction requires the specification
of a funding address. Wallet creation and generating an address for it are
covered by [this guide (steps 2 to 2.4)](../README.md#2-setting-up-a-bitcoin-node).

## Identifying the Staker Public Key

A Bitcoin staking transaction requires the specification
of the staker public key, which corresponds to the public key
of the wallet that is funding the staking transaction.
Once you setup your wallet and an address for it,
you can extract the public key corresponding to it through the
[`bitcoin-cli listunspent`](https://chainquery.com/bitcoin-cli/listunspent).
The output should be one slice with a list of unspent transaction outputs:

```shell
bitcoin-cli -signet \
  -rpcuser=<your_rpc_username> \
  -rpcpassword=<your_rpc_password> \
  -rpcport=38332 \
  -rpcwallet=btc-staker \
  listunspent

[
  {
    "txid": "f9eeaa603041f0db55383f7baf6b048b27660eba47aebea435a564df4f87a5ff",
    "vout": 0,
    "address": "bcrt1q29q36vd2449ajaz68mhnh46xcty825lnh6z0xl",
    "label": "",
    "scriptPubKey": "001451411d31aaad4bd9745a3eef3bd746c2c87553f3",
    "amount": 600.00000000,
    "confirmations": 30,
    "spendable": true,
    "solvable": true,
    "desc": "wpkh([4b45934d/0h/0h/0h]020721ef511b0faee2a487a346fdb96425d9dd7fa79210adbe7b47f0bcdc7e29de)#kxsmmtvy",
    "parent_descs": [
    ],
    "safe": true
  }
]
```

The BTC staker public key can be derived from the `desc` property.
You can use the `jq` utility to reduce it as follows:

```shell
bitcoin-cli -datadir=1 -rpcwallet=btc-staker listunspent | jq -r '.[0].desc | split("]") | .[-1] | split(")") | .[0] | .[2:]'

0721ef511b0faee2a487a346fdb96425d9dd7fa79210adbe7b47f0bcdc7e29de
```

In this example the value `0721ef511b0faee2a487a346fdb96425d9dd7fa79210adbe7b47f0bcdc7e29de`
is the BTC staker public key in hex format.

## Create Raw Transaction

The binary `stakercli` will be used to generate the transaction using
the `transaction create-phase1-staking-transaction` command.

This command has several flag options:

- `--staker-pk` BTC staker public key in schnorr format as hex.
- `--finality-provider-pk` The finality provider public key in schnorr format as hex.
- `--staking-amount` The amount of satoshis to be locked.
- `--staking-time` The amount of BTC blocks to lock for.
- `--magic-bytes` Magic bytes in op_return output in hex.
- `--covenant-committee-pks` BTC public keys of the covenant committee.
- `--covenant-quorum` Required quorum of covenant members to unbond.
- `--network` Specifies the BTC network this transaction will be sent, any of
`[mainnet, testnet3, regtest, simnet, signet]`.

For example to generate one staking transaction that locks `0.05` BTC for one
year, use `--staking-amount=5000000` and `--staking-time=52560`.

```shell
stakercli transaction create-phase1-staking-transaction \
  --staker-pk 0721ef511b0faee2a487a346fdb96425d9dd7fa79210adbe7b47f0bcdc7e29de
  --staking-amount 5000000 --staking-time 52560 \
  --magic-bytes <bbn_4byte_identifier> \
  --finality-provider-pk <fp_pk_chosen> \
  --covenant-quorum <bbn_quorum> --covenant-committee-pks <covenant_pk> \
  --network signet

{
  "staking_tx_hex": "020000000002404b4c00000000002251207c2649dc890238fada228d52a4c25fcef82e1cf3d7f53895ca0fcfb15dd142bb0000000000000000496a470102030400b91ea4619bc7b3f93e5015976f52f666ae4eb5c98018a6c8e41424905fa8591fa89e7caf57360bc8b791df72abc3fb6d2ddc0e06e171c9f17c4ea1299e677565cd5000000000"
}
```
