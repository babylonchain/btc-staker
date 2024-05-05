# Creating and Submitting phase-1 Staking Transactions

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

It only requires the specification of a funding Bitcoin public key. Wallet
creation and generating a Bitcoin public key for it are covered by
[this guide (steps 2 to 2.4)](../README.md#2-setting-up-a-bitcoin-node).

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

- `--staker-pk` Schnorr BTC staker public key in hex format.
- `--finality-provider-pk` The finality provider Schnorr BTC public key in hex format.
- `--staking-amount` The amount of satoshis to be locked.
- `--staking-time` The amount of BTC blocks to lock for.
- `--magic-bytes` Magic bytes in op_return output in hex.
- `--covenant-committee-pks` BTC public keys of the covenant committee. For each
covenant pub key specified, the flag needs to be used again.
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
  --covenant-quorum 3 \
  --covenant-committee-pks 05149a0c7a95320adf210e47bca8b363b7bd966be86be6392dd6cf4f96995869 \
  --covenant-committee-pks e8d503cb52715249f32f3ee79cee88dfd48c2565cb0c79cf9640d291f46fd518 \
  --covenant-committee-pks fe81b2409a32ddfd8ec1556557e8dd949b6e4fd37047523cb7f5fefca283d542 \
  --covenant-committee-pks bc4a1ff485d7b44faeec320b81ad31c3cad4d097813c21fcf382b4305e4cfc82 \
  --covenant-committee-pks 001e50601a4a1c003716d7a1ee7fe25e26e55e24e909b3642edb60d30e3c40c1 \
  --network signet

{
  "staking_tx_hex": "020000000002404b4c00000000002251207c2649dc890238fada228d52a4c25fcef82e1cf3d7f53895ca0fcfb15dd142bb0000000000000000496a470102030400b91ea4619bc7b3f93e5015976f52f666ae4eb5c98018a6c8e41424905fa8591fa89e7caf57360bc8b791df72abc3fb6d2ddc0e06e171c9f17c4ea1299e677565cd5000000000"
}
```

## Fund Raw Transaction

The generated raw transaction needs to be funded. To fund a transaction run
[`bitcoin-cli fundrawtransaction`](https://chainquery.com/bitcoin-cli/fundrawtransaction)
that adds inputs to a transaction until it has enough value to satisfy the transaction.

```shell
bitcoin-cli -testnet3 \
  -rpcuser=<your_rpc_username> \
  -rpcpassword=<your_rpc_password> \
  -rpcport=38332 \
  -rpcwallet=btc-staker \
  fundrawtransaction 020000000002404b4c00000000002251207c2649dc890238fada228d52a4c25fcef82e1cf3d7f53895ca0fcfb15dd142bb0000000000000000496a470102030400b91ea4619bc7b3f93e5015976f52f666ae4eb5c98018a6c8e41424905fa8591fa89e7caf57360bc8b791df72abc3fb6d2ddc0e06e171c9f17c4ea1299e677565cd5000000000

{
  "hex": "02000000015bd115941b71ace5ed9d5a0c239f9a074b32655bb8557497500edf92189a2bf20200000000fdffffff039095a7f70d0000001600142465c9555dba91e3e9a489c0b5ce706046ae8f34404b4c00000000002251207c2649dc890238fada228d52a4c25fcef82e1cf3d7f53895ca0fcfb15dd142bb0000000000000000496a470102030400b91ea4619bc7b3f93e5015976f52f666ae4eb5c98018a6c8e41424905fa8591fa89e7caf57360bc8b791df72abc3fb6d2ddc0e06e171c9f17c4ea1299e677565cd5000000000",
  "fee": 0.00235000,
  "changepos": 0
}
```

> You might need to unlock the wallet with [`bitcoin-cli walletpassphrase`](https://chainquery.com/bitcoin-cli/walletpassphrase)

## Sign Transaction

For the transaction to be submitted to the BTC network it first needs to be signed.
You can sign the raw funded transaction and output the signed format as hex
using the
[`bitcoin-cli signrawtransactionwithwallet`](https://chainquery.com/bitcoin-cli/signrawtransactionwithwallet)
command.

```shell
bitcoin-cli -testnet3 \
  -rpcuser=<your_rpc_username> \
  -rpcpassword=<your_rpc_password> \
  -rpcport=38332 \
  -rpcwallet=btc-staker \
  signrawtransactionwithwallet 02000000015bd115941b71ace5ed9d5a0c239f9a074b32655bb8557497500edf92189a2bf20200000000fdffffff039095a7f70d0000001600142465c9555dba91e3e9a489c0b5ce706046ae8f34404b4c00000000002251207c2649dc890238fada228d52a4c25fcef82e1cf3d7f53895ca0fcfb15dd142bb0000000000000000496a470102030400b91ea4619bc7b3f93e5015976f52f666ae4eb5c98018a6c8e41424905fa8591fa89e7caf57360bc8b791df72abc3fb6d2ddc0e06e171c9f17c4ea1299e677565cd5000000000

{
  "hex": "02000000000101ffa5874fdf64a535a4beae47ba0e66278b046baf7b3f3855dbf0413060aaeef90000000000fdffffff03404b4c00000000002251207c2649dc890238fada228d52a4c25fcef82e1cf3d7f53895ca0fcfb15dd142bb0000000000000000496a470102030400b91ea4619bc7b3f93e5015976f52f666ae4eb5c98018a6c8e41424905fa8591fa89e7caf57360bc8b791df72abc3fb6d2ddc0e06e171c9f17c4ea1299e677565cd50c876f7f70d0000001600141b9b57f4d4555e65ceb98c465c9580b0d6b0d0f60247304402200ae05daea3dc62ee7f2720c87705da28077ab19e420538eea5b92718271b4356022026c8367ac8bcd0b6d011842159cd525db672b234789a8d37725b247858c90a120121020721ef511b0faee2a487a346fdb96425d9dd7fa79210adbe7b47f0bcdc7e29de00000000",
  "complete": true
}
```

The output gives out the signed funded self-lock transaction in the `hex` property.

## Submit Transaction

The signed transaction can be submited onchain to BTC to be included in the blocks.
You can submit a transaction through the
[bitcoin-cli sendrawtransaction](https://chainquery.com/bitcoin-cli/sendrawtransaction)
that propagates the signed transaction to other nodes.

```shell
bitcoin-cli -testnet3 \
  -rpcuser=<your_rpc_username> \
  -rpcpassword=<your_rpc_password> \
  -rpcport=38332 \
  sendrawtransaction 02000000000101ffa5874fdf64a535a4beae47ba0e66278b046baf7b3f3855dbf0413060aaeef90000000000fdffffff03404b4c00000000002251207c2649dc890238fada228d52a4c25fcef82e1cf3d7f53895ca0fcfb15dd142bb0000000000000000496a470102030400b91ea4619bc7b3f93e5015976f52f666ae4eb5c98018a6c8e41424905fa8591fa89e7caf57360bc8b791df72abc3fb6d2ddc0e06e171c9f17c4ea1299e677565cd50c876f7f70d0000001600141b9b57f4d4555e65ceb98c465c9580b0d6b0d0f60247304402200ae05daea3dc62ee7f2720c87705da28077ab19e420538eea5b92718271b4356022026c8367ac8bcd0b6d011842159cd525db672b234789a8d37725b247858c90a120121020721ef511b0faee2a487a346fdb96425d9dd7fa79210adbe7b47f0bcdc7e29de00000000

f22b9a1892df0e50977455b85b65324b079a9f230c5a9dede5ac711b9415d15b
```

It outputs the transaction hash. Wait a few minutes and make sure that
the transaction is included in the blockchain by using the explorer or
running the following command [`bitcoin-cli gettransaction`](https://chainquery.com/bitcoin-cli/gettransaction)

```shell
bitcoin-cli -testnet3 \
  -rpcuser=<your_rpc_username> \
  -rpcpassword=<your_rpc_password> \
  -rpcport=38332 \
  gettransaction f22b9a1892df0e50977455b85b65324b079a9f230c5a9dede5ac711b9415d15b

{
  "amount": -0.05000000,
  "fee": -0.00235000,
  "confirmations": 3,
  "blockhash": "49e93a8088aca2e39aa92374e0cd4c6a641d04414953e523d91d5adf64d9b841",
  "blockheight": 471,
  "blockindex": 1,
  "blocktime": 1714779852,
  "txid": "f22b9a1892df0e50977455b85b65324b079a9f230c5a9dede5ac711b9415d15b",
  "wtxid": "6c46d1a2092c0ff8f26e6d1517f9f9ee119e57a615a47870dda58e69b36586ad",
  "walletconflicts": [
  ],
  "time": 1714779824,
  "timereceived": 1714779824,
  "bip125-replaceable": "no",
  "details": [
    {
      "address": "bcrt1p0snynhyfqgu04k3z34f2fsjlemuzu88n6l6n39w2pl8mzhw3g2asnxtl3q",
      "category": "send",
      "amount": -0.05000000,
      "vout": 0,
      "fee": -0.00235000,
      "abandoned": false
    },
    {
      "category": "send",
      "amount": 0.00000000,
      "vout": 1,
      "fee": -0.00235000,
      "abandoned": false
    }
  ],
  "hex": "02000000000101ffa5874fdf64a535a4beae47ba0e66278b046baf7b3f3855dbf0413060aaeef90000000000fdffffff03404b4c00000000002251207c2649dc890238fada228d52a4c25fcef82e1cf3d7f53895ca0fcfb15dd142bb0000000000000000496a470102030400b91ea4619bc7b3f93e5015976f52f666ae4eb5c98018a6c8e41424905fa8591fa89e7caf57360bc8b791df72abc3fb6d2ddc0e06e171c9f17c4ea1299e677565cd50c876f7f70d0000001600141b9b57f4d4555e65ceb98c465c9580b0d6b0d0f60247304402200ae05daea3dc62ee7f2720c87705da28077ab19e420538eea5b92718271b4356022026c8367ac8bcd0b6d011842159cd525db672b234789a8d37725b247858c90a120121020721ef511b0faee2a487a346fdb96425d9dd7fa79210adbe7b47f0bcdc7e29de00000000",
  "lastprocessedblock": {
    "hash": "59b36db40d4e127aaca060bf37d100d58b7afd33d930af74529be75bcfed488b",
    "height": 473
  }
}
```
