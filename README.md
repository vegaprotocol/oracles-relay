oracles-relay
-------------

A repo containing oracles relays for the vega network.

The vega relay, pull oracle data from oracles providers, wrap them into a vega transaction, and submit the resulting transaction to a validator node
of the vega network.

# Supported oracles

So far only the [coinbase open oracle](https://docs.pro.coinbase.com/?r=1#oracle) is supported. More may come in the future.

# Configuration

Here's an example configuration required to start the relay
```toml
node_addr = "localhost:3002"

[coinbase]
  key_id = "coinbase key id"
  passphrase = "coinbase passphrase"
  secret = "base64 encode coinbase secret"
  frequency = "1h"
```
