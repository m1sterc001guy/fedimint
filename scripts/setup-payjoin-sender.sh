#!/usr/bin/env bash
# Setup script for payjoin sender wallet
# Usage: ./scripts/setup-payjoin-sender.sh

set -euo pipefail

# Get the RPC port from environment or use default
RPC_PORT="${FM_PORT_BTC_RPC:-18443}"

echo "Using Bitcoin RPC port: $RPC_PORT"

# Create sender wallet (ignore error if already exists)
echo "Creating sender wallet..."
bitcoin-cli -rpcuser=bitcoin -rpcpassword=bitcoin -regtest -rpcport="$RPC_PORT" createwallet sender 2>/dev/null || echo "Wallet 'sender' already exists"

# Get a new address from sender wallet
ADDR=$(bitcoin-cli -rpcuser=bitcoin -rpcpassword=bitcoin -regtest -rpcport="$RPC_PORT" -rpcwallet=sender getnewaddress)
echo "Sender address: $ADDR"

# Fund sender wallet from default wallet
echo "Funding sender wallet with 1 BTC..."
TXID=$(bitcoin-cli -rpcuser=bitcoin -rpcpassword=bitcoin -regtest -rpcport="$RPC_PORT" -rpcwallet="" sendtoaddress "$ADDR" 1)
echo "Funding txid: $TXID"

# Mine a block to confirm
echo "Mining a block..."
bitcoin-cli -rpcuser=bitcoin -rpcpassword=bitcoin -regtest -rpcport="$RPC_PORT" -rpcwallet="" -generate 1 > /dev/null

# Check balance
BALANCE=$(bitcoin-cli -rpcuser=bitcoin -rpcpassword=bitcoin -regtest -rpcport="$RPC_PORT" -rpcwallet=sender getbalance)
echo "Sender wallet balance: $BALANCE BTC"

echo ""
echo "Done! Sender wallet is ready."
echo ""
echo "To send a payjoin, use:"
echo "payjoin-cli --rpcuser bitcoin --rpcpassword bitcoin --rpchost http://127.0.0.1:$RPC_PORT/wallet/sender --ohttp-relays http://127.0.0.1:\$FM_PORT_PAYJOIN_RELAY send --fee-rate 1 \"<PAYJOIN_URI>\""
