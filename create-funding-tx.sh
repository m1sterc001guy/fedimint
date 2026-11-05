#!/usr/bin/env bash
#
# Prints the hex of a transaction paying <amount> sats to <address> from the
# default wallet of the running devimint federation's bitcoind.
#
# The bitcoind wallet signs the transaction but does not broadcast it. Paste
# it into Ecash App's statecoin deposit: the app and the federation first sign
# the coin's backup transactions, which spend this one, and then the app
# broadcasts it.
#
# Usage: ./create-funding-tx.sh <address> <amount in sats>

set -euo pipefail

if [ $# -ne 2 ] || ! [[ "$2" =~ ^[0-9]+$ ]]; then
  echo "Usage: $0 <address> <amount in sats>" >&2
  exit 1
fi
ADDRESS="$1"
SATS="$2"

DEVIMINT_ENV="${DEVIMINT_ENV:-$(dirname "${BASH_SOURCE[0]}")/target-nix/devimint/env}"

# Set inside the devimint shell; elsewhere, read from devimint's env file.
if [ -z "${FM_BTC_CLIENT:-}" ]; then
  if [ ! -f "$DEVIMINT_ENV" ]; then
    echo "No devimint env at $DEVIMINT_ENV: run 'FM_ENABLE_MODULE_STATECHAIN=1 just devimint-env' first" >&2
    exit 1
  fi
  FM_BTC_CLIENT=$(sed -n 's/^export FM_BTC_CLIENT="\(.*\)"$/\1/p' "$DEVIMINT_ENV")
fi

if ! command -v bitcoin-cli >/dev/null; then
  echo "bitcoin-cli is not on the PATH: run this inside 'nix develop'" >&2
  exit 1
fi

BTC=$(printf '%d.%08d' $((SATS / 100000000)) $((SATS % 100000000)))

# add_to_wallet=false signs without broadcasting; lock_unspents keeps the
# next funding transaction from spending the same coins before this one is
# broadcast.
# shellcheck disable=SC2086 # FM_BTC_CLIENT is a command with arguments
RESULT=$($FM_BTC_CLIENT -rpcwallet=default -named send \
  outputs="{\"$ADDRESS\": $BTC}" \
  fee_rate=2 \
  options='{"add_to_wallet": false, "lock_unspents": true}')

if ! grep -q '"complete": true' <<<"$RESULT"; then
  echo "bitcoind could not sign the transaction: $RESULT" >&2
  exit 1
fi

sed -n 's/^ *"hex": "\([0-9a-f]*\)".*$/\1/p' <<<"$RESULT"
