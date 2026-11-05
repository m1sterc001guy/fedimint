#!/usr/bin/env bash
#
# Prints a new address of the running devimint federation's bitcoind default
# wallet, e.g. for a statecoin's exit address or a peg-out.
#
# Usage: ./get-new-address.sh

set -euo pipefail

if [ $# -ne 0 ]; then
  echo "Usage: $0" >&2
  exit 1
fi

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

# shellcheck disable=SC2086 # FM_BTC_CLIENT is a command with arguments
$FM_BTC_CLIENT -rpcwallet=default getnewaddress
