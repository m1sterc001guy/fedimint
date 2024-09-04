#!/usr/bin/env bash

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"

source scripts/_common.sh
build_workspace
add_target_dir_to_path

gateway-tests config-test --gw-type lnd
gateway-tests config-test --gw-type cln
gateway-tests config-test --gw-type ldk
gateway-tests backup-restore-test
