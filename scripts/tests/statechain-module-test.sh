#!/usr/bin/env bash
# Runs the statechain module's end-to-end CLI test against a devimint federation

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"

source scripts/_common.sh
build_workspace
add_target_dir_to_path

fedimint-statechain-devimint-tests
