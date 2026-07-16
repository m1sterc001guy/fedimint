#!/usr/bin/env bash
# Runs the frost-playground binary, which exercises FROST DKG and a taproot
# peg-in against a devimint federation

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"

source scripts/_common.sh
build_workspace
add_target_dir_to_path
make_fm_test_marker

frost-playground
