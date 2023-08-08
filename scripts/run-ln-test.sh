#!/bin/bash

# Run the command 10 times in a loop
for ((i = 1; i <= 10; i++)); do
    echo "Running iteration $i"
    ./scripts/rust-tests.sh
done

