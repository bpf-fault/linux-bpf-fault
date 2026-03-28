#!/bin/bash
# Single-threaded fault benchmarks: missing, WP, and minor faults
set -eu -o pipefail

SCRIPT_PATH=$(realpath "$0")
SCRIPT_DIR=$(dirname "$SCRIPT_PATH")
RESULTS_DIR="$SCRIPT_DIR/results"

ITERATIONS=3
PAGES=1024

mkdir -p "$RESULTS_DIR"

python3 "$SCRIPT_DIR/run_bench_fault.py" \
	-n "$PAGES" \
	--iterations "$ITERATIONS" \
	--results-file "$RESULTS_DIR/fault_results.json"

echo "Fault benchmark completed. Results saved to $RESULTS_DIR/fault_results.json."
