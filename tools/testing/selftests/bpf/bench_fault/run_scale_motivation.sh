#!/bin/bash
# Scalability benchmark: baseline vs uffd vs sigsegv
set -eu -o pipefail

SCRIPT_PATH=$(realpath "$0")
SCRIPT_DIR=$(dirname "$SCRIPT_PATH")
RESULTS_DIR="$SCRIPT_DIR/results"

ITERATIONS=3
PAGES=64
MODES="baseline,uffd,sigsegv"

mkdir -p "$RESULTS_DIR"

python3 "$SCRIPT_DIR/run_bench_scale.py" \
	-n "$PAGES" \
	-m "$MODES" \
	--iterations "$ITERATIONS" \
	--results-file "$RESULTS_DIR/scale_results.json"

echo "Scale benchmark completed. Results saved to $RESULTS_DIR/scale_results.json."
