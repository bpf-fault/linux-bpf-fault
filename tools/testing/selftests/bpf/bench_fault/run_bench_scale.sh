#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Run bench_fault_scale across thread counts for all modes.
#
# Usage: ./run_bench_scale.sh [pages_per_thread]
#   pages_per_thread defaults to 64

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BENCH="$SCRIPT_DIR/bench_fault_scale"
PAGES_PER_THREAD="${1:-64}"
THREADS="1 2 4 8 16 32 64 128 192 256 320 384 448 512"

if [ ! -x "$BENCH" ]; then
	echo "error: $BENCH not found, run 'make' first" >&2
	exit 1
fi

for t in $THREADS; do
	"$BENCH" -t "$t" -n "$PAGES_PER_THREAD" -b baseline
	"$BENCH" -t "$t" -n "$PAGES_PER_THREAD" -b uffd
	"$BENCH" -t "$t" -n "$PAGES_PER_THREAD" -b uffd_mt
	"$BENCH" -t "$t" -n "$PAGES_PER_THREAD" -b uffd_mt1
	"$BENCH" -t "$t" -n "$PAGES_PER_THREAD" -b bpf
done
