#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Run the userfaultfd vs bpf_fault benchmark.
#
# Usage: ./run_bench.sh [-n num_pages] [-r rounds]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BENCH="$SCRIPT_DIR/bench_fault"
NUM_PAGES="${1:-4096}"
ROUNDS="${2:-3}"

if [ ! -x "$BENCH" ]; then
	echo "Error: bench_fault not found. Build it first with 'make'."
	exit 1
fi

echo "============================================================"
echo "  Page Fault Benchmark: userfaultfd vs bpf_fault"
echo "============================================================"
echo ""
echo "System info:"
echo "  Kernel:    $(uname -r)"
echo "  CPU:       $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)"
echo "  CPUs:      $(nproc)"
echo "  Memory:    $(free -h | awk '/Mem:/{print $2}')"
echo "  Page size: $(getconf PAGESIZE)"
echo ""

# Check capabilities
if [ "$(id -u)" -ne 0 ]; then
	echo "Warning: not running as root. BPF may fail."
	echo "  Try: sudo $0 $*"
	echo ""
fi

echo "Running benchmark: $NUM_PAGES pages, $ROUNDS rounds"
echo "============================================================"
echo ""

"$BENCH" -n "$NUM_PAGES" -r "$ROUNDS" 2>&1

echo "============================================================"
echo "  Done."
echo "============================================================"
