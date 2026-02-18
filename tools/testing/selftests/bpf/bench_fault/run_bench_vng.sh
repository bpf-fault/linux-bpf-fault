#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Build and run the bpf_fault benchmark inside virtme-ng.
#
# This script handles the full workflow:
#   1. Build the kernel (if needed)
#   2. Build the benchmark (using the built kernel's BTF)
#   3. Boot the built kernel in virtme-ng
#   4. Run the benchmark inside the VM
#   5. Check dmesg for errors
#
# Usage: ./run_bench_vng.sh [-n num_pages] [-r rounds] [-b uffd|bpf|both]
#                           [-m memory] [-s] [-h]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KDIR="$(cd "$SCRIPT_DIR/../../../../.." && pwd)"
BENCH_BIN="$SCRIPT_DIR/bench_fault"
VMLINUX="$KDIR/vmlinux"

# Defaults
NUM_PAGES=1024
ROUNDS=3
BENCH_MODE="all"
MEMORY="2G"
SKIP_BUILD=false

usage() {
	cat <<-EOF
	Usage: $(basename "$0") [options]

	Options:
	  -n NUM_PAGES   Number of pages to fault (default: $NUM_PAGES)
	  -r ROUNDS      Number of rounds (default: $ROUNDS)
	  -b MODE        Benchmark mode: uffd, bpf, baseline, or all (default: $BENCH_MODE)
	  -m MEMORY      Guest memory size (default: $MEMORY)
	  -s             Skip kernel and benchmark build (use existing binaries)
	  -h             Show this help
	EOF
	exit 0
}

while getopts "n:r:b:m:sh" opt; do
	case $opt in
	n) NUM_PAGES="$OPTARG" ;;
	r) ROUNDS="$OPTARG" ;;
	b) BENCH_MODE="$OPTARG" ;;
	m) MEMORY="$OPTARG" ;;
	s) SKIP_BUILD=true ;;
	h) usage ;;
	*) usage ;;
	esac
done

die() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "==> $*"; }

# --- Preflight checks ---

command -v vng >/dev/null 2>&1 || die "virtme-ng (vng) not found in PATH"
command -v clang >/dev/null 2>&1 || die "clang not found in PATH"

case "$BENCH_MODE" in
uffd|bpf|baseline|all) ;;
*) die "Invalid benchmark mode '$BENCH_MODE'. Use: uffd, bpf, baseline, or all" ;;
esac

# --- Step 1: Build the kernel ---

if [ "$SKIP_BUILD" = false ]; then
	info "Building kernel in $KDIR"
	if [ -x "$KDIR/build.py" ]; then
		"$KDIR/build.py" build
	else
		make -C "$KDIR" LLVM=1 CC=clang -j"$(nproc)"
	fi
else
	info "Skipping kernel build (-s)"
fi

[ -f "$KDIR/arch/x86/boot/bzImage" ] || die "Kernel image not found. Run without -s to build."
[ -f "$VMLINUX" ] || die "vmlinux not found at $VMLINUX. Run without -s to build."

# --- Step 2: Build the benchmark ---

if [ "$SKIP_BUILD" = false ]; then
	info "Building benchmark (BTF from $VMLINUX)"
	make -C "$SCRIPT_DIR" clean
	make -C "$SCRIPT_DIR" VMLINUX_BTF="$VMLINUX"
else
	info "Skipping benchmark build (-s)"
fi

[ -x "$BENCH_BIN" ] || die "bench_fault binary not found. Run without -s to build."

# --- Step 3: Write guest script and run in virtme-ng ---

GUEST_SCRIPT=$(mktemp /tmp/bench_fault_guest.XXXXXX.sh)
trap "rm -f '$GUEST_SCRIPT'" EXIT

cat > "$GUEST_SCRIPT" <<'INNEREOF'
#!/bin/sh
set -e

# Clear dmesg so we only see messages from the benchmark run
dmesg -c > /dev/null 2>&1

echo "============================================================"
echo "  Page Fault Benchmark: userfaultfd vs bpf_fault (virtme-ng)"
echo "============================================================"
echo ""
echo "System info:"
echo "  Kernel:    $(uname -r)"
echo "  CPU:       $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)"
echo "  CPUs:      $(nproc)"
echo "  Memory:    $(free -h | awk '/Mem:/{print $2}')"
echo "  Page size: $(getconf PAGESIZE)"
echo ""
echo "Running: @BENCH@ -n @PAGES@ -r @ROUNDS@ -b @MODE@"
echo "============================================================"
echo ""

@BENCH@ -n @PAGES@ -r @ROUNDS@ -b @MODE@
rc=$?

echo ""
echo "============================================================"
echo "  dmesg (post-benchmark)"
echo "============================================================"
dmesg

exit $rc
INNEREOF

# Substitute host-side variables into the guest script
sed -i \
	-e "s|@BENCH@|$BENCH_BIN|g" \
	-e "s|@PAGES@|$NUM_PAGES|g" \
	-e "s|@ROUNDS@|$ROUNDS|g" \
	-e "s|@MODE@|$BENCH_MODE|g" \
	"$GUEST_SCRIPT"
chmod +x "$GUEST_SCRIPT"

info "Booting kernel in virtme-ng (memory=$MEMORY)"

exec script -qc "vng --run '$KDIR' --memory '$MEMORY' --exec '$GUEST_SCRIPT'" /dev/null
