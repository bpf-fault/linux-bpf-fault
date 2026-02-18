#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Run bench_fault_scale across thread counts and plot the results.
#
# Usage: ./plot_bench_scale.py [-n pages_per_thread] [-o output.png]
#   -n  pages per thread (default: 64)
#   -o  output file (default: bench_fault_scale.png)

import argparse
import os
import subprocess
import sys
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.join(SCRIPT_DIR, "bench_fault_scale")
THREADS = [1, 2, 4, 8, 16, 32, 64, 128, 192, 256, 320, 384, 448, 512]


def run_bench(threads, pages_per_thread, mode):
    cmd = ["sudo", BENCH, "-t", str(threads), "-n", str(pages_per_thread), "-b", mode]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"error: {' '.join(cmd)}", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        return None

    for line in result.stdout.strip().splitlines():
        if line.startswith("mode="):
            fields = {}
            for token in line.split():
                k, v = token.split("=", 1)
                fields[k] = v
            return fields
    return None


def main():
    parser = argparse.ArgumentParser(description="Scalability benchmark plot")
    parser.add_argument("-n", type=int, default=64, help="pages per thread")
    parser.add_argument("-o", default="bench_fault_scale.png", help="output file")
    args = parser.parse_args()

    if not os.path.isfile(BENCH):
        print(f"error: {BENCH} not found, run 'make' first", file=sys.stderr)
        sys.exit(1)

    modes = ["baseline", "bpf"] # "uffd"
    # mode -> {threads: wall_ms}
    data = defaultdict(dict)

    for t in THREADS:
        for mode in modes:
            print(f"  running: {mode} threads={t} pages={args.n}", file=sys.stderr)
            r = run_bench(t, args.n, mode)
            if r and "wall_ns" in r:
                wall_ms = int(r["wall_ns"]) / 1e6
                data[mode][t] = wall_ms

    fig, ax = plt.subplots(figsize=(10, 6))
    for mode in modes:
        if mode not in data:
            continue
        xs = sorted(data[mode].keys())
        ys = [data[mode][t] for t in xs]
        print(mode)
        ax.plot(xs, ys, marker="o", label=mode)

    ax.set_xlabel("Threads")
    ax.set_ylabel("Wall time (ms)")
    ax.set_title(f"Page fault scalability ({args.n} pages/thread)")
    ax.legend()
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(args.o, dpi=150)
    print(f"Plot saved to {args.o}", file=sys.stderr)


if __name__ == "__main__":
    main()
