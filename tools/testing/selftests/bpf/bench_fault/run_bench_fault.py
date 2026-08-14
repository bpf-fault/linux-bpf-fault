#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Run bench_fault, bench_fault_wp, and bench_fault_shmem benchmarks
# using the BenchmarkFramework and output JSON results.
#
# Usage:
#   ./run_bench_fault.py                                    # all defaults
#   ./run_bench_fault.py -n 2048 --iterations 3             # 2048 pages, 3 rounds
#   ./run_bench_fault.py -f missing,wp                      # only missing + WP
#   ./run_bench_fault.py -f wp -m bpf,sigsegv               # WP bpf+sigsegv only
#   ./run_bench_fault.py --results-file wp.json -f wp       # custom output file
#   ./run_bench_fault.py --no-reuse-results                 # fresh run, no reuse

import logging
import os
import sys

from bench_lib import (
    SCRIPT_DIR,
    BenchmarkFramework,
    BenchResults,
    add_config_option,
    disable_smt,
    enable_smt,
    parse_bench_output,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

BENCHMARKS = {
    "missing": {
        "binary": "bench_fault",
        "modes": ["baseline", "uffd", "sigsegv", "bpf"],
    },
    "wp": {
        "binary": "bench_fault_wp",
        "modes": ["bpf", "uffd", "sigsegv"],
    },
    "minor": {
        "binary": "bench_fault_shmem",
        "modes": ["baseline", "uffd", "bpf"],
    },
}

# Fault types whose binary accepts -W to fault with a write instead of a
# read.  For the others the access mode is fixed at "write".
WRITE_FLAG_TYPES = ("missing", "minor")


class FaultBenchmark(BenchmarkFramework):

    def add_arguments(self, parser):
        parser.add_argument(
            "-n", "--num-pages", type=int, default=1024,
            help="Pages to fault per run",
        )
        parser.add_argument(
            "-f", "--fault-types", default="missing,wp,minor",
            help="Comma-separated fault types (missing, wp, minor)",
        )
        parser.add_argument(
            "-m", "--modes", default=None,
            help="Comma-separated modes to run (default: all for each type)",
        )
        parser.add_argument(
            "-a", "--access-modes", default="read,write",
            help="Comma-separated access modes: read, write (default: both)",
        )
        # Override base class default: uffd needs at least 2 CPUs
        # (faulter + handler), 1 CPU forces both onto the same core
        # which hides cross-CPU context switch costs.
        parser.set_defaults(cpu="2")

    def generate_configs(self, configs):
        fault_types = [t.strip() for t in self.args.fault_types.split(",")]
        access_modes = [a.strip() for a in self.args.access_modes.split(",")]
        mode_filter = None
        if self.args.modes:
            mode_filter = set(m.strip() for m in self.args.modes.split(","))

        configs = add_config_option("num_pages", [self.args.num_pages], configs)

        expanded = []
        for config in configs:
            for ft in fault_types:
                if ft not in BENCHMARKS:
                    print(f"error: unknown fault type '{ft}', "
                          f"choose from: {','.join(BENCHMARKS)}",
                          file=sys.stderr)
                    sys.exit(1)
                for mode in BENCHMARKS[ft]["modes"]:
                    if mode_filter and mode not in mode_filter:
                        continue
                    # bench_fault and bench_fault_shmem take -W; the wp
                    # binary always writes (that is what lifts the WP).
                    ft_access = (access_modes if ft in WRITE_FLAG_TYPES
                                 else ["write"])
                    for access in ft_access:
                        c = config.copy()
                        c["fault_type"] = ft
                        c["mode"] = mode
                        c["access"] = access
                        expanded.append(c)

        rounds = list(range(1, self.args.iterations + 1))
        expanded = add_config_option("round", rounds, expanded)
        return expanded

    def benchmark_prepare(self, config):
        ft = config["fault_type"]
        binary = BENCHMARKS[ft]["binary"]
        path = os.path.join(SCRIPT_DIR, binary)
        if not os.path.isfile(path):
            raise FileNotFoundError(f"{path} not found, run 'make' first")

    def benchmark_cmd(self, config):
        ft = config["fault_type"]
        binary = BENCHMARKS[ft]["binary"]
        path = os.path.join(SCRIPT_DIR, binary)
        cmd = ["sudo", path,
               "-n", str(config["num_pages"]),
               "-r", "1",
               "-b", config["mode"]]
        if config.get("access") == "write" and ft in WRITE_FLAG_TYPES:
            cmd.append("-W")
        return cmd

    def parse_results(self, stdout):
        blocks = parse_bench_output(stdout)
        if blocks:
            return BenchResults(blocks[0])
        return BenchResults({})


if __name__ == "__main__":
    disable_smt()
    try:
        bench = FaultBenchmark("fault_bench")
        results = bench.benchmark()
    finally:
        enable_smt()
    print(f"\nCompleted {len(results)} benchmark runs.", file=sys.stderr)
