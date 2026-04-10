#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Run bench_fault_scale across thread counts using the BenchmarkFramework.
# Outputs JSON with result reuse, checkpointing, and iteration support.
#
# Usage:
#   ./run_bench_scale.py                                        # all defaults
#   ./run_bench_scale.py -n 128 --iterations 3                  # 128 pages, 3 rounds
#   ./run_bench_scale.py -m baseline,bpf -t 1,2,4,8             # subset
#   ./run_bench_scale.py --results-file scale.json               # custom output
#   ./run_bench_scale.py --no-reuse-results                      # fresh run

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
    online_cpu_count,
    parse_strings_string,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

BENCH = os.path.join(SCRIPT_DIR, "bench_fault_scale")
DEFAULT_THREADS = "1,2,4,8,16,32,64,128,192,256,320,384,448,512"
DEFAULT_MODES = "baseline,uffd,uffd_mt,uffd_mt1,uffd_mfd,sigsegv,bpf"


class ScaleBenchmark(BenchmarkFramework):

    def add_arguments(self, parser):
        # Default --cpu to online CPUs (queried after SMT is disabled)
        parser.set_defaults(cpu=str(online_cpu_count()))
        parser.add_argument(
            "-n", "--pages-per-thread", type=int, default=64,
            help="Pages per thread",
        )
        parser.add_argument(
            "-m", "--modes", default=DEFAULT_MODES,
            help="Comma-separated modes",
        )
        parser.add_argument(
            "-t", "--threads", default=DEFAULT_THREADS,
            help="Comma-separated thread counts",
        )

    def generate_configs(self, configs):
        modes = parse_strings_string(self.args.modes)
        thread_counts = [int(t.strip()) for t in self.args.threads.split(",")]

        configs = add_config_option("pages_per_thread",
                                    [self.args.pages_per_thread], configs)
        configs = add_config_option("mode", modes, configs)
        configs = add_config_option("threads", thread_counts, configs)

        rounds = list(range(1, self.args.iterations + 1))
        configs = add_config_option("round", rounds, configs)
        return configs

    def benchmark_prepare(self, config):
        if not os.path.isfile(BENCH):
            raise FileNotFoundError(f"{BENCH} not found, run 'make' first")

    def benchmark_cmd(self, config):
        return ["sudo", BENCH,
                "-t", str(config["threads"]),
                "-n", str(config["pages_per_thread"]),
                "-b", config["mode"]]

    def parse_results(self, stdout):
        for line in stdout.strip().splitlines():
            if line.startswith("mode="):
                fields = {}
                for token in line.split():
                    k, v = token.split("=", 1)
                    fields[k] = v
                for k in ["handlers", "threads", "pages_per_thread",
                           "total_faults", "wall_ns", "cpu_us"]:
                    if k in fields:
                        fields[k] = int(fields[k])
                return BenchResults(fields)
        return BenchResults({})


if __name__ == "__main__":
    disable_smt()
    try:
        bench = ScaleBenchmark("scale_bench")
        results = bench.benchmark()
    finally:
        enable_smt()
    print(f"\nCompleted {len(results)} benchmark runs.", file=sys.stderr)
