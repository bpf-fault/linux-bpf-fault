#!/usr/bin/env python3

import argparse
import logging
import os
import subprocess
import sys
from multiprocessing import cpu_count
from typing import List, Dict

log = logging.getLogger(__name__)


def run(*args, **kwargs):
    """Run commands idiomatically.

    Differences from default subprocess.run:
    - Errors raise an exception instead of having to check.
    """
    if "check" not in kwargs:
        kwargs["check"] = True
    return subprocess.run(*args, **kwargs)


def parse_args():
    parser = argparse.ArgumentParser("Kernel build helper")
    # Add build subcommand
    subparsers = parser.add_subparsers(dest="command")
    base_subparser = argparse.ArgumentParser(add_help=False)
    base_subparser.add_argument(
        "--debug", action="store_true", help="Enable debug mode"
    )
    base_subparser.add_argument(
        "--no-clang",
        action="store_true",
        default=False,
        help="Use clang as the compiler",
    )

    build_parser = subparsers.add_parser(
        "build", help="Build the kernel", parents=[base_subparser]
    )
    install_parser = subparsers.add_parser(
        "install", help="Install the kernel", parents=[base_subparser]
    )

    return parser.parse_args()


def edit_config_file(config_options: Dict[str, str], path=".config"):
    for config_opt, action in config_options.items():
        if action == "y":
            run(["./scripts/config", "-e", config_opt])
        elif action == "m":
            run(["./scripts/config", "-m", config_opt])
        elif action == "n":
            run(["./scripts/config", "-d", config_opt])
        else:
            raise ValueError(f"Invalid action {action} for config option {config_opt}")


def add_bpf_fault_config_options():
    config_options = {
        "CONFIG_USERFAULTFD": "y",
        "CONFIG_PTE_MARKER_UFFD_WP": "y",
        "CONFIG_BPF": "y",
        "CONFIG_BPF_JIT": "y",
        "CONFIG_DEBUG_INFO_REDUCED": "n",
        "CONFIG_DEBUG_INFO_BTF": "y",
        "CONFIG_BPF_FAULT": "y",
    }
    edit_config_file(config_options)


def add_default_config_options():
    config_options = {
        "CONFIG_RANDOMIZE_BASE": "n",
    }
    edit_config_file(config_options)


def add_debug_config_options():
    debug_config_options = {
        "CONFIG_DEBUG_KERNEL": "y",
        "CONFIG_DEBUG_SLAB": "y",
        "CONFIG_DEBUG_PAGEALLOC": "y",  # might be too slow
        "CONFIG_DEBUG_SPINLOCK": "y",
        "CONFIG_DEBUG_SPINLOCK_SLEEP": "y",
        "CONFIG_DEBUG_LOCKDEP": "y",
        "CONFIG_PROVE_LOCKING": "y",
        "CONFIG_LOCK_STAT": "y",
        "CONFIG_INIT_DEBUG": "y",
        "CONFIG_DEBUG_INFO": "y",
        "CONFIG_DEBUG_STACKOVERFLOW": "y",
        "CONFIG_DEBUG_STACK_USAGE": "y",
        # "CONFIG_DEBUG_KMEMLEAK": "y",
    }
    edit_config_file(debug_config_options)


def make(args: List[str] = [], env=None, parallel=True, sudo=False):
    cmd = ["make"]
    if sudo:
        cmd = ["sudo"] + cmd
    if parallel:
        cmd += ["-j", str(cpu_count())]
    cmd += args
    if not env:
        env = os.environ()
    run(cmd, env=env)


def build(args, llvm_env):
    log.info("Building the kernel")
    add_default_config_options()
    add_bpf_fault_config_options()
    if args.debug:
        add_debug_config_options()
    make(env=llvm_env)
    run(["python3", "./scripts/clang-tools/gen_compile_commands.py"])


def main():
    global log
    logging.basicConfig(level=logging.INFO)
    args = parse_args()
    if not args.no_clang:
        llvm_envvars = {
            "LLVM": "1",
            "CC": "clang",
            "KBUILD_BUILD_TIMESTAMP": "",
        }
    else:
        llvm_envvars = {}

    llvm_env = os.environ.copy()
    llvm_env.update(llvm_envvars)

    if args.command == "build":
        build(args, llvm_env)
    elif args.command == "install":
        build(args, llvm_env)
        log.info("Installing the kernel")
        make(["modules_install"], env=llvm_env, sudo=True)
        make(["install"], env=llvm_env, sudo=True)


if __name__ == "__main__":
    sys.exit(main())
