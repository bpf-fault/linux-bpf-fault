#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Plot helpers for benchmark results

import logging
from copy import deepcopy
from typing import Dict, List, Tuple, Callable, Union

import numpy as np
import matplotlib
matplotlib.use("Agg")
from matplotlib import pyplot as plt

# Embed fonts as TrueType so PDFs are editable in Illustrator/Inkscape
plt.rcParams["pdf.fonttype"] = 42
plt.rcParams["ps.fonttype"] = 42

from bench_lib import BenchRun

log = logging.getLogger(__name__)


def exists_config_in_results(results: List[BenchRun], config: Dict) -> bool:
    for r in results:
        if r.config == config:
            return True
    return False


def configs_select(results: List[BenchRun], config_match: Dict) -> List[Dict]:
    return [r.config for r in results if config_match.items() <= r.config.items()]


def results_select(
    results: List[BenchRun], config_match: Dict, select_fn: Callable
) -> List[BenchRun]:
    # Select results based on partial config match
    return [
        select_fn(r.results)
        for r in results
        if config_match.items() <= r.config.items()
    ]


def single_result_select(
    results: List[BenchRun], config_match: Dict, select_fn: Callable
) -> BenchRun:
    # Select results based on partial config match
    results = results_select(results, config_match, select_fn)
    if len(results) != 1:
        raise ValueError("Expected 1 result, got %s" % results)
    return results[0]


def config_combinations(results: List[BenchRun], fields: List[str]) -> List[Dict]:
    """Get all unique config combinations for the given fields."""
    configs = []
    for r in results:
        if not set(r.config.keys()) >= set(fields):
            continue
        new_combination = {}
        for field in fields:
            new_combination[field] = r.config[field]
        if new_combination not in configs:
            configs.append(new_combination)
    return configs


def filter_lists(l1: List, l2: List, f: callable) -> Tuple[List, List]:
    """Filter two lists based on a filter function."""
    good_idxs = []
    if len(l1) != len(l2):
        raise ValueError("Lists must be of same length")
    for i in range(len(l1)):
        if f(l1[i], l2[i]):
            good_idxs.append(i)
    return [l1[i] for i in good_idxs], [l2[i] for i in good_idxs]


def assert_only_differs_in_fields(configs: List[Dict], fields: List[str]):
    copied_configs = [deepcopy(config) for config in configs]
    copied_configs = [
        {k: v for k, v in config.items() if k not in fields}
        for config in copied_configs
    ]
    for config in copied_configs:
        assert copied_configs[0] == config, (
            f"Configs differ in fields other than {fields}. Configs: {configs}"
        )


class GrouppedBarPlot(object):
    def __init__(
        self,
        names: List[str],
        y_values: List[List],
        groups: List[str],
        colors: List[str],
        y_label=None,
    ) -> None:
        assert len(names) == len(y_values)
        assert len(y_values) > 0
        self.names = names
        self.y_values = y_values
        self.groups = groups
        self.num_bars = len(y_values)
        self.colors = colors
        self.y_label = y_label


def plot_groupped_bars(
    gpplot: GrouppedBarPlot,
    output="groupped_bars.pdf",
    show_measurements=True,
    measurement_fontsize=10,
    measurement_rotation=0,
    measurement_offset=1000,
    bar_width=0.7,
    ylimit=None,
    hide_y_ticks=False,
    fontsize=12,
    legend_fontsize=12,
    label_fontsize=None,
    legend_loc="best",
    text_center_list=None,
):
    if label_fontsize is None:
        label_fontsize = fontsize

    num_bars = gpplot.num_bars
    step = bar_width
    start = -bar_width * (num_bars - 1) / 2
    end = start + bar_width * (num_bars - 1)
    offsets = np.arange(start, end + step, step)
    xticks = np.arange(0, 4 * len(gpplot.groups), step=4)
    for i in range(num_bars):
        plt.bar(
            xticks + offsets[i],
            gpplot.y_values[i],
            width=bar_width,
            label=gpplot.names[i],
            color=gpplot.colors[i],
        )
        if show_measurements:
            for j, v in enumerate(xticks + offsets[i]):
                if text_center_list and j in text_center_list:
                    plt.text(
                        v + 0.1 * bar_width,
                        ylimit / 2,
                        str(int(gpplot.y_values[i][j] / 1000)) + "K",
                        ha="center",
                        rotation=measurement_rotation,
                        fontsize=measurement_fontsize,
                        color="white",
                        weight="bold",
                    )
                else:
                    plt.text(
                        v + 0.1 * bar_width,
                        gpplot.y_values[i][j] + measurement_offset,
                        str(int(gpplot.y_values[i][j] / 1000)) + "K",
                        ha="center",
                        rotation=measurement_rotation,
                        fontsize=measurement_fontsize,
                        color=gpplot.colors[i],
                        weight="bold",
                    )
    plt.xticks(xticks, gpplot.groups, fontsize=fontsize)
    if gpplot.y_label:
        plt.ylabel(gpplot.y_label, fontsize=label_fontsize)

    if ylimit:
        plt.ylim(0, ylimit)

    if hide_y_ticks:
        plt.tick_params(axis="y", which="both", labelleft=False)

    plt.yticks(fontsize=fontsize)
    plt.legend(fontsize=legend_fontsize, loc=legend_loc)
    plt.tight_layout()
    plt.savefig(output, metadata={"creationDate": None})
    plt.clf()


def bench_plot_groupped_results(
    config_matches: List[Dict],
    results: List[BenchRun],
    colors=["salmon", "maroon", "peru"],
    filename="groupped_bars.pdf",
    name_func=None,
    bench_types=None,
    bench_type_to_group: Union[None, Dict[str, str]] = None,
    result_select_fn=lambda r: r["throughput_avg"],
    y_label="Total Throughput (req/sec)",
    ylimit=None,
    hide_y_ticks=False,
    show_measurements=True,
    measurement_rotation=90,
    measurement_fontsize=12,
    fontsize=12,
    legend_fontsize=12,
    measurement_offset=1000,
    bar_width=1,
    label_fontsize=None,
    legend_loc="best",
    normalize_per_group=False,
    text_center_list=None,
):
    """Plot grouped bar chart results.

    Config match dicts should contain the fields needed to select results,
    plus a "benchmark" field that will be iterated over bench_types.
    """
    if bench_types is None:
        bench_types = []
    if name_func is None:
        name_func = lambda c: str(c)

    if not bench_type_to_group:
        bench_type_to_group = {}
        for idx in range(len(bench_types)):
            bench_type_to_group[bench_types[idx]] = f"Benchmark {idx}"
    groups = [bench_type_to_group[bench_type] for bench_type in bench_types]
    names = []
    y_values = []

    for config_match in config_matches:
        names.append(name_func(config_match))
        ys = []

        for bench_type in bench_types:
            config_match["benchmark"] = bench_type
            y_res = results_select(results, config_match, result_select_fn)
            cm_res = configs_select(results, config_match)
            if len(y_res) > 1:
                assert_only_differs_in_fields(cm_res, ["iteration"])
                y_res = [np.mean(y_res)]
            elif len(y_res) == 0:
                raise Exception(f"No results for {config_match}")
            assert len(y_res) == 1, "len(y_res) = %d" % len(y_res)
            ys.append(y_res[0])
        assert len(ys) == len(groups), "len(ys) = %d" % len(ys)
        y_values.append(ys)

    if normalize_per_group:
        for idx in range(len(y_values[0])):
            max_value_for_idx = max([ys[idx] for ys in y_values])
            for ys in y_values:
                ys[idx] = ys[idx] / max_value_for_idx * 100

    gpplot = GrouppedBarPlot(names, y_values, groups, colors, y_label=y_label)
    assert gpplot.num_bars == len(colors), "gpplot.num_bars = %d, len(colors) = %d" % (
        gpplot.num_bars,
        len(colors),
    )

    plot_groupped_bars(
        gpplot,
        filename,
        measurement_offset=measurement_offset,
        bar_width=bar_width,
        show_measurements=show_measurements,
        measurement_fontsize=measurement_fontsize,
        measurement_rotation=measurement_rotation,
        ylimit=ylimit,
        hide_y_ticks=hide_y_ticks,
        fontsize=fontsize,
        legend_fontsize=legend_fontsize,
        label_fontsize=label_fontsize,
        legend_loc=legend_loc,
        text_center_list=text_center_list,
    )
