# ---
# jupyter:
#   jupytext:
#     notebook_metadata_filter: -jupytext.text_representation.jupytext_version
#     text_representation:
#       extension: .py
#       format_name: percent
#       format_version: '1.3'
#   kernelspec:
#     display_name: Python 3 (ipykernel)
#     language: python
#     name: python3
# ---

# %% [markdown]
# # Plot the relationship between FPR and traffic increase
#
# Plot the relationship between FPR and traffic increase.
# FPR is a metric we much care about, as this correlates with the resolution failure for benign traffic.
# This script consumes data in JSON format, potentially aggregated, and plots a point for each item.

# %%
from collections import defaultdict
from glob import glob
from pathlib import Path
from typing import Any, cast

import common_functions
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib import colors as mpl_colors
from matplotlib import lines as mpl_lines
from matplotlib import patches as mpl_patches

# # %matplotlib ipympl
# %matplotlib inline

# %%
common_functions.matplotlib_better_lines()
plt.rcParams["figure.figsize"] = (7, 4)
plt.rcParams["figure.dpi"] = 200
plt.rcParams["savefig.bbox"] = "tight"
plt.rcParams["figure.autolayout"] = True

# %%
USE_FLOAT = np.float64
DTYPES = {
    "count": np.uint32,
    "train_length": np.uint16,
    "test_length": np.uint16,
    "min_active": np.uint8,
    "min_pkts_avg": np.uint16,
    "low_pass": np.uint16,
    "above_train_limit": np.float64,
    "attack_bandwidth": np.float64,
    "true_positives": USE_FLOAT,
    "true_negatives": USE_FLOAT,
    "false_positives": USE_FLOAT,
    "false_negatives": USE_FLOAT,
    "f1_score": USE_FLOAT,
    "f05_score": USE_FLOAT,
    "avg_attack_traffic": USE_FLOAT,
    "avg_fpr": USE_FLOAT,
}

# %%
loc = pd.read_json(
    open(
        "dfc_results_config.json",
        "rt",
    ),
    dtype=DTYPES,
)
loc.head()

# %%
columns: list[str | list[str]] = [
    # "location",
    # "iprange_dst",
    # ["location", "iprange_dst"],
    # "test_length",
    # "low_pass",
    # ["test_length", "low_pass"],
    [
        "low_pass",
        "test_length",
    ],
    # "attack_bandwidth",
]


def format_legend_label(parameter: str, value: str | float) -> str:
    match parameter:
        case "test_length":
            return f"{value} h"
        case "attack_bandwidth":
            value = cast(float, value)
            return f"{value / (1024 * 1024 * 1024)} GBit/s"
        case "iprange_dst":
            value = cast(str, value)
            return value.split("/")[0]
        case _:
            return str(value)


def format_title_parts(part: str) -> str:
    d = {
        "low_pass": "$LPF$",
        "test_length": "$W_{test}$",
    }
    return d.get(part, part)


datafiles = glob("*_results_*.json")
for file in datafiles:
    loc = pd.read_json(
        open(file, "rt"),
        dtype=DTYPES,
    )
    scatters: defaultdict[
        tuple[str, ...], defaultdict[tuple[str, ...], tuple[list[float], list[float]]]
    ] = defaultdict(lambda: defaultdict(lambda: ([], [])))
    datafile_stats: defaultdict[
        # Test lengths
        int,
        defaultdict[
            # Low pass
            int,
            # FPR, weight of location, traffic in packets per second
            list[tuple[float, float, float]],
        ],
    ] = defaultdict(lambda: defaultdict(list))
    for col_idx, col in enumerate(columns):
        for index, row in loc.iterrows():
            if row["test_length"] not in [8, 24, 72]:
                continue

            avg_fpr = row["avg_fpr"]
            avg_attack_traffic = row["avg_attack_traffic"]

            if isinstance(col, list):
                primary_difference: tuple[str, ...] = tuple([c for c in col])
                secondary: tuple[Any, ...] = tuple([row[c] for c in col])
            else:
                primary_difference = tuple([col])
                secondary = tuple([row[col]])
            xs, ys = scatters[primary_difference][secondary]
            xs.append(avg_attack_traffic / 3600)
            ys.append(avg_fpr)

            # Collect stats for the datafile
            # Only do this once, otherwise duplicate data is entered
            if col_idx == 0:
                test_length = row["test_length"]
                low_pass = row["low_pass"]
                datafile_stats[test_length][low_pass].append(
                    (avg_fpr, 1.0, avg_attack_traffic / 3600)
                )

    imagebasepath = ""
    for idx, (primary_difference, scatter_data) in enumerate(scatters.items()):
        legend_handles = []
        # The plot might depend on a combined value
        # In this case we want to use different color+marker combinations
        match len(primary_difference):
            case 1:
                for primary_values, (xs, ys) in scatter_data.items():
                    # s=1
                    handle = plt.scatter(
                        xs,
                        ys,
                        label=format_legend_label(
                            primary_difference[0], primary_values[0]
                        ),
                        marker="+",  # type: ignore
                        alpha=1,
                    )
                    legend_handles.append(handle)
            case 2:
                coloriter = iter(
                    [
                        "#1f77b4",
                        "#ff7f0e",
                        "#2ca02c",
                        "#d62728",
                        "#9467bd",
                        "#8c564b",
                        "#e377c2",
                        "#7f7f7f",
                        "#bcbd22",
                        "#17becf",
                    ]
                )
                markeriter = iter(
                    [
                        "+",  # point
                        ".",  # start
                        "x",  # x
                        "d",  # thin diamond
                        "|",  # vline
                        "^",
                        "v",
                    ]
                )
                colorcache: defaultdict[str, str] = defaultdict(
                    lambda: next(coloriter)  # pylint: disable=cell-var-from-loop
                )
                markercache: defaultdict[str, str] = defaultdict(
                    lambda: next(markeriter)  # pylint: disable=cell-var-from-loop
                )

                for primary_values, (xs, ys) in scatter_data.items():
                    # Split the combined logical_dst value and get color and marker for them
                    first, second = primary_values
                    color = colorcache[first]
                    facecolor = mpl_colors.to_rgba(color, 0.7)  # type: ignore
                    edgecolor = mpl_colors.to_rgba(color, 0.0)  # type: ignore
                    marker = markercache[second]
                    plt.scatter(
                        xs, ys, facecolor=facecolor, edgecolor=edgecolor, marker=marker  # type: ignore
                    )

                for first, color in colorcache.items():
                    patch = mpl_patches.Patch(
                        color=color,
                        label=format_legend_label(primary_difference[0], first),
                    )
                    legend_handles.append(patch)
                for second, marker in markercache.items():
                    patch = mpl_lines.Line2D(
                        [0],
                        [0],
                        color="black",
                        label=format_legend_label(primary_difference[1], second),
                        marker=marker,
                        lw=0,
                    )
                    legend_handles.append(patch)
            case n:
                raise Exception(f"Found {n} parts, which is more than supported")

        setting, configuration = file.split("_results_")
        setting = setting.split("/")[-1]
        configuration = configuration.split(".")[0]
        # plt.title(
        #     " - ".join(format_title_parts(part) for part in primary_difference)
        #     + f" - {setting} - {configuration}"
        # )
        plt.xlabel("Traffic in packets per second")
        plt.ylabel("FPR")
        plt.xscale("symlog", linthresh=1)
        plt.xlim(left=10**0, right=10**6)
        plt.ylim(bottom=0, top=0.3)
        lgnd = plt.legend(handles=legend_handles)
        for lh in lgnd.legendHandles:  # type: ignore
            lh.set_alpha(1)
        Path(f"traffic-fpr/{configuration}/{setting}").mkdir(
            parents=True, exist_ok=True
        )
        imagebasepath = f"traffic-fpr/{configuration}/{setting}/{'-'.join(primary_difference).replace('/', '-')}"
        plt.savefig(imagebasepath + ".svg")
        plt.show()

    # Display stats about min/max/avg/med for the current dataset
    table_data = []
    for test_length in sorted(datafile_stats):
        datafile_stats_test_length = datafile_stats[test_length]
        for low_pass in sorted(datafile_stats_test_length):
            data: list[tuple[float, float, float]] = datafile_stats_test_length[
                low_pass
            ]

            values_fpr = list(a for a, _, _ in data)
            weights = list(b for _, b, _ in data)
            values_traffic = list(c for _, _, c in data)

            minimum_fpr = min(values_fpr)
            maximum_fpr = max(values_fpr)
            avg_fpr = sum(values_fpr) / len(values_fpr)
            avg_weight_fpr = sum(a * b for a, b in zip(values_fpr, weights)) / sum(
                weights
            )
            med_fpr = common_functions.median(values_fpr)
            med_weight_fpr = common_functions.weighted_median(values_fpr, weights)

            minimum_traffic = min(values_traffic)
            maximum_traffic = max(values_traffic)
            avg_traffic = sum(values_traffic) / len(values_traffic)
            avg_weight_traffic = sum(
                a * b for a, b in zip(values_traffic, weights)
            ) / sum(weights)
            med_traffic = common_functions.median(values_traffic)
            med_weight_traffic = common_functions.weighted_median(
                values_traffic, weights
            )

            table_data.append(
                [
                    test_length,
                    low_pass,
                    minimum_fpr,
                    avg_fpr,
                    med_fpr,
                    avg_weight_fpr,
                    med_weight_fpr,
                    maximum_fpr,
                    minimum_traffic,
                    avg_traffic,
                    med_traffic,
                    avg_weight_traffic,
                    med_weight_traffic,
                    maximum_traffic,
                ]
            )

    df = pd.DataFrame(
        table_data,
        columns=[
            "Test Length",
            "Low Pass",
            "Min",
            "Avg",
            "Med",
            "Avg (W)",
            "Med (W)",
            "Max",
            "Min",
            "Avg",
            "Med",
            "Avg (W)",
            "Med (W)",
            "Max",
        ],
    )
    ltx = df.to_latex(
        index=False,
        column_format="S" * len(df.columns),
        multirow=True,
        sparsify=True,
    )
    print(ltx)
    Path(imagebasepath + ".txt").write_text(ltx)

plt.clf()
