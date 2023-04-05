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
# # Show the difference between normal evaluation and the "churn" results
#
# The "churn" results use the same allowlist (`start_time` == 1) for all times.
# This means it ages throughout the time.
# In the beginning the "churn" version will be identical to the normal evaluation, but then the differences in the allowlist will accumulate.
#
# Positive values represent that the "churn" variant is worse than normal, while negative values indicate a better performance.

# %%
import json
from collections import defaultdict
from typing import Any

import common_functions
import matplotlib.pyplot as plt

# # %matplotlib ipympl

# %%
common_functions.matplotlib_better_lines()
plt.rcParams["figure.figsize"] = (7, 4)
plt.rcParams["figure.dpi"] = 200
plt.rcParams["savefig.bbox"] = "tight"
plt.rcParams["figure.autolayout"] = True

# %%
with open("./results_diff_config.json") as f:
    data = json.load(f)


# %%


def check_passes_filter(config: dict[str, Any], filt: dict[str, list[Any]]) -> bool:
    for filterkey, filtervalues in filt.items():
        if config[filterkey] not in filtervalues:
            return False
    return True


# %%
filters: list[dict[str, list[Any]]] = [
    {
        "train_length": [1],
        "test_length": [8],
    },
    {
        "train_length": [72],
        "test_length": [72],
    },
    {
        "train_length": [72],
        "test_length": [8],
    },
    {
        "train_length": [1],
        "test_length": [72],
    },
]

for filt in filters:
    count = 0
    points: dict[tuple[str, str], list[tuple[int, float, float]]] = defaultdict(list)

    for entry in data:
        if not check_passes_filter(entry["config"], filt):
            continue

        for idx, diff in enumerate(entry["diffs"]):
            points[
                (entry["config"]["location"], entry["config"]["iprange_dst"])
            ].append((idx, diff["attack_traffic"], diff["fpr"]))

    xbins = list(range(0, 700, 4))
    for key, p in points.items():
        x, y, z = zip(*p)

        counts, xedges, yedges, im = plt.hist2d(
            x,
            y,
            bins=(
                xbins,
                [
                    -100000,
                    -50000,
                    -20000,
                    -10000,
                    -5000,
                    -2000,
                    -1000,
                    0,
                    1000,
                    2000,
                    5000,
                    10000,
                    20000,
                    50000,
                    100000,
                ],
            ),  # type: ignore
        )
        plt.colorbar(im)
        plt.title(f"Traffic {key[0]} F{filt}")
        plt.show()

        counts, xedges, yedges, im = plt.hist2d(
            x,
            z,
            bins=(
                xbins,
                [
                    -1.0,
                    -0.5,
                    -0.4,
                    -0.3,
                    -0.2,
                    -0.15,
                    -0.1,
                    -0.08,
                    -0.06,
                    -0.05,
                    -0.04,
                    -0.03,
                    -0.02,
                    -0.01,
                    0.0,
                    0.01,
                    0.02,
                    0.03,
                    0.04,
                    0.05,
                    0.06,
                    0.08,
                    0.1,
                    0.15,
                    0.2,
                    0.3,
                    0.4,
                    0.5,
                    1.0,
                ],
            ),  # type: ignore
        )
        plt.colorbar(im)
        plt.title(f"FPR {key[0]} F{filt}")
        plt.show()

# %%
filters = [
    {
        "train_length": [1],
        "test_length": [1],
        "min_active": [1],
        "min_pkts_avg": [64],
        "low_pass": [128],
        "above_train_limit": [1],
        "location": ["xxx"],
    },
]


for filt in filters:
    count = 0
    points2: dict[
        tuple[str, str], dict[str, list[tuple[int, float, float]]]
    ] = defaultdict(lambda: defaultdict(list))

    for entry in data:
        if not check_passes_filter(entry["config"], filt):
            continue

        values = [
            (idx + entry["config"]["train_length"], diff["attack_traffic"], diff["fpr"])
            for idx, diff in enumerate(entry["diffs"])
        ]
        points2[(entry["config"]["location"], entry["config"]["iprange_dst"])][
            str(entry["config"]["train_length"])
        ] = values

    xbins = list(range(0, 700, 4))
    for key, lines in points2.items():
        maxx = 0
        for label, line in lines.items():
            x, y, z = list(zip(*line))
            maxx = max(maxx, *x)
            plt.plot(x, y, label=f"$W_{{train}}$ = {label}")
        plt.hlines(0, xmin=0, xmax=maxx, color="black", alpha=0.5, linestyles="dashed")
        plt.title(f"Traffic {key[0]} F{filt}")
        plt.legend()
        plt.xlim(1, maxx)
        plt.show()

        for label, line in lines.items():
            x, y, z = list(zip(*line))
            plt.plot(x, z, label=f"$W_{{train}}$ = {label}")
        plt.hlines(0, xmin=0, xmax=maxx, color="black", alpha=0.5, linestyles="dashed")
        # plt.title(f"FPR {key[0]} F{filter}")
        plt.legend()
        plt.xlim(0, maxx)
        plt.ylim(-0.3, 0.3)
        plt.xlabel("Time in hours")
        plt.ylabel("FPR Comparison\n    Drift Better | Normal Better")
        plt.savefig("churn-comparison.svg")
        plt.show()
