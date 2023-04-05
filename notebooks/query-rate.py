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

# %%
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import common_functions
import matplotlib.pyplot as plt
import numpy as np
from matplotlib import colors


# %%
@dataclass(order=True)
class Tuple:
    first: Any


# %%
common_functions.matplotlib_better_lines()
# plt.rcParams["figure.figsize"] = (15, 7.5)
plt.rcParams["figure.figsize"] = (7, 4)
plt.rcParams["figure.figsize"] = (14, 4.5)
plt.rcParams["savefig.bbox"] = "tight"
plt.rcParams["figure.autolayout"] = True

# %%

total_packets: dict[str, int] = defaultdict(int)
list_active_hours: dict[str, list[int]] = defaultdict(list)
list_pkts_max: dict[str, list[float]] = defaultdict(list)
list_pkts_sum: dict[str, list[int]] = defaultdict(list)
list_pkts_avg: dict[str, list[float]] = defaultdict(list)

# See peak-rate.sql how to generate this file
with open("./peak-rate.json") as f:
    for line in f:
        data = json.loads(line)

        loc = data["location"]
        assert loc is not None
        active_hours = int(data["active_hours"])

        if active_hours <= 0:
            continue

        # *10 to account for the 1-to-10 sampling rate
        pkts_max = int(data["total_packets_max"]) * 10
        pkts_sum = int(data["total_packets_sum"]) * 10
        pkts_avg = pkts_sum / active_hours

        total_packets[loc] += pkts_sum
        list_active_hours[loc].append(active_hours)
        list_pkts_max[loc].append(pkts_max)
        list_pkts_sum[loc].append(pkts_sum)
        list_pkts_avg[loc].append(pkts_avg)

        # dict_keys(['location', 'iprange_src', 'iprange_dst', 'total_packets_max', 'total_packets_sum', 'active_hours'])

# %%
THRESHOLDS = [0.8, 0.85, 0.9, 0.925, 0.95, 0.975, 0.99]
THRESHOLDS = []


# %%
def calculate_border(
    total_packets: int,
    list_active_hours: list[int],
    list_pkts_sum: list[int],
    list_pkts_prop: list[float],
) -> tuple[list[int], dict[float, list[float]]]:
    border_x: list[int] = []
    border_y: dict[float, list[float]] = defaultdict(list)
    for min_hours in range(0, 648 + 1, 5):

        # Filter the previous lists, to only keep entries with the correct min_hours value
        filtered_pkts_sum: list[int] = []
        filtered_pkts_prop: list[float] = []
        for hours, pkts_sum, pkts_avg in zip(
            list_active_hours, list_pkts_sum, list_pkts_prop
        ):
            if hours >= min_hours:
                filtered_pkts_sum.append(pkts_sum)
                filtered_pkts_prop.append(pkts_avg)

        # From highest pkts value to the lowest, determine where the border is
        # Filter according to the total number of packets send by each source
        sort_idxs = np.argsort(
            [Tuple((a, b)) for a, b in zip(filtered_pkts_prop, filtered_pkts_sum)]  # type: ignore
        )
        # Sort highest first
        sort_idxs = np.flipud(sort_idxs)
        filtered_pkts_sum = [filtered_pkts_sum[idx] for idx in sort_idxs]
        filtered_pkts_prop = [filtered_pkts_prop[idx] for idx in sort_idxs]

        cumsum_sum = np.cumsum(filtered_pkts_sum)

        # Find the index where we reach the border condition
        border_x.append(min_hours)
        for t in THRESHOLDS:
            for i, v in enumerate(cumsum_sum):
                if v >= total_packets * t:
                    border_y[t].append(filtered_pkts_prop[i])
                    break
    return (border_x, border_y)


# %%
bins = [648 // 2, np.logspace(np.log10(10), np.log10(10000000), 100)]
for loc, l_active_hours in list_active_hours.items():
    print(loc)
    norm = colors.LogNorm()

    plt.clf()
    # border_x, border_y = calculate_border(
    #     sum(list_pkts_sum[loc]),
    #     list_active_hours[loc],
    #     list_pkts_sum[loc],
    #     list_pkts_max[loc],
    # )
    counts, xedges, yedges, im = plt.hist2d(
        l_active_hours,
        list_pkts_max[loc],
        label=f"{loc} - pkts_max",
        bins=bins,
        norm=norm,
    )
    plt.colorbar(im, label="Number of source networks")
    plt.xlim(left=0)
    plt.ylim(bottom=10**1)
    plt.yscale("log")
    # plt.legend(loc="upper center", ncol=3)
    plt.xlabel("Total number of active hours")
    plt.ylabel("Peak queries per hour")
    plt.title(f"{loc} - pkts_max")
    plt.show()
    Path("./query-rate/").mkdir(parents=True, exist_ok=True)
    plt.savefig(f"./query-rate/{loc}-pkts-max.svg")

    plt.clf()
    # border_x, border_y = calculate_border(
    #     sum(list_pkts_sum[loc]),
    #     list_active_hours[loc],
    #     list_pkts_sum[loc],
    #     list_pkts_avg[loc],
    # )
    counts, xedges, yedges, im = plt.hist2d(
        l_active_hours,
        list_pkts_avg[loc],
        label=f"{loc} - pkts_avg",
        bins=bins,
        norm=norm,
    )
    plt.colorbar(im, label="Number of source networks")
    plt.xlim(left=0)
    plt.ylim(bottom=10**1)
    plt.yscale("log")
    # plt.legend(loc="upper center", ncol=3)
    plt.xlabel("Total number of active hours")
    plt.ylabel("Average packets per hour during active periods    ")
    # plt.title(f"{loc.value} - pkts_avg")
    Path("./query-rate/").mkdir(parents=True, exist_ok=True)
    plt.savefig(f"./query-rate/{loc}-pkts-avg.svg")
    plt.show()
