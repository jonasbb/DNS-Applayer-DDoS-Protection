# ---
# jupyter:
#   jupytext:
#     formats: ipynb,py:percent
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

# %% [markdown] tags=[]
# # About
#
# This notebook contains Python functions common between multiple notebooks.
# Thanks to jupytext, this notebook can be imported as `import common_functions` or `from common_functions import *`.

# %%
from __future__ import annotations

import sys


# %%
def matplotlib_better_lines(*, markevery=True, linestyles=True, markers=True) -> None:  # type: ignore
    """
    Set matplotlib to use nicer lines and markers.

    Individual features can be disabled by setting the keyword argument to `False`.
    For example, the `markevery` attribute can sometimes cause problems.
    """

    import matplotlib.pyplot as plt  # pylint: disable=import-outside-toplevel
    from matplotlib.rcsetup import cycler  # pylint: disable=import-outside-toplevel

    # https://stackoverflow.com/a/51716959
    try:
        from math import lcm  # type: ignore # pylint: disable=import-outside-toplevel
    except:  # pylint: disable=bare-except
        import math  # pylint: disable=import-outside-toplevel

        def lcm(a: int, b: int) -> int:  # type: ignore
            return abs(a * b) // math.gcd(a, b)

    def cyclers_add(cyc_a: cycler, cyc_b: cycler) -> cycler:  # type: ignore
        """
        Add two cyclers of different lengths.

        https://github.com/matplotlib/cycler/issues/41#issuecomment-279803761
        """
        mult = lcm(len(cyc_a), len(cyc_b))
        return cyc_a * (mult // len(cyc_a)) + cyc_b * (mult // len(cyc_b))

    markevery = cycler(markevery=[0.1])
    # Least common multiple lcm(4,5,9) = 180 is the highest combination
    # *4* distinct linestyles
    linestyles = cycler(linestyle=["-", "--", ":", "-."])
    # *5* different markers
    markers = cycler(
        marker=[
            ".",  # point
            "*",  # start
            "x",  # x
            "d",  # thin diamond
            "|",  # vline
        ]
    )
    # First *9* default colors
    colors = cycler(
        color=[
            "#1f77b4",
            "#ff7f0e",
            "#2ca02c",
            "#d62728",
            "#9467bd",
            "#8c564b",
            "#e377c2",
            "#7f7f7f",
            "#bcbd22",
            # "#17becf",
        ]
    )

    c = colors
    if markevery:
        c = cyclers_add(c, markevery)
    if linestyles:
        c = cyclers_add(c, linestyles)
    if markers:
        c = cyclers_add(c, markers)

    plt.rcParams["axes.prop_cycle"] = c


# %%
# https://github.com/tinybike/weightedstats/blob/master/weightedstats/__init__.py
def median(data: list[float]) -> float:
    """Calculate the median of a list."""
    data.sort()
    num_values = len(data)
    half = num_values // 2
    if num_values % 2:
        return data[half]
    return 0.5 * (data[half - 1] + data[half])


def weighted_median(data: list[float], weights: list[float] | None = None) -> float:
    """Calculate the weighted median of a list."""
    if weights is None:
        return median(data)
    midpoint = 0.5 * sum(weights)
    if any(j > midpoint for j in weights):
        return data[weights.index(max(weights))]
    if any(j > 0 for j in weights):
        sorted_data: tuple[float]
        sorted_weights: tuple[float]
        sorted_data, sorted_weights = zip(*sorted(zip(data, weights)))  # type: ignore
        cumulative_weight: float = 0
        below_midpoint_index = 0
        while cumulative_weight <= midpoint:
            below_midpoint_index += 1
            cumulative_weight += sorted_weights[below_midpoint_index - 1]
        cumulative_weight -= sorted_weights[below_midpoint_index - 1]
        if abs(cumulative_weight - midpoint) < sys.float_info.epsilon:
            bounds: tuple[float, ...] = sorted_data[
                below_midpoint_index - 2 : below_midpoint_index
            ]
            return sum(bounds) / float(len(bounds))
        return sorted_data[below_midpoint_index - 1]

    raise ValueError("All weights are zero or negative.")
