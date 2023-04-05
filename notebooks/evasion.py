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
# # Plot the impact of evasion IPs on the overall traffic
#
# This takes the pre-aggregated values per configuration and plots the Traffic and FPR in relation to the number of evasion IP addresses.

# %%
import json
from collections import defaultdict

import common_functions
import matplotlib.pyplot as plt

# # %matplotlib ipympl
# %matplotlib inline

# %%
common_functions.matplotlib_better_lines()
# plt.rcParams["figure.figsize"] = (10, 7)
plt.rcParams["figure.figsize"] = (7, 4)
plt.rcParams["figure.dpi"] = 200
plt.rcParams["savefig.bbox"] = "tight"
plt.rcParams["figure.autolayout"] = True

# %%
with open("./results_evasion.json") as f:
    data = json.load(f)

# location -> evasion_ips -> (attack_traffic, fpr)
aggregated: dict[str, dict[int, tuple[float, float]]] = defaultdict(dict)
for d in data:
    aggregated[d["location"]][d["evasion_ips"]] = (d["attack_traffic"] / 3600, d["fpr"])

# %%
for loc, locdata in aggregated.items():
    evasionips = list(sorted(locdata.keys()))
    attack_traffic = [locdata[eips][0] for eips in evasionips]
    plt.plot(evasionips, attack_traffic, label=loc)
plt.xlim(left=0)
plt.ylim(bottom=1000)
plt.xlabel("Attacker IPs on allowlist")
plt.ylabel("Attack traffic in packets per second")
plt.savefig("./evasion-ips.svg")
plt.show()

for loc, locdata in aggregated.items():
    evasionips = list(sorted(locdata.keys()))
    fpr = [locdata[eips][1] for eips in evasionips]
    plt.plot(evasionips, fpr, label=loc)
plt.xlim(left=0)
plt.ylim(bottom=0)
plt.show()
