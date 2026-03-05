#!/usr/bin/env python3

import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.ticker import LogLocator, FuncFormatter

# =========================
# Configuration
# =========================

# Base directory where CSV files live
BASE_DIR = "./latency/final"

files = {
    "YouTube": "youtube_latency_final.csv",
    "Facebook": "facebook_latency_final.csv",
    "Instagram": "instagram_latency_final.csv",
    "LinkedIn": "linkedin_latency_final.csv",
    "Spotify": "spotify_latency_final.csv",
    "TikTok": "tiktok_latency_final.csv",
    "Twitter": "twitter_latency_final.csv",
    "Wikipedia": "wikipedia_latency_final.csv",
}

# If you prefer a hard visual window, set XVIEW_US to a number (µs).
# Otherwise set XVIEW_US = None to compute from data (we compute it automatically below).
XVIEW_US = None

# Percentile used to pick the view window when XVIEW_US is None (e.g. 99 for 99th percentile)
VIEW_PERCENTILE = 99
# Extra padding multiplier to give a little breathing room after percentile
PADDING_MULT = 1.10

# Plot appearance
FIGSIZE = (5, 2)
LINEWIDTH = 2.2
LEGEND_FONT_SZ = 12
LABEL_FONT_SZ = 16
TICK_FONT_SZ = 18

# -------------------------
# Helpers
# -------------------------
def compute_cdf(arr):
    """Return sorted array and empirical CDF in percent (0-100)."""
    arr_sorted = np.sort(arr)
    cdf = np.arange(1, len(arr_sorted) + 1) / len(arr_sorted)
    return arr_sorted, cdf * 100.0  # percent

# -------------------------
# Read data and compute full CDFs
# -------------------------
all_vals_list = []
curves = {}  # app -> (x_full, cdf_full)

for app, filename in files.items():
    path = os.path.join(BASE_DIR, filename)
    if not os.path.exists(path):
        print(f"[WARN] Missing file: {path}")
        continue

    df = pd.read_csv(path)
    if "delta_0_us" not in df.columns:
        print(f"[WARN] delta_0_us not found in {filename}")
        continue

    vals = pd.to_numeric(df["delta_0_us"].dropna(), errors="coerce").values
    vals = vals[~np.isnan(vals)]
    # semilogx requires strictly positive x values
    vals = vals[vals > 0]

    if vals.size == 0:
        print(f"[WARN] No valid latency values in {filename}")
        continue

    x_full, cdf_full = compute_cdf(vals)
    curves[app] = (x_full, cdf_full)
    all_vals_list.append(vals)

    # Print percentiles for quick reference
    p50 = np.percentile(vals, 50)
    p95 = np.percentile(vals, 95)
    p99 = np.percentile(vals, 99)
    print(f"[STATS] {app}: 50th={p50:.3f} µs, 95th={p95:.3f} µs, 99th={p99:.3f} µs")

if not curves:
    raise SystemExit("[ERROR] No data found. Check BASE_DIR and CSV files.")

# -------------------------
# Determine view window (XVIEW_US) automatically if not provided
# -------------------------
if XVIEW_US is None:
    all_vals = np.concatenate(all_vals_list)
    # pick percentile and add padding
    XVIEW_US = float(np.percentile(all_vals, VIEW_PERCENTILE) * PADDING_MULT)
    # make sure XVIEW_US is at least a small number > 1
    XVIEW_US = max(XVIEW_US, 5.0)
    print(f"[INFO] Auto XVIEW_US set to the {VIEW_PERCENTILE}th percentile * {PADDING_MULT:.2f} = {XVIEW_US:.1f} µs")

# -------------------------
# Build plot
# -------------------------
fig, ax = plt.subplots(figsize=FIGSIZE)

# Plot full CDFs (do not truncate arrays) so curves reach 100%
for app, (x_full, cdf_full) in curves.items():
    # compute how many values are beyond the view window (for optional annotation)
    n_beyond = int((x_full > XVIEW_US).sum())
    label = app
    ax.semilogx(x_full, cdf_full, label=label, linewidth=LINEWIDTH)

# Layout & labels
ax.set_xlabel("Feature Extraction Latency (µs)", fontsize=LABEL_FONT_SZ)
ax.set_ylabel("CDF (%)", fontsize=LABEL_FONT_SZ)
ax.set_ylim(-3, 105)
ax.grid(True, which="major", linestyle="-", linewidth=0.9, alpha=0.6)
# enable minor grid lightly
ax.grid(True, which="minor", linestyle="-", linewidth=0.5, alpha=0.25)
ax.margins(x=0.01, y=0.01)

# -------------------------
# X ticks: choose human-friendly ticks within data range
# -------------------------
# Preferred tick candidates (µs). You can expand/contract this list as needed.
preferred_ticks = [2, 10, 90]

# Determine data bounds
data_min = max(1.0, min(v.min() for v in all_vals_list) * 0.8)
data_max = max(v.max() for v in all_vals_list)

# Filter and use preferred ticks that fall in the plotting interval [data_min, XVIEW_US]
ticks = [t for t in preferred_ticks if (t >= data_min and t <= XVIEW_US)]
if len(ticks) < 2:
    # fallback to log locator when preferred ticks don't produce a reasonable set
    ax.xaxis.set_major_locator(LogLocator(base=10.0))
else:
    ax.set_xticks(ticks)

# Format tick labels as integers (no scientific notation)
ax.xaxis.set_major_formatter(FuncFormatter(lambda x, pos: f"{int(x)}"))

ax.tick_params(axis='both', which='major', labelsize=TICK_FONT_SZ)
ax.tick_params(axis='both', which='minor', labelsize=max(8, int(TICK_FONT_SZ * 0.75)), length=4)

# Visual-only x-limits (show full curves but zoom the view)
left = max(1.0, data_min)
right = XVIEW_US
if right <= left:
    # safety fallback to auto-range if something odd happens
    ax.set_xlim(left, max(data_max, left * 2.0))
else:
    ax.set_xlim(left=1, right=200)

xmin, xmax = ax.get_xlim()

ax.set_xlim(
    left=xmin * 0.8,   # 20% space on left
    right=xmax * 1.1   # 10% space on right
)

# Legend (top center)
fig.legend(loc="upper center", bbox_to_anchor=(0.5, 1.05),
           ncol=3, fontsize=LEGEND_FONT_SZ, frameon=True, handlelength=2.6)

plt.subplots_adjust(left=0.06, right=0.99, top=0.90, bottom=0.12)
plt.show()
