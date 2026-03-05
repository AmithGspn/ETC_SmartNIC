#!/usr/bin/env python3
"""
Plot CDF (semilog-x) of feature-extraction latency in microseconds (µs).
- Reads `delta_0_us` column from CSV files in BASE_DIR.
- Plots full CDF for each app (so every curve reaches 100%).
- Sets a zoomed x-axis that covers the 99th percentile (with a small padding).
- Uses human-friendly x ticks and clean, publication-ready styling.
"""
import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.ticker import LogLocator, FuncFormatter

# -------------------------
# Configuration
# -------------------------
BASE_DIR = "./latency/final"

files = {
    "Discord": "discord_latency_final.csv",
    "Whatsapp": "whatsapp_latency_final.csv",
    "Teams": "teams_latency_final.csv",
    "Signal": "signal_latency_final.csv",
    "Telegram": "telegram_latency_final.csv",
    "Messenger": "messenger_latency_final.csv",
}

# If you prefer a hard visual window, set XVIEW_US to a number (µs).
# Otherwise set XVIEW_US = None to compute from data (we compute it automatically below).
XVIEW_US = None

# Percentile used to pick the view window when XVIEW_US is None (e.g. 99 for 99th percentile)
VIEW_PERCENTILE = 99
# Extra padding multiplier to give a little breathing room after percentile
PADDING_MULT = 1.10

# Plot appearance
FIGSIZE = (5, 2)     # increased for readability
LINEWIDTH = 2.2
LEGEND_FONT_SZ = 12
LABEL_FONT_SZ = 16
TICK_FONT_SZ = 18       # used now for tick labels

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

color_map = {
    "Discord": "#bcbd22",
    "Whatsapp": "#17becf",
    "Teams": "#393b79",
    "Signal": "#637939",
    "Telegram": "#8c6d31",
    "Messenger": "#843c39",
}

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
    ax.semilogx(
        x_full,
        cdf_full,
        label=app,
        linewidth=LINEWIDTH,
        color=color_map.get(app, None)  # fallback to default if missing
    )

# Layout & labels
ax.set_xlabel("Feature Extraction Latency (µs)", fontsize=LABEL_FONT_SZ)
ax.set_ylabel("CDF (%)", fontsize=LABEL_FONT_SZ)
ax.set_ylim(-3, 105)   # small gap below 0 and above 100
ax.grid(True, which="major", linestyle="-", linewidth=0.9, alpha=0.6)
# enable minor grid lightly
ax.grid(True, which="minor", linestyle="-", linewidth=0.5, alpha=0.25)
ax.margins(x=0.02, y=0.02)

# Fixed colors (consistent across runs)


# -------------------------
# X tick handling for log scale: major + minor ticks
# -------------------------
# Major locator: powers of 10
ax.xaxis.set_major_locator(LogLocator(base=10.0, numticks=12))
# Minor locator: show 2..9 subdivisions so ticks at 2,3,4...9, then 20,30...
ax.xaxis.set_minor_locator(LogLocator(base=10.0, subs=np.arange(2, 10), numticks=12))

# Choose readable major tick formatter (show plain numbers)
ax.xaxis.set_major_formatter(FuncFormatter(lambda x, pos: f"{int(x)}" if x >= 1 else f"{x:.1f}"))

# If you prefer a custom subset of tick labels, you can override like this:
# preferred_ticks = [2, 5, 10, 20, 50, 100]
# ax.set_xticks(preferred_ticks)
# ax.set_xticklabels([str(t) for t in preferred_ticks])

# Apply tick font sizes
ax.tick_params(axis='both', which='major', labelsize=TICK_FONT_SZ)
ax.tick_params(axis='both', which='minor', labelsize=max(8, int(TICK_FONT_SZ * 0.75)), length=4)

# Visual-only x-limits (show full curves but zoom the view)
left = max(1.0, min(v.min() for v in all_vals_list) * 0.8)
right = XVIEW_US
if right <= left:
    ax.set_xlim(left, max(np.max(all_vals_list[0]), left * 2.0))
else:
    # you previously used right=200; keep flexible but set to computed view
    ax.set_xlim(left=1.0, right=max(right, 200.0))  # ensure you can show up to 200 if desired

# Legend (top center) with consistent font size
fig.legend(loc="upper center", bbox_to_anchor=(0.5, 0.98),
           ncol=3, fontsize=LEGEND_FONT_SZ, frameon=True, handlelength=2.6)

plt.subplots_adjust(left=0.08, right=0.99, top=0.90, bottom=0.12)
plt.show()
