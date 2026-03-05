import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import glob
import re
from matplotlib.colors import LinearSegmentedColormap

# -------------------------------------------------
# CONFIG
# -------------------------------------------------
INPUT_PATTERN = "./Throughput_results/*_results.xlsx"
OUTPUT_FILE = "rx_gbps_heatmap_packetY_coreX.png"
FIG_DPI = 200
# -------------------------------------------------

# Custom colormap
custom_cmap = LinearSegmentedColormap.from_list(
    "im",
    ['#f1f8e9', '#a5d6a7', '#66bb6a']
)

# Find all result files
files = glob.glob(INPUT_PATTERN)

if not files:
    raise FileNotFoundError("No *_results.xlsx files found.")

all_data = []

for file in files:
    print("Reading:", file)

    # Extract core count from filename
    match = re.search(r'(\d+)', file)
    if not match:
        raise ValueError(f"Cannot infer core number from {file}")
    core_count = int(match.group(1))

    df = pd.read_excel(file)

    # Remove commas if present
    for col in df.columns:
        if df[col].dtype == object:
            df[col] = df[col].astype(str).str.replace(",", "")

    df["Packet Size (Bytes)"] = pd.to_numeric(df["Packet Size (Bytes)"], errors="coerce")
    df["RX Gbps (Calculated)"] = pd.to_numeric(df["RX Gbps (Calculated)"], errors="coerce")

    grouped = df.groupby("Packet Size (Bytes)")["RX Gbps (Calculated)"].mean()

    for pkt_size, rx_gbps in grouped.items():
        all_data.append({
            "Core Count": core_count,
            "Packet Size (Bytes)": int(pkt_size),
            "RX Gbps": rx_gbps
        })

# Build DataFrame
data_df = pd.DataFrame(all_data)

pivot = data_df.pivot(index="Packet Size (Bytes)",
                      columns="Core Count",
                      values="RX Gbps")

pivot = pivot.sort_index()
pivot = pivot.reindex(sorted(pivot.columns), axis=1)

print("\nPivot Table:\n")
print(pivot)

# -------------------------------------------------
# Plot Heatmap
# -------------------------------------------------

fig, ax = plt.subplots(figsize=(6, 4))

im = ax.imshow(
    pivot.values,
    aspect='auto',
    origin='lower',
    cmap=custom_cmap   # 👈 Custom colormap applied here
)

ax.set_xticks(np.arange(len(pivot.columns)))
ax.set_xticklabels(pivot.columns, fontsize=12)

ax.set_yticks(np.arange(len(pivot.index)))
ax.set_yticklabels(pivot.index, fontsize=12)

ax.set_xlabel("Core Count", fontsize=14)
ax.set_ylabel("Packet Size (Bytes)", fontsize=14)

# ax.set_title("Mean RX Throughput (Gbps)")

# Annotate values
for i in range(pivot.shape[0]):
    for j in range(pivot.shape[1]):
        val = pivot.iat[i, j]
        ax.text(j, i, f"{val:.0f}", ha="center", va="center", fontsize=13)

cbar = fig.colorbar(im, ax=ax)
cbar.ax.tick_params(labelsize=14)
cbar.set_label("Throughput (Gbps)", fontsize=14)

# Remove heatmap border
for spine in ax.spines.values():
    spine.set_visible(False)

# Remove colorbar border
cbar.outline.set_visible(False)

plt.tight_layout()
plt.savefig(OUTPUT_FILE, dpi=FIG_DPI)
plt.show()

print("\nSaved to:", OUTPUT_FILE)
