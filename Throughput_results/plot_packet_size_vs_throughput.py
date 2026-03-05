import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import glob
import re

# -------------------------------------------------
# CONFIG
# -------------------------------------------------
INPUT_PATTERN = "./Throughput_results/*_results.xlsx"
OUTPUT_FILE = "packet_size_vs_throughput.png"
FIG_DPI = 300
# -------------------------------------------------

files = glob.glob(INPUT_PATTERN)

if not files:
    raise FileNotFoundError("No *_results.xlsx files found.")

all_data = []

for file in files:
    print("Reading:", file)

    # Extract core number from filename
    match = re.search(r'(\d+)', file)
    if not match:
        raise ValueError(f"Cannot infer core number from {file}")
    core_count = int(match.group(1))

    df = pd.read_excel(file)

    # Clean commas
    for col in df.columns:
        if df[col].dtype == object:
            df[col] = df[col].astype(str).str.replace(",", "")

    df["Packet Size (Bytes)"] = pd.to_numeric(df["Packet Size (Bytes)"], errors="coerce")
    df["RX Gbps (Calculated)"] = pd.to_numeric(df["RX Gbps (Calculated)"], errors="coerce")

    grouped = df.groupby("Packet Size (Bytes)")["RX Gbps (Calculated)"].mean()

    for pkt_size, rx_gbps in grouped.items():
        all_data.append({
            "Core Count": core_count,
            "Packet Size": int(pkt_size),
            "RX Gbps": rx_gbps
        })

# Create DataFrame
data_df = pd.DataFrame(all_data)

# -------------------------------------------------
# Plot
# -------------------------------------------------

fig, ax = plt.subplots(figsize=(8, 5))

for core in sorted(data_df["Core Count"].unique()):
    subset = data_df[data_df["Core Count"] == core]
    subset = subset.sort_values("Packet Size")

    ax.plot(
        subset["Packet Size"],
        subset["RX Gbps"],
        marker='o',
        linewidth=2,
        label=f"{core} Cores"
    )

ax.set_xlabel("Packet Size (Bytes)", fontsize=14)
ax.set_ylabel("RX Throughput (Gbps)", fontsize=14)
ax.set_title("Packet Size vs Throughput", fontsize=16)

ax.tick_params(labelsize=12)

ax.grid(True, linestyle='--', alpha=0.4)
ax.legend(title="Core Count", fontsize=11)

plt.tight_layout()
plt.savefig(OUTPUT_FILE, dpi=FIG_DPI)
plt.show()

print("Saved to:", OUTPUT_FILE)
