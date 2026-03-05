#!/usr/bin/env python3
"""
generate_plots.py

Usage:
  python generate_plots.py

Put your data file path in INPUT_PATH below. The file can be .xlsx or .csv.
Expected columns (case-insensitive):
  - Sec
  - Core Count
  - Packet Size (Bytes)  OR Packet Size
  - TX pps
  - RX pps
  - TX Mbps
  - RX Mbps
Optional / derived:
  - RX Gbps (Calculated)  (if not present we compute from RX Mbps)
  - pps / core (if not present we compute as RX pps / Core Count)

Outputs: plots saved under ./plots/
"""

import os
import sys
import math
import argparse
from pathlib import Path
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# -------- USER CONFIG ----------
INPUT_PATH = "./latency/plot_scripts/SmartNIC_Core_Scaling_Throughput_Template.xlsx"
OUTPUT_DIR = "plots"
LINE_RATE_GBPS = 100.0   # 100G link
FIG_DPI = 200
# --------------------------------

def load_table(path):
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Input file not found: {path}")
    if p.suffix.lower() in [".xlsx", ".xls"]:
        df = pd.read_excel(p)
    elif p.suffix.lower() == ".csv":
        df = pd.read_csv(p)
    else:
        raise ValueError("Unsupported file type. Use .xlsx/.xls/.csv")
    return df

def normalize_columns(df):
    # normalize column names to a consistent set of keys
    cols = {c.lower().strip(): c for c in df.columns}
    lookup = {}
    # common column variants mapping
    mapping = {
        "sec": ["sec", "second", "s"],
        "core_count": ["core count", "cores", "core_count", "corecount"],
        "packet_size": ["packet size (bytes)", "packet size", "pkt size", "packet_size", "pkt_size"],
        "tx_pps": ["tx pps", "tx_pps", "txpps", "tx p/s", "tx pps "],
        "rx_pps": ["rx pps", "rx_pps", "rxpps", "rx p/s"],
        "tx_mbps": ["tx mbps", "tx_mbps", "txmbps"],
        "rx_mbps": ["rx mbps", "rx_mbps", "rxmbps"],
        "rx_gbps": ["rx gbps (calculated)", "rx gbps", "rx_gbps", "rx_gbps (calculated)"],
        "pps_per_core": ["pps / core", "pps_per_core", "pps/core", "pps per core"]
    }
    for logical, variants in mapping.items():
        for v in variants:
            if v in cols:
                lookup[logical] = cols[v]
                break
    # return mapping to actual columns in df
    return lookup

def prepare_dataframe(df):
    lookup = normalize_columns(df)

    # create canonical columns where possible
    def col(name):
        return lookup.get(name)

    # Ensure numeric types
    # Packet size
    ps_col = col("packet_size")
    if ps_col is None:
        raise ValueError("No packet size column found. Expected 'Packet Size (Bytes)' or similar.")
    df = df.copy()
    df[ps_col] = pd.to_numeric(df[ps_col], errors="coerce").astype('Int64')

    # Core count
    core_col = col("core_count")
    if core_col is None:
        # If core count absent, assume single-core?
        raise ValueError("No 'Core Count' column found. Please provide core count per row.")
    df[core_col] = pd.to_numeric(df[core_col], errors="coerce").astype('Int64')

    # RX/Tx pps and Mbps
    for k in ("tx_pps", "rx_pps", "tx_mbps", "rx_mbps"):
        c = col(k)
        if c is not None:
            df[c] = pd.to_numeric(df[c], errors="coerce")

    # Compute RX Gbps from RX Mbps if missing
    rx_gb_col = col("rx_gbps")
    rx_mbps_col = col("rx_mbps")
    if rx_gb_col is None:
        if rx_mbps_col is None:
            raise ValueError("Missing both RX Mbps and RX Gbps columns; cannot compute throughput.")
        df["RX Gbps (Calculated)"] = df[rx_mbps_col] / 1000.0
        rx_gb_name = "RX Gbps (Calculated)"
    else:
        df[rx_gb_col] = pd.to_numeric(df[rx_gb_col], errors="coerce")
        rx_gb_name = rx_gb_col

    # Compute pps per core if missing
    pps_core_col = col("pps_per_core")
    rx_pps_col = col("rx_pps")
    if pps_core_col is None:
        if rx_pps_col is None:
            raise ValueError("Missing RX pps column; cannot compute pps per core.")
        df["pps_per_core"] = df[rx_pps_col] / df[core_col]
        pps_core_name = "pps_per_core"
    else:
        df[pps_core_col] = pd.to_numeric(df[pps_core_col], errors="coerce")
        pps_core_name = pps_core_col

    # rename for ease
    canonical = {
        core_col: "Core Count",
        ps_col: "Packet Size (Bytes)",
    }
    if rx_pps_col: canonical[rx_pps_col] = "RX pps"
    if col("tx_pps"): canonical[col("tx_pps")] = "TX pps"
    if rx_mbps_col: canonical[rx_mbps_col] = "RX Mbps"
    if col("tx_mbps"): canonical[col("tx_mbps")] = "TX Mbps"
    canonical[rx_gb_name] = "RX Gbps"
    canonical[pps_core_name] = "pps_per_core"

    df = df.rename(columns=canonical)
    # drop rows with NaN in required fields
    df = df.dropna(subset=["Core Count", "Packet Size (Bytes)", "RX Gbps", "pps_per_core"])
    df["Core Count"] = df["Core Count"].astype(int)
    df["Packet Size (Bytes)"] = df["Packet Size (Bytes)"].astype(int)
    return df

def ensure_outdir(path):
    os.makedirs(path, exist_ok=True)

def save_fig(fig, name):
    ensure_outdir(OUTPUT_DIR)
    png = os.path.join(OUTPUT_DIR, f"{name}.png")
    pdf = os.path.join(OUTPUT_DIR, f"{name}.pdf")
    fig.savefig(png, dpi=FIG_DPI, bbox_inches="tight")
    fig.savefig(pdf, dpi=FIG_DPI, bbox_inches="tight")
    print(f"Saved: {png} and {pdf}")

def plot_throughput_vs_pktsize(df):
    # 1️⃣ Throughput vs Packet Size (multi-core lines)
    fig, ax = plt.subplots(figsize=(7,4))
    for cores in sorted(df["Core Count"].unique()):
        sub = df[df["Core Count"]==cores]
        avg = sub.groupby("Packet Size (Bytes)")["RX Gbps"].mean().sort_index()
        ax.plot(avg.index, avg.values, marker='o', linewidth=1, label=f"{cores} cores")
    ax.set_xlabel("Packet Size (Bytes)")
    ax.set_ylabel("RX Throughput (Gbps)")
    ax.set_title("Throughput vs Packet Size (per core count)")
    ax.grid(True, linewidth=0.3)
    ax.legend(loc="best", fontsize="small")
    save_fig(fig, "throughput_vs_packet_size")
    plt.close(fig)

def plot_throughput_vs_corecount(df):
    # 2️⃣ Throughput vs Core Count (for each packet size)
    fig, ax = plt.subplots(figsize=(7,4))
    for pkt in sorted(df["Packet Size (Bytes)"].unique()):
        sub = df[df["Packet Size (Bytes)"]==pkt]
        avg = sub.groupby("Core Count")["RX Gbps"].mean().sort_index()
        ax.plot(avg.index, avg.values, marker='o', linewidth=1, label=f"{pkt} B")
    ax.set_xlabel("Core Count")
    ax.set_ylabel("RX Throughput (Gbps)")
    ax.set_title("Throughput vs Core Count (per packet size)")
    ax.grid(True, linewidth=0.3)
    ax.legend(loc="best", fontsize="small")
    save_fig(fig, "throughput_vs_corecount")
    plt.close(fig)

def plot_scaling_efficiency(df):
    # 3️⃣ Scaling Efficiency Plot
    fig, ax = plt.subplots(figsize=(7,4))
    for pkt in sorted(df["Packet Size (Bytes)"].unique()):
        sub = df[df["Packet Size (Bytes)"]==pkt]
        avg = sub.groupby("Core Count")["RX Gbps"].mean().sort_index()
        if 1 not in avg.index:
            # use minimum core count as baseline if 1-core absent
            baseline_cores = avg.index.min()
            base = avg.loc[baseline_cores]
            denom = avg.index * base
            eff = avg / denom
            ax.plot(avg.index, eff.values, marker='o', linewidth=1, label=f"{pkt} B")
        else:
            base = avg.loc[1]
            denom = avg.index * base
            eff = avg / denom
            ax.plot(avg.index, eff.values, marker='o', linewidth=1, label=f"{pkt} B")
    ax.set_xlabel("Core Count")
    ax.set_ylabel("Scaling Efficiency (Throughput / (N * 1-core throughput))")
    ax.set_title("Scaling Efficiency vs Core Count")
    ax.grid(True, linewidth=0.3)
    ax.legend(loc="best", fontsize="small")
    save_fig(fig, "scaling_efficiency")
    plt.close(fig)

def plot_pps_per_core(df):
    # 4️⃣ PPS per Core vs Packet Size
    fig, ax = plt.subplots(figsize=(7,4))
    for cores in sorted(df["Core Count"].unique()):
        sub = df[df["Core Count"]==cores]
        avg = sub.groupby("Packet Size (Bytes)")["pps_per_core"].mean().sort_index()
        ax.plot(avg.index, avg.values, marker='o', linewidth=1, label=f"{cores} cores")
    ax.set_xlabel("Packet Size (Bytes)")
    ax.set_ylabel("PPS per core")
    ax.set_title("PPS per Core vs Packet Size")
    ax.grid(True, linewidth=0.3)
    ax.legend(loc="best", fontsize="small")
    save_fig(fig, "pps_per_core_vs_packet_size")
    plt.close(fig)

def plot_heatmap(df):
    # 5️⃣ Heatmap (Core Count x Packet Size -> RX Gbps)
    pivot = df.groupby(["Core Count", "Packet Size (Bytes)"])["RX Gbps"].mean().unstack(fill_value=np.nan)
    fig, ax = plt.subplots(figsize=(8,6))
    im = ax.imshow(pivot.values, aspect='auto', origin='lower')
    ax.set_xticks(np.arange(len(pivot.columns)))
    ax.set_xticklabels([str(c) for c in pivot.columns], rotation=45)
    ax.set_yticks(np.arange(len(pivot.index)))
    ax.set_yticklabels([str(c) for c in pivot.index])
    ax.set_xlabel("Packet Size (Bytes)")
    ax.set_ylabel("Core Count")
    ax.set_title("RX Throughput Heatmap (Gbps)")
    fig.colorbar(im, ax=ax)
    save_fig(fig, "throughput_heatmap")
    plt.close(fig)

def compute_and_print_summary(df):
    # print a small summary table (average per packet size & core)
    group = df.groupby(["Core Count", "Packet Size (Bytes)"]).agg(
        rx_gbps_mean=("RX Gbps", "mean"),
        rx_pps_mean=("RX pps", "mean") if "RX pps" in df.columns else ("RX Gbps", "mean"),
        pps_per_core_mean=("pps_per_core", "mean")
    ).reset_index()
    print("\nSummary (snippet):")
    print(group.head(20).to_string(index=False))

def main():
    print("Loading:", INPUT_PATH)
    df_raw = load_table(INPUT_PATH)
    df = prepare_dataframe(df_raw)
    ensure_outdir(OUTPUT_DIR)
    compute_and_print_summary(df)
    # Create plots
    plot_throughput_vs_pktsize(df)
    plot_throughput_vs_corecount(df)
    plot_scaling_efficiency(df)
    plot_pps_per_core(df)
    plot_heatmap(df)
    print("All plots generated under:", OUTPUT_DIR)

if __name__ == "__main__":
    main()
