import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

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

# files = {
#     "Discord": "discord_latency_final.csv",
#     "Whatsapp": "whatsapp_latency_final.csv",
#     "Teams": "teams_latency_final.csv",
#     "Signal": "signal_latency_final.csv",
#     "Telegram": "telegram_latency_final.csv",
#     "Messenger": "messenger_latency_final.csv",
# }

# =========================
# Helpers
# =========================

def compute_cdf(arr):
    """Return sorted array and empirical CDF in percent (0-100)."""
    arr_sorted = np.sort(arr)
    cdf = np.arange(1, len(arr_sorted) + 1) / len(arr_sorted)
    return arr_sorted, cdf * 100.0  # percent

# =========================
# Plot
# =========================

fig, axs = plt.subplots(figsize=(5, 2))

any_plotted = False

for app, filename in files.items():
    path = os.path.join(BASE_DIR, filename)

    if not os.path.exists(path):
        print(f"[WARN] Missing file: {path}")
        continue

    df = pd.read_csv(path)

    # change to delta_3 for multimedia apps

    if "delta_3" not in df.columns:
        print(f"[WARN] delta_3 not found in {filename}")
        continue

    latency_ms = pd.to_numeric(
        df["delta_3"].dropna(), errors="coerce"
    ).values

    latency_ms = latency_ms[~np.isnan(latency_ms)]

    # # ===== REQUIRED for log-x =====
    # latency_ms = latency_ms[latency_ms > 0]

    if latency_ms.size == 0:
        print(f"[WARN] No valid latency values in {filename}")
        continue

    x, cdf_percent = compute_cdf(latency_ms)

    # ===== CHANGE: semilogx instead of plot =====
    axs.semilogx(x, cdf_percent, label=app, linewidth=2)

    # Optional: print percentiles (useful for paper tables)
    p50 = np.percentile(latency_ms, 50)
    p95 = np.percentile(latency_ms, 95)
    p99 = np.percentile(latency_ms, 99)
    print(
        f"[STATS] {app}: "
        f"50th={p50:.3f} µs, "
        f"95th={p95:.3f} µs, "
        f"99th={p99:.3f} µs"
    )

    any_plotted = True

if not any_plotted:
    print("[ERROR] No data plotted. Check BASE_DIR and CSV files.")
else:
    # Legend (unchanged)
    fig.legend(
        loc="upper center",
        bbox_to_anchor=(0.5, 0.99),
        ncol=2,
        fontsize=14,
        frameon=True,
        handlelength=2.8,
        columnspacing=2.8
    )

    plt.subplots_adjust(
        left=0.12,
        right=0.98,
        bottom=0.12,
        top=0.85
    )

    axs.set_xlabel("Application classification Inference Time (µs)", fontsize=20)
    axs.set_ylabel("CDF (%)", fontsize=20)

    axs.set_yticks(np.arange(0, 101, 25))
    axs.tick_params(axis='both', which='major', labelsize=18)

    # ===== Grid updated for log scale (no visual size change) =====
    axs.grid(True, which="both", linestyle="-", alpha=1.0)

    # Small visual gap from borders
    axs.margins(x=0.02, y=0.03)
    axs.set_xlim(left=2)

    axs.xaxis.get_offset_text().set_fontsize(8)

    plt.subplots_adjust(left=0.12, right=0.98, bottom=0.12, top=0.80)

    # Save or show
    # plt.savefig("feature_extraction_cdf_logx.pdf",
    #             bbox_inches="tight", dpi=700)
    plt.show()
