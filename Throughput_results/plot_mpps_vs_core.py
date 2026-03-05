import pandas as pd
import glob, os, re
import matplotlib.pyplot as plt

INPUT_FOLDER = "Throughput_results"
PATTERN = os.path.join(INPUT_FOLDER, "*_results.xlsx")

files = sorted(glob.glob(PATTERN))
data = []
for f in files:
    fname = os.path.basename(f)
    m = re.search(r'(\d+)_core', fname)
    cores = int(m.group(1)) if m else None
    df = pd.read_excel(f)
    # auto-detect columns
    col_pkt = next((c for c in df.columns if "packet" in str(c).lower()), None)
    col_tpps = next((c for c in df.columns if "tx" in str(c).lower() and "pps" in str(c).lower()), None)
    if col_pkt is None or col_tpps is None: 
        continue
    grouped = df.groupby(col_pkt)[col_tpps].mean()
    for pkt, pps in grouped.items():
        data.append({"cores": cores, "pkt": int(pkt), "mpps": float(pps)/1e6})

df_all = pd.DataFrame(data)
plt.figure(figsize=(10,5))
for pkt in sorted(df_all["pkt"].unique()):
    sub = df_all[df_all["pkt"]==pkt].sort_values("cores")
    plt.plot(sub["cores"], sub["mpps"], marker='o', label=f"{pkt} B")
plt.xlabel("Core Count")
plt.ylabel("Total throughput (Mpps)")
plt.title("Mpps vs Core Count")
plt.grid(alpha=0.3)
plt.legend(
    title="Packet size",
    bbox_to_anchor=(1.02, 1),
    loc="upper left",
    borderaxespad=0,
    fontsize=11,
    title_fontsize=12
)
plt.tight_layout()
plt.show()
