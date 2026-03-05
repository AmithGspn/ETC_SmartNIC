import pandas as pd
import glob, os, re

INPUT_FOLDER = "Throughput_results"
PATTERN = os.path.join(INPUT_FOLDER, "*_results.xlsx")
OUT_CSV = "throughput_summary.csv"

def safe_num(x):
    if pd.isna(x): return None
    s = str(x).replace(",", "").strip()
    try:
        return float(s)
    except:
        return None

rows = []

files = sorted(glob.glob(PATTERN))
if not files:
    raise SystemExit("No files found matching: " + PATTERN)

print("Found files (in order):")
for f in files:
    print("  ", os.path.basename(f))

for f in files:
    fname = os.path.basename(f)
    m = re.search(r'(\d+)_core', fname)
    core_count = int(m.group(1)) if m else None

    print(f"\nReading: {fname}  -> cores: {core_count}")

    df = pd.read_excel(f)

    # Try to detect column names similar to your sheet
    # Adjust names if your actual column headers differ
    col_pkt = None
    col_tpps = None
    for c in df.columns:
        cl = str(c).lower()
        if "packet" in cl and "size" in cl:
            col_pkt = c
        if "tx" in cl and "pps" in cl:
            col_tpps = c

    if col_pkt is None or col_tpps is None:
        print("  WARNING: could not automatically find packet-size or TX pps columns. Columns:", df.columns.tolist())
        continue

    df[col_pkt] = df[col_pkt].apply(safe_num)
    df[col_tpps] = df[col_tpps].apply(safe_num)
    grouped = df.dropna(subset=[col_pkt, col_tpps]).groupby(col_pkt)[col_tpps].mean()

    for pkt_size, pps in grouped.items():
        if pps is None: 
            continue
        mpps = pps / 1e6
        gbps = (pps * pkt_size * 8) / 1e9   # using packet size only; add overhead separately if desired
        rows.append({
            "file": fname,
            "cores": core_count,
            "packet_size": int(pkt_size),
            "tx_pps": pps,
            "tx_mpps": mpps,
            "tx_gbps": gbps
        })
        print(f"  {int(pkt_size):5d} B : {pps:12,.0f} pps  | {mpps:6.2f} Mpps | {gbps:6.2f} Gbps")

# Save CSV
df_out = pd.DataFrame(rows).sort_values(["packet_size", "cores"])
df_out.to_csv(OUT_CSV, index=False)
print(f"\nSaved summary to {OUT_CSV}")
