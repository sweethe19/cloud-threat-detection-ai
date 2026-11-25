import pandas as pd

from defenses import apply_floor, classify, is_poisoned

KNOWN = ["P1_override", "P2_authority", "P3_fake_output", "P4_deflect"]
HELDOUT = ["P5_heldout_paraphrase", "P6_heldout_french"]
ADAPTIVE = ["P7_valid_iam_name"]

none = pd.concat([pd.read_csv("results/injection_v1.csv"),
                  pd.read_csv("results/injection_v2_baseline.csv")], ignore_index=True)
none["config"] = "1. no defense"
spot = pd.read_csv("results/injection_v2_spotlight.csv")
spot["config"] = "2. spotlighting"
san = pd.read_csv("results/injection_v2_sanitize.csv")
san["config"] = "3. spotlighting + sanitization"

df = pd.concat([none, spot, san], ignore_index=True)
df["flagged"] = df["flagged"].fillna(False).astype(bool)
df["floor_outcome"] = [classify(*apply_floor(v, s, f))
                       for v, s, f in zip(df["verdict"], df["severity"], df["flagged"])]
df["poisoned"] = df["summary"].apply(is_poisoned)


def rate(d, payloads):
    d = d[d["payload"].isin(payloads) & (d["outcome"] != "error")]
    return f"{int((d['outcome'] == 'FOOLED').sum())}/{len(d)}" if len(d) else "n/a"


rows = []
for cfg, d in df.groupby("config"):
    pay = d[(d["payload"] != "control") & (d["outcome"] != "error")]
    ctrl = d[(d["payload"] == "control") & (d["outcome"] != "error")]
    rows.append({
        "config": cfg,
        "known P1-P4": rate(d, KNOWN),
        "held-out P5-P6": rate(d, HELDOUT),
        "adaptive P7": rate(d, ADAPTIVE),
        "fooled after floor": f"{int((pay['floor_outcome'] == 'FOOLED').sum())}/{len(pay)}",
        "summary poisoned": f"{int(pay['poisoned'].sum())}/{len(pay)}",
        "flagged": f"{int(pay['flagged'].sum())}/{len(pay)}",
        "controls held": f"{int((ctrl['outcome'] == 'held').sum())}/{len(ctrl)}",
    })

table = pd.DataFrame(rows)
print(table.to_string(index=False))
print("\nErrors:", int((df["outcome"] == "error").sum()))
table.to_csv("results/injection_summary.csv", index=False)