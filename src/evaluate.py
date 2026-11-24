import pandas as pd

from detect import ALL_RULES, prepare
from inject import build

real = pd.read_pickle("data/flaws.pkl")
events, scenarios = build()
syn = pd.DataFrame(events)
syn["eventTime"] = pd.to_datetime(syn["eventTime"], utc=True)

df = prepare(pd.concat([real, syn], ignore_index=True))
alerts = pd.concat([rule(df) for rule in ALL_RULES], ignore_index=True)

rows = []
for s in scenarios:
    hit = alerts[alerts["sourceIPAddress"] == s["ip"]]
    rows.append({"id": s["id"], "scenario": s["name"],
                 "detected": len(hit) > 0,
                 "rules": ", ".join(sorted(hit["rule"].unique()))})

res = pd.DataFrame(rows)
res.to_csv("results/synthetic_eval.csv", index=False)
print(res.to_string(index=False))
print(f"\nDetected {res['detected'].sum()} of {len(res)} ({res['detected'].mean():.0%})")