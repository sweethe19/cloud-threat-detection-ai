import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from detect import ALL_RULES, prepare
from inject import build

NOISY = "amazonaws.com|AWS Internal"
KEYS = ["hour", "sourceIPAddress", "identityName"]
FEATURES = ["log_events", "unique_events", "unique_services",
            "unique_regions", "error_rate", "recon_share", "is_root"]


def featurize(df):
    d = df.copy()
    d["is_recon"] = d["eventName"].str.match(r"^(List|Describe|Get)", na=False)
    d["is_error"] = d["errorCode"] != ""
    d["is_root"] = d["identityType"] == "Root"
    g = d.groupby(KEYS, dropna=False)
    return pd.DataFrame({
        "log_events": np.log1p(g.size()),
        "unique_events": g["eventName"].nunique(),
        "unique_services": g["eventSource"].nunique(),
        "unique_regions": g["awsRegion"].nunique(),
        "error_rate": g["is_error"].mean(),
        "recon_share": g["is_recon"].mean(),
        "is_root": g["is_root"].max().astype(int),
    }).reset_index()


if __name__ == "__main__":
    real = prepare(pd.read_pickle("data/flaws.pkl"))
    real = real[~real["sourceIPAddress"].astype(str).str.contains(NOISY)]
    X = featurize(real)
    print("Training rows (IP/identity/hour):", len(X))

    model = IsolationForest(n_estimators=200, contamination=0.01, random_state=42)
    model.fit(X[FEATURES])
    X["anomaly"] = model.predict(X[FEATURES]) == -1
    X["score"] = -model.score_samples(X[FEATURES])
    print("Flagged as anomalous:", int(X["anomaly"].sum()))

    # Fair test: score the synthetic attacks the model never saw
    events, scenarios = build()
    syn = pd.DataFrame(events)
    syn["eventTime"] = pd.to_datetime(syn["eventTime"], utc=True)
    S = featurize(prepare(syn))
    S["anomaly"] = model.predict(S[FEATURES]) == -1

    rows = []
    for s in scenarios:
        hit = S[(S["sourceIPAddress"] == s["ip"]) & S["anomaly"]]
        rows.append({"id": s["id"], "scenario": s["name"], "ml_detected": len(hit) > 0})
    res = pd.DataFrame(rows)
    print("\n" + res.to_string(index=False))
    print(f"\nML alone detected {res['ml_detected'].sum()} of {len(res)}")
    res.to_csv("results/ml_synthetic_eval.csv", index=False)

    # What does ML flag on real data that the rules never alerted on?
    rule_alerts = pd.concat([r(real) for r in ALL_RULES], ignore_index=True)
    rule_ips = set(rule_alerts["sourceIPAddress"].astype(str))
    ml_only = X[X["anomaly"] & ~X["sourceIPAddress"].astype(str).isin(rule_ips)]
    print("\nML-flagged rows from IPs no rule alerted on:", len(ml_only))
    print("Distinct IPs:", ml_only["sourceIPAddress"].nunique())

    X.sort_values("score", ascending=False).head(200).to_csv(
        "results/ml_top_anomalies.csv", index=False)
    print("\nTop 10 most anomalous rows:")
    print(X.sort_values("score", ascending=False).head(10)[
        ["sourceIPAddress", "identityName", "log_events", "unique_events", "error_rate"]
    ].to_string(index=False))