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


def pair_key(df):
    return df["sourceIPAddress"].astype(str) + "|" + df["identityName"].astype(str)


if __name__ == "__main__":
    real = prepare(pd.read_pickle("data/flaws.pkl"))
    real = real[~real["sourceIPAddress"].astype(str).str.contains(NOISY)]

    # Which IP+identity pairs did the rules already alert on?
    alerts = pd.concat([r(real) for r in ALL_RULES], ignore_index=True)
    alerted_pairs = set(pair_key(alerts))

    X = featurize(real)
    X["alerted"] = pair_key(X).isin(alerted_pairs)
    baseline = X[~X["alerted"]]
    print("All rows:", len(X), "| rule-alerted:", int(X["alerted"].sum()),
          "| clean baseline:", len(baseline))

    model = IsolationForest(n_estimators=200, random_state=42)
    model.fit(baseline[FEATURES])
    base_scores = -model.score_samples(baseline[FEATURES])
    threshold = np.percentile(base_scores, 99)

    # Fair test: score synthetic attacks the model never saw
    events, scenarios = build()
    syn = pd.DataFrame(events)
    syn["eventTime"] = pd.to_datetime(syn["eventTime"], utc=True)
    S = featurize(prepare(syn))
    S["score"] = -model.score_samples(S[FEATURES])

    rows = []
    for s in scenarios:
        sc = S[S["sourceIPAddress"] == s["ip"]]["score"].max()
        rows.append({"id": s["id"], "scenario": s["name"],
                     "score": round(sc, 3),
                     "percentile": round((base_scores < sc).mean() * 100, 1),
                     "ml_detected": bool(sc > threshold)})
    res = pd.DataFrame(rows)
    print("\n" + res.to_string(index=False))
    print(f"\nML alone detected {res['ml_detected'].sum()} of {len(res)}")
    res.to_csv("results/ml_synthetic_eval.csv", index=False)

    # Agreement with the rules, and what ML flags where rules were silent
    X["score"] = -model.score_samples(X[FEATURES])
    X["ml_flag"] = X["score"] > threshold
    print(f"\nML flags {X[X['alerted']]['ml_flag'].mean():.0%} of rows "
          "from pairs the rules alerted on")
    cand = X[~X["alerted"] & X["ml_flag"]].sort_values("score", ascending=False)
    print("ML-only candidates (rules silent):", len(cand),
          "rows from", cand["sourceIPAddress"].nunique(), "IPs")
    cand.head(100).to_csv("results/ml_candidates.csv", index=False)
    print("\nTop 10 candidates:")
    print(cand.head(10)[["sourceIPAddress", "identityName", "log_events",
                         "unique_events", "error_rate"]].to_string(index=False))

    # Threshold sweep: detection vs. alert volume
    print("\nThreshold sweep (catching attacks vs. alert volume):")
    sweep = []
    for pct in [90, 95, 97, 99]:
        thr = np.percentile(base_scores, pct)
        sweep.append({"baseline_percentile": pct,
                      "synthetic_detected": f"{int((res['score'] > thr).sum())}/10",
                      "baseline_rows_flagged": int((base_scores > thr).sum())})
    sweep = pd.DataFrame(sweep)
    print(sweep.to_string(index=False))
    sweep.to_csv("results/ml_threshold_sweep.csv", index=False)