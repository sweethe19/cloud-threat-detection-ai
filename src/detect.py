import pandas as pd

KEYS = ["hour", "sourceIPAddress", "identityName"]


def prepare(df):
    df = df.copy()
    ident = df["userIdentity"]
    df["identityType"] = ident.apply(lambda x: x.get("type") if isinstance(x, dict) else None)
    df["identityName"] = ident.apply(
        lambda x: (x.get("userName") or x.get("arn") or x.get("principalId"))
        if isinstance(x, dict) else None
    )
    df["hour"] = df["eventTime"].dt.floor("h")
    df["errorCode"] = df["errorCode"].fillna("")
    df["eventName"] = df["eventName"].fillna("")
    return df


def summarize(rows, rule, attack_id):
    g = rows.groupby(KEYS, dropna=False).size().reset_index(name="event_count")
    g.insert(0, "rule", rule)
    g.insert(1, "attack_id", attack_id)
    return g


def rule_compute_hijacking(df, threshold=100):
    rows = df[df["eventName"] == "RunInstances"]
    g = summarize(rows, "Mass RunInstances from one source", "T1496.001")
    return g[g["event_count"] >= threshold]


def rule_root_usage(df):
    rows = df[df["identityType"] == "Root"]
    return summarize(rows, "Root account used", "T1078.004")


def rule_logging_tampering(df):
    bad = ["StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"]
    rows = df[(df["eventSource"] == "cloudtrail.amazonaws.com") & (df["eventName"].isin(bad))]
    return summarize(rows, "CloudTrail logging modified or stopped", "T1562.008")


def rule_access_denied_burst(df, threshold=50):
    denied = df["errorCode"].str.contains("AccessDenied|UnauthorizedOperation", regex=True)
    g = summarize(df[denied], "Burst of access-denied errors", "T1580")
    return g[g["event_count"] >= threshold]


def rule_recon_enumeration(df, threshold=20):
    rows = df[df["eventName"].str.match(r"^(List|Describe|Get)", na=False)]
    g = (rows.groupby(KEYS, dropna=False)["eventName"].nunique()
         .reset_index(name="event_count"))
    g.insert(0, "rule", "Many different recon calls in one hour")
    g.insert(1, "attack_id", "T1580")
    return g[g["event_count"] >= threshold]


ALL_RULES = [
    rule_compute_hijacking,
    rule_root_usage,
    rule_logging_tampering,
    rule_access_denied_burst,
    rule_recon_enumeration,
]

if __name__ == "__main__":
    df = prepare(pd.read_pickle("data/flaws.pkl"))
    NOISY_SOURCES = "amazonaws.com|AWS Internal"
    df = df[~df["sourceIPAddress"].astype(str).str.contains(NOISY_SOURCES)]
    alerts = pd.concat([rule(df) for rule in ALL_RULES], ignore_index=True)
    alerts.to_csv("results/alerts.csv", index=False)

    print("Alerts per rule:")
    print(alerts["rule"].value_counts())
    print("\nTop alerting sources:")
    print(alerts.groupby("sourceIPAddress").size().sort_values(ascending=False).head(10))