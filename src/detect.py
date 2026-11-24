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

def _has(series, text):
    return series.astype(str).str.contains(text, regex=False)


def rule_slow_compute_hijacking(df, threshold=15):
    rows = df[df["eventName"] == "RunInstances"].copy()
    rows["day"] = rows["eventTime"].dt.floor("D")
    g = (rows.groupby(["day", "sourceIPAddress", "identityName"], dropna=False)
         .size().reset_index(name="event_count"))
    g = g[g["event_count"] >= threshold]
    g.insert(0, "rule", "RunInstances volume per day from one source")
    g.insert(1, "attack_id", "T1496.001")
    return g


def rule_new_credentials(df):
    names = ["CreateUser", "CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile"]
    rows = df[df["eventName"].isin(names) & (df["errorCode"] == "")]
    return summarize(rows, "New IAM user, key or password created", "T1098.001")


def rule_public_snapshot(df):
    rows = df[df["eventName"].isin(["ModifySnapshotAttribute", "ModifyImageAttribute"])]
    rows = rows[_has(rows["requestParameters"], "'group': 'all'")]
    return summarize(rows, "Snapshot or image shared publicly", "T1537")


def rule_admin_policy_attached(df):
    names = ["AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"]
    rows = df[df["eventName"].isin(names)]
    rows = rows[_has(rows["requestParameters"], "AdministratorAccess")]
    return summarize(rows, "AdministratorAccess policy attached", "T1098.003")


def rule_console_login_no_mfa(df):
    rows = df[df["eventName"] == "ConsoleLogin"]
    no_mfa = rows["additionalEventData"].apply(
        lambda x: isinstance(x, dict) and x.get("MFAUsed") == "No")
    success = rows["responseElements"].apply(
        lambda x: isinstance(x, dict) and x.get("ConsoleLogin") == "Success")
    return summarize(rows[no_mfa & success], "Console login without MFA", "T1078.004")

ALL_RULES = [
    rule_compute_hijacking,
    rule_root_usage,
    rule_logging_tampering,
    rule_access_denied_burst,
    rule_recon_enumeration,
    rule_slow_compute_hijacking,
    rule_new_credentials,
    rule_public_snapshot,
    rule_admin_policy_attached,
    rule_console_login_no_mfa,
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