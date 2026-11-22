import pandas as pd

alerts = pd.read_csv("results/alerts.csv")

for rule, grp in alerts.groupby("rule"):
    print(f"\n{rule}: {len(grp)} alerts")
    print(grp["sourceIPAddress"].value_counts().head(3).to_string())

print("\nRules triggered by 5.205.62.253:")
print(alerts[alerts["sourceIPAddress"] == "5.205.62.253"]["rule"].value_counts())

print("\nLogging-tamper alerts:")
cols = ["hour", "sourceIPAddress", "identityName", "event_count"]
print(alerts[alerts["rule"].str.contains("CloudTrail")][cols].to_string())