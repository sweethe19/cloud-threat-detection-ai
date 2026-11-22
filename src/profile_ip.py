import sys

import pandas as pd

df = pd.read_pickle("data/flaws.pkl")
df["identityType"] = df["userIdentity"].apply(
    lambda x: x.get("type") if isinstance(x, dict) else None
)

for ip in sys.argv[1:]:
    sub = df[df["sourceIPAddress"] == ip]
    print("=" * 60)
    print("IP:", ip, "| events:", len(sub))
    print("Active:", sub["eventTime"].min(), "to", sub["eventTime"].max())
    print("Identity types:", sub["identityType"].value_counts().to_dict())
    print("\nTop events:")
    print(sub["eventName"].value_counts().head(8).to_string())
    print("\nTop errors:")
    print(sub["errorCode"].value_counts().head(5).to_string())
    print("\nUser agents:")
    print(sub["userAgent"].astype(str).str[:70].value_counts().head(4).to_string())