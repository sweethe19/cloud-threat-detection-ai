import pandas as pd

df = pd.read_pickle("data/flaws.pkl")

top_ip = df["sourceIPAddress"].value_counts().index[0]
sub = df[df["sourceIPAddress"] == top_ip]
print("Top IP:", top_ip, "events:", len(sub))
print(sub["eventName"].value_counts().head(5))
print(sub["errorCode"].value_counts(dropna=False).head(5))
print(sub["eventTime"].min(), "to", sub["eventTime"].max())

root = df[df["userIdentity"].apply(lambda x: isinstance(x, dict) and x.get("type") == "Root")]
print("\nRoot events:", len(root))
print(root["eventName"].value_counts().head(10))