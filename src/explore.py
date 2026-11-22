import pandas as pd

df = pd.read_pickle("data/flaws.pkl")

print("Date range:", df["eventTime"].min(), "to", df["eventTime"].max())

print("\nTop services:")
print(df["eventSource"].value_counts().head(10))

print("\nTop error codes:")
print(df["errorCode"].value_counts().head(10))

print("\nTop user agents:")
print(df["userAgent"].astype(str).str[:80].value_counts().head(10))

print("\nTop source IPs:")
print(df["sourceIPAddress"].value_counts().head(10))

df["identityType"] = df["userIdentity"].apply(
    lambda x: x.get("type") if isinstance(x, dict) else None
)
print("\nIdentity types:")
print(df["identityType"].value_counts())