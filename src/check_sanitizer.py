import pandas as pd

from defenses import is_valid_identity
from detect import prepare

df = prepare(pd.read_pickle("data/flaws.pkl"))
counts = df["identityName"].astype(str).value_counts()
bad = counts[[not is_valid_identity(n) for n in counts.index]]
print(len(counts), "unique identity values,", len(bad), "would be flagged")
print("Events affected:", int(bad.sum()), "of", int(counts.sum()))
print(bad.head(10).to_string())