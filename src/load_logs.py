import gzip
import json
from pathlib import Path

import pandas as pd


def read_file(path):
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("Records", []) if isinstance(data, dict) else data


def load_cloudtrail(folder="data/flaws"):
    records = []
    for p in Path(folder).rglob("*"):
        if p.suffix in (".json", ".gz"):
            try:
                records.extend(read_file(p))
            except Exception as e:
                print("skipped", p.name, e)
    df = pd.DataFrame(records)
    df["eventTime"] = pd.to_datetime(df["eventTime"], errors="coerce")
    return df


if __name__ == "__main__":
    df = load_cloudtrail()
    print("Total events:", len(df))
    print("Columns:", df.columns.tolist())
    print(df["eventName"].value_counts().head(15))
    df.to_pickle("data/flaws.pkl")
    print("Saved to data/flaws.pkl")