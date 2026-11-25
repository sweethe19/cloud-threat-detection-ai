import json
import urllib.request

import pandas as pd

from detect import ALL_RULES, prepare
from inject import build

MODEL = "llama3.1:8b"
URL = "http://localhost:11434/api/chat"

SYSTEM = (
    "You are a cloud security analyst triaging AWS CloudTrail alerts. "
    "Reply with JSON only, using exactly these keys: "
    '"verdict" (one of "escalate", "investigate", "likely_benign"), '
    '"severity" (one of "low", "medium", "high", "critical"), '
    '"summary" (at most 2 sentences), '
    '"attack_ids" (list of MITRE ATT&CK IDs taken only from the incident), '
    '"actions" (list of at most 3 short response steps).'
)


def build_incident(ip, ev, a):
    return {
        "source_ip": ip,
        "first_seen": str(ev["eventTime"].min()),
        "last_seen": str(ev["eventTime"].max()),
        "total_events": int(len(ev)),
        "rules_fired": sorted(a["rule"].unique().tolist()),
        "attack_ids": sorted(a["attack_id"].unique().tolist()),
        "top_events": {k: int(v) for k, v in ev["eventName"].value_counts().head(5).items()},
        "identities": ev["identityName"].astype(str).unique()[:3].tolist(),
        "user_agents": ev["userAgent"].astype(str).str[:80].unique()[:2].tolist(),
        "error_rate": round(float((ev["errorCode"] != "").mean()), 2),
    }


def ask(incident, tries=2):
    body = {
        "model": MODEL, "stream": False, "format": "json",
        "options": {"temperature": 0},
        "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user",
             "content": "Triage this incident:\n" + json.dumps(incident, indent=2)},
        ],
    }
    req = urllib.request.Request(
        URL, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"})
    err = None
    for _ in range(tries):
        try:
            with urllib.request.urlopen(req, timeout=900) as r:
                return json.loads(json.loads(r.read())["message"]["content"])
        except Exception as e:
            err = e
    return {"error": str(err)}

    req = urllib.request.Request(
        URL, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=900) as r:
            return json.loads(json.loads(r.read())["message"]["content"])
    except Exception as e:
        return {"error": str(e)}


if __name__ == "__main__":
    real = pd.read_pickle("data/flaws.pkl")
    events, scenarios = build()
    syn = pd.DataFrame(events)
    syn["eventTime"] = pd.to_datetime(syn["eventTime"], utc=True)
    df = prepare(pd.concat([real, syn], ignore_index=True))
    df = df[~df["sourceIPAddress"].astype(str).str.contains("amazonaws.com|AWS Internal")]

    alerts = pd.concat([r(df) for r in ALL_RULES], ignore_index=True)

    syn_ips = [s["ip"] for s in scenarios]
    real_alerts = alerts[~alerts["sourceIPAddress"].isin(syn_ips)]
    real_ips = real_alerts["sourceIPAddress"].value_counts().head(5).index.tolist()
    ips = syn_ips + real_ips

    sub = df[df["sourceIPAddress"].isin(ips)]
    results = []
    for i, ip in enumerate(ips, 1):
        inc = build_incident(ip, sub[sub["sourceIPAddress"] == ip],
                             alerts[alerts["sourceIPAddress"] == ip])
        out = ask(inc)
        bad_ids = sorted(set(out.get("attack_ids", [])) - set(inc["attack_ids"]))
        results.append({"ip": ip, "synthetic": ip in syn_ips,
                        "incident": inc, "output": out, "invalid_attack_ids": bad_ids})
        print(f"[{i}/{len(ips)}] {ip} -> {out.get('verdict')} / {out.get('severity')}"
              f" | invalid IDs: {bad_ids}", flush=True)
        print("    ", str(out.get("summary", out))[:200], flush=True)

    with open("results/triage_v1.json", "w") as f:
        json.dump(results, f, indent=2, default=str)

    s = [r for r in results if r["synthetic"]]
    ok = sum(1 for r in s if r["output"].get("verdict") in ("escalate", "investigate"))
    print(f"\nSynthetic incidents not marked benign: {ok}/{len(s)}")
    print("Incidents with invented ATT&CK IDs:",
          sum(1 for r in results if r["invalid_attack_ids"]), "of", len(results))