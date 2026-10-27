"""Build a separate, reproducible synthetic hold-out dataset for rule validation.

All public IP addresses are RFC 5737 documentation-only addresses.
No actual external traffic is generated or queried.
"""

from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

BASE = datetime(2026, 10, 28, 0, 0, tzinfo=timezone.utc)
NORMAL_IPS = ("192.0.2.41", "192.0.2.42", "198.51.100.41")
SERVER = "10.20.0.10"

# Ground-truth cases are independent of the detector logic.
TRUTH = [
    {"src_ip": "203.0.113.70", "alert_type": "POSSIBLE_PORT_SCAN", "scenario": "fast port scan: 15 denied ports in 5 min"},
    {"src_ip": "198.51.100.70", "alert_type": "DENY_BURST", "scenario": "50 denied connections in 5 min"},
    {"src_ip": "203.0.113.80", "alert_type": "POSSIBLE_PORT_SCAN", "scenario": "slow scan: 10 denied ports in each of two 5-min buckets (known miss)"},
]


def _row(stamp: datetime, src: str, port: int, action: str, src_port: int) -> dict:
    return {
        "timestamp": stamp.isoformat().replace("+00:00", "Z"),
        "src_ip": src, "dst_ip": SERVER,
        "src_port": src_port, "dst_port": port,
        "protocol": "TCP", "action": action,
        "bytes": 0 if action == "DENY" else 1600,
    }


def build_validation() -> pd.DataFrame:
    rng = random.Random(2027)
    rows = []
    # Background: a relatively quiet day of normal traffic on known ports.
    for n in range(420):
        stamp = BASE + timedelta(seconds=rng.randrange(86400))
        rows.append(_row(stamp, rng.choice(NORMAL_IPS), rng.choice([22, 53, 80, 443]),
                         "ALLOW" if rng.random() < 0.88 else "DENY", 10000 + n))

    # Positive case 1: fast scan, 15 different destinations in same 5min bucket.
    for n in range(15):
        rows.append(_row(BASE + timedelta(hours=9, minutes=1, seconds=n * 4),
                         "203.0.113.70", 3000 + n, "DENY", 20000 + n))

    # Positive case 2: deny burst with one destination port; NOT a scan.
    for n in range(50):
        rows.append(_row(BASE + timedelta(hours=12, minutes=1, seconds=n * 3),
                         "198.51.100.70", 22, "DENY", 22000 + n))

    # Benign near-miss: 35 denies on 2 ports in one bucket (below thresholds).
    for n in range(35):
        rows.append(_row(BASE + timedelta(hours=14, minutes=1, seconds=n * 4),
                         "192.0.2.55", 443 if n % 2 == 0 else 80, "DENY", 25000 + n))

    # Known weakness: a scan spread across two different 5-minute windows.
    # Neither five-minute window contains 12 distinct ports.
    for n in range(20):
        rows.append(_row(BASE + timedelta(hours=16, minutes=1, seconds=n * 26),
                         "203.0.113.80", 4000 + n, "DENY", 30000 + n))
    return pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)


def main():
    parser = argparse.ArgumentParser(description="Generate a distinct synthetic validation set")
    parser.add_argument("--output", default="data/validation_firewall_logs.csv")
    parser.add_argument("--truth", default="data/validation_truth.json")
    args = parser.parse_args()
    output = Path(args.output)
    truth = Path(args.truth)
    output.parent.mkdir(parents=True, exist_ok=True)
    truth.parent.mkdir(parents=True, exist_ok=True)
    frame = build_validation()
    frame.to_csv(output, index=False)
    truth.write_text(json.dumps(TRUTH, indent=2), encoding="utf-8")
    print(f"Wrote {len(frame)} simulated events to {output}")
    print(f"Wrote {len(TRUTH)} labeled threat scenarios to {truth}")


if __name__ == "__main__":
    main()
