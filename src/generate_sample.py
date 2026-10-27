"""Generate deterministic SYNTHETIC firewall telemetry (no real victims)."""

import argparse
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

BASE = datetime(2026, 10, 27, 0, 0, tzinfo=timezone.utc)
SOURCES = ["192.0.2.10", "192.0.2.11", "198.51.100.8", "198.51.100.9"]
TARGETS = ["10.10.0.10", "10.10.0.11", "10.10.0.12"]
COMMON_PORTS = [22, 53, 80, 443, 3389]


def build_sample() -> pd.DataFrame:
    rng = random.Random(42)
    rows = []
    for _ in range(1400):
        stamp = BASE + timedelta(seconds=rng.randrange(86400))
        rows.append({
            "timestamp": stamp.isoformat().replace("+00:00", "Z"),
            "src_ip": rng.choice(SOURCES), "dst_ip": rng.choice(TARGETS),
            "src_port": rng.randint(1024, 65535),
            "dst_port": rng.choice(COMMON_PORTS), "protocol": "TCP",
            "action": "ALLOW" if rng.random() < 0.87 else "DENY",
            "bytes": rng.randrange(100, 7500),
        })
    # Explicitly injected port scan simulation, 20 denied destination ports in 5 minutes.
    for idx, port in enumerate(range(2000, 2020)):
        rows.append({
            "timestamp": (BASE + timedelta(hours=10, minutes=1, seconds=idx * 3)).isoformat().replace("+00:00", "Z"),
            "src_ip": "203.0.113.50", "dst_ip": "10.10.0.10", "src_port": 47000 + idx,
            "dst_port": port, "protocol": "TCP", "action": "DENY", "bytes": 0,
        })
    # Explicitly injected repetitive denied connection simulation.
    for idx in range(65):
        rows.append({
            "timestamp": (BASE + timedelta(hours=14, minutes=2, seconds=idx * 3)).isoformat().replace("+00:00", "Z"),
            "src_ip": "198.51.100.23", "dst_ip": "10.10.0.11", "src_port": 42000 + idx,
            "dst_port": 22, "protocol": "TCP", "action": "DENY", "bytes": 0,
        })
    return pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a safe synthetic firewall CSV")
    parser.add_argument("--output", default="data/sample_firewall_logs.csv")
    args = parser.parse_args()
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    sample = build_sample()
    sample.to_csv(path, index=False)
    print(f"Generated {len(sample)} synthetic events -> {path}")


if __name__ == "__main__":
    main()
