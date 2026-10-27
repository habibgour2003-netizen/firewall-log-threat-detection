"""Transparent, explainable 5-minute-window firewall detections."""

from __future__ import annotations

import ipaddress
from pathlib import Path

import pandas as pd

REQUIRED_COLUMNS = [
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "action", "bytes",
]
WINDOW = "5min"
PORT_SCAN_THRESHOLD = 12   # distinct destination ports / src+dst / 5 min
DENY_BURST_THRESHOLD = 40  # denied connection events / src / 5 min


def load_logs(path: str | Path) -> pd.DataFrame:
    """Read the lab CSV; reject malformed records rather than guessing."""
    df = pd.read_csv(path)
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing CSV columns: {', '.join(missing)}")
    df = df[REQUIRED_COLUMNS].copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    if df["timestamp"].isna().any():
        raise ValueError("Invalid timestamp in CSV. Use ISO 8601 (e.g. 2026-10-27T10:00:00Z).")
    for field in ("src_port", "dst_port", "bytes"):
        df[field] = pd.to_numeric(df[field], errors="coerce")
        if df[field].isna().any():
            raise ValueError(f"Non-numeric value in {field}.")
    if (((df["src_port"] < 0) | (df["src_port"] > 65535) |
         (df["dst_port"] < 0) | (df["dst_port"] > 65535) |
         (df["bytes"] < 0))).any():
        raise ValueError("Invalid port number or negative bytes.")
    for field in ("src_port", "dst_port", "bytes"):
        df[field] = df[field].astype("int64")
    for field in ("src_ip", "dst_ip"):
        try:
            for ip in df[field].unique():
                ipaddress.ip_address(str(ip))
        except ValueError as exc:
            raise ValueError(f"Invalid {field}: {exc}") from exc
    df["action"] = df["action"].astype(str).str.upper().str.strip()
    df["protocol"] = df["protocol"].astype(str).str.upper().str.strip()
    if not df["action"].isin(["ALLOW", "DENY"]).all():
        raise ValueError("action must be ALLOW or DENY.")
    if not df["protocol"].isin(["TCP", "UDP", "ICMP"]).all():
        raise ValueError("protocol must be TCP, UDP, or ICMP.")
    return df.sort_values("timestamp").reset_index(drop=True)


def detect_alerts(logs: pd.DataFrame) -> pd.DataFrame:
    """Flag potential scans and deny bursts. Signals, not proof of attacks."""
    output_cols = ["window_start", "src_ip", "dst_ip", "alert_type", "severity", "event_count", "distinct_ports", "reason"]
    if logs.empty:
        return pd.DataFrame(columns=output_cols)

    denied = logs.loc[logs["action"] == "DENY"].copy()
    if denied.empty:
        return pd.DataFrame(columns=output_cols)
    denied["window_start"] = denied["timestamp"].dt.floor(WINDOW)
    alerts = []

    scan_groups = denied.groupby(["window_start", "src_ip", "dst_ip"], as_index=False).agg(
        event_count=("dst_port", "size"), distinct_ports=("dst_port", "nunique")
    )
    for row in scan_groups.loc[scan_groups["distinct_ports"] >= PORT_SCAN_THRESHOLD].itertuples():
        alerts.append({
            "window_start": row.window_start, "src_ip": row.src_ip, "dst_ip": row.dst_ip,
            "alert_type": "POSSIBLE_PORT_SCAN", "severity": "HIGH",
            "event_count": int(row.event_count), "distinct_ports": int(row.distinct_ports),
            "reason": f"{row.distinct_ports} distinct denied destination ports within 5 minutes",
        })

    burst_groups = denied.groupby(["window_start", "src_ip"], as_index=False).agg(
        event_count=("dst_port", "size"), distinct_ports=("dst_port", "nunique")
    )
    for row in burst_groups.loc[burst_groups["event_count"] >= DENY_BURST_THRESHOLD].itertuples():
        alerts.append({
            "window_start": row.window_start, "src_ip": row.src_ip, "dst_ip": "*",
            "alert_type": "DENY_BURST", "severity": "MEDIUM",
            "event_count": int(row.event_count), "distinct_ports": int(row.distinct_ports),
            "reason": f"{row.event_count} denied connection events within 5 minutes",
        })
    return pd.DataFrame(alerts, columns=output_cols).sort_values(
        ["window_start", "src_ip", "alert_type"]
    ).reset_index(drop=True)
