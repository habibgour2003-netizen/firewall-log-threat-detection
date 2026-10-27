"""Streamlit local dashboard for synthetic or authorized firewall logs."""

import sqlite3
import json
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).parent
ORIGINAL_DB = ROOT / "outputs" / "firewall_lab.db"
VALIDATION_DB = ROOT / "outputs" / "validation" / "firewall_lab.db"
datasets = {"Original synthetic sample": ORIGINAL_DB}
if VALIDATION_DB.exists():
    datasets["Independent synthetic validation sample"] = VALIDATION_DB
st.set_page_config(page_title="Firewall Threat Lab", page_icon="🛡️", layout="wide")
st.title("🛡️ Firewall Log Analysis & Threat Detection")
st.caption("Local defensive lab • Synthetic sample data • Heuristic alerts are not confirmed intrusions")

selected_dataset = st.sidebar.selectbox("Dataset", list(datasets.keys()))
DB_PATH = datasets[selected_dataset]
if not DB_PATH.exists():
    st.error("Database missing. Run: python -m src.generate_sample then python -m src.pipeline")
    st.stop()

with sqlite3.connect(DB_PATH) as connection:
    logs = pd.read_sql_query("SELECT * FROM firewall_logs", connection)
    alerts = pd.read_sql_query("SELECT * FROM alerts", connection)

if logs.empty:
    st.warning("No firewall events found.")
    st.stop()

logs["timestamp"] = pd.to_datetime(logs["timestamp"], utc=True)
if not alerts.empty:
    alerts["window_start"] = pd.to_datetime(alerts["window_start"], utc=True)

st.sidebar.header("Filters")
selected = st.sidebar.selectbox("Source IP", ["All"] + sorted(logs["src_ip"].unique().tolist()))
chosen_action = st.sidebar.selectbox("Action", ["All", "ALLOW", "DENY"])
filtered = logs.copy()
if selected != "All":
    filtered = filtered[filtered["src_ip"] == selected]
if chosen_action != "All":
    filtered = filtered[filtered["action"] == chosen_action]

col1, col2, col3, col4 = st.columns(4)
col1.metric("Events", f"{len(filtered):,}")
col2.metric("Denied", f"{(filtered['action'] == 'DENY').sum():,}")
col3.metric("Unique source IPs", filtered["src_ip"].nunique())
matching_alerts = alerts if selected == "All" else alerts[alerts["src_ip"] == selected]
if chosen_action == "ALLOW":
    # Every rule is based exclusively on DENY events.
    matching_alerts = matching_alerts.iloc[0:0]
col4.metric("Detection alerts", len(matching_alerts))

st.subheader("Events over time (15-minute buckets)")
if not filtered.empty:
    timeline = (
        filtered.set_index("timestamp").groupby([pd.Grouper(freq="15min"), "action"])
        .size().unstack(fill_value=0).reindex(columns=["ALLOW", "DENY"], fill_value=0)
    )
    st.line_chart(timeline)

left, right = st.columns(2)
with left:
    st.subheader("Top source IPs")
    if not filtered.empty:
        st.bar_chart(filtered["src_ip"].value_counts().head(10))
with right:
    st.subheader("Top destination ports (denied)")
    denied = filtered[filtered["action"] == "DENY"]
    if not denied.empty:
        st.bar_chart(denied["dst_port"].astype(str).value_counts().head(10))

if selected_dataset.startswith("Independent"):
    evaluation_path = ROOT / "outputs" / "validation" / "evaluation.json"
    if evaluation_path.exists():
        evaluation = json.loads(evaluation_path.read_text(encoding="utf-8"))
        st.info(
            f"**Validation sur scénarios synthétiques** : "
            f"{evaluation['true_positives']} détectés / "
            f"{evaluation['false_negatives']} manqués / "
            f"{evaluation['false_positives']} alertes inattendues. "
            "Le scan lent est volontairement non détecté par les règles actuelles. "
            "Ces chiffres ne mesurent PAS la performance en production."
        )

st.subheader("Detection alerts")
if matching_alerts.empty:
    st.info("No heuristic alerts match the current source IP filter.")
else:
    st.dataframe(matching_alerts.sort_values("window_start", ascending=False),
                 use_container_width=True, hide_index=True)

st.subheader("Firewall events")
st.dataframe(filtered.sort_values("timestamp", ascending=False).head(1000),
             use_container_width=True, hide_index=True)
st.caption("Rules: ≥12 distinct denied destination ports to one target in a 5-minute UTC bucket; or ≥40 denied connections from one source in a 5-minute UTC bucket. Tune thresholds for real datasets.")
