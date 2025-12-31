# net_dashboard_full.py
import streamlit as st
import pandas as pd
import plotly.express as px
from scapy.all import sniff, IP, TCP, UDP, Raw
import threading
import time
from datetime import datetime
import logging
import math
import re
import requests
from typing import Optional, Any
from collections import deque, defaultdict
import sqlite3
import smtplib
from email.message import EmailMessage

# ML imports
import numpy as np
from sklearn.ensemble import IsolationForest

# Optional geoip2 import
try:
    import geoip2.database
    GEOIP2_AVAILABLE = True
except Exception:
    GEOIP2_AVAILABLE = False

# ---------------------------
# Logging
# ---------------------------
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("net_dashboard_full")

# ---------------------------
# Utilities
# ---------------------------
def entropy_of_bytes(b: bytes) -> float:
    if not b:
        return 0.0
    counts = {}
    for byte in b:
        counts[byte] = counts.get(byte, 0) + 1
    probs = [c / len(b) for c in counts.values()]
    ent = -sum(p * math.log2(p) for p in probs if p > 0)
    return ent

def safe_text(b: bytes, max_len=300) -> str:
    try:
        s = b.decode(errors='replace')
    except Exception:
        s = ''.join(chr(x) if 32 <= x < 127 else '.' for x in b)
    return s[:max_len]

def get_geo_for_ip(ip: str, geoip_reader: Optional[Any]=None) -> dict:
    if GEOIP2_AVAILABLE and geoip_reader is not None:
        try:
            r = geoip_reader.city(ip)
            return {
                'country': r.country.name,
                'region': r.subdivisions.most_specific.name,
                'city': r.city.name,
                'lat': getattr(r.location, 'latitude', None),
                'lon': getattr(r.location, 'longitude', None)
            }
        except Exception:
            pass
    try:
        resp = requests.get(f'https://ipinfo.io/{ip}/json', timeout=3)
        if resp.status_code == 200:
            j = resp.json()
            lat = lon = None
            if 'loc' in j and j['loc']:
                try:
                    lat, lon = map(float, j['loc'].split(','))
                except Exception:
                    pass
            return {
                'country': j.get('country'),
                'region': j.get('region'),
                'city': j.get('city'),
                'lat': lat,
                'lon': lon
            }
    except Exception:
        pass
    return {'country': None, 'region': None, 'city': None, 'lat': None, 'lon': None}

# ---------------------------
# Packet Processor
# ---------------------------
class PacketProcessor:
    def __init__(self, keep_last=5000, geoip_db_path: Optional[str] = None):
        self.protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        self.packet_data = deque(maxlen=keep_last)
        self.start_time = datetime.now()
        self.lock = threading.Lock()
        self.geo_cache = {}
        self.geo_reader = None
        if GEOIP2_AVAILABLE and geoip_db_path:
            try:
                self.geo_reader = geoip2.database.Reader(geoip_db_path)
            except Exception as e:
                logger.warning(f"Could not open GeoIP DB: {e}")
                self.geo_reader = None

    def _proto_name(self, pnum: int) -> str:
        return self.protocol_map.get(pnum, f'OTHER({pnum})')

    def process_packet(self, pkt) -> None:
        try:
            if IP not in pkt:
                return
            with self.lock:
                now = datetime.now()
                proto = self._proto_name(pkt[IP].proto)
                base = {
                    'timestamp': now,
                    'time_relative': (now - self.start_time).total_seconds(),
                    'source': pkt[IP].src,
                    'destination': pkt[IP].dst,
                    'protocol': proto,
                    'size': len(pkt)
                }
                if TCP in pkt:
                    base.update({
                        'src_port': int(pkt[TCP].sport),
                        'dst_port': int(pkt[TCP].dport),
                        'tcp_flags': str(pkt[TCP].flags)
                    })
                elif UDP in pkt:
                    base.update({
                        'src_port': int(pkt[UDP].sport),
                        'dst_port': int(pkt[UDP].dport)
                    })
                else:
                    base.update({'src_port': None, 'dst_port': None})

                payload_bytes = b''
                if Raw in pkt:
                    try:
                        payload_bytes = bytes(pkt[Raw].load)
                    except Exception:
                        payload_bytes = b''

                base['payload_len'] = len(payload_bytes)
                base['payload_entropy'] = entropy_of_bytes(payload_bytes)
                base['payload_preview'] = safe_text(payload_bytes, max_len=500)

                src = base['source']
                if src not in self.geo_cache:
                    self.geo_cache[src] = get_geo_for_ip(src, geoip_reader=self.geo_reader)
                base['geo_src_country'] = self.geo_cache[src].get('country')
                base['geo_src_city'] = self.geo_cache[src].get('city')
                base['geo_src_lat'] = self.geo_cache[src].get('lat')
                base['geo_src_lon'] = self.geo_cache[src].get('lon')

                self.packet_data.append(base)
        except Exception as e:
            logger.exception("Error processing packet: %s", e)

    def get_dataframe(self) -> pd.DataFrame:
        with self.lock:
            if not self.packet_data:
                return pd.DataFrame()
            return pd.DataFrame(list(self.packet_data))

# ---------------------------
# Anomaly Detector
# ---------------------------
class AnomalyDetector:
    def __init__(self, retrain_every=200, contamination=0.01, random_state=42):
        self.model = None
        self.retrain_every = retrain_every
        self.contamination = contamination
        self.counter = 0
        self.random_state = random_state

    def _features(self, df: pd.DataFrame) -> np.ndarray:
        if df.empty:
            return np.empty((0, 6))
        proto_map = {'ICMP': 1, 'TCP': 6, 'UDP': 17}
        proto_num = df['protocol'].map(lambda x: proto_map.get(x, 0)).fillna(0).astype(float)
        size = df['size'].fillna(0).astype(float)
        payload_len = df.get('payload_len', pd.Series(0, index=df.index)).fillna(0).astype(float)
        payload_entropy = df.get('payload_entropy', pd.Series(0, index=df.index)).fillna(0).astype(float)
        src_port = df.get('src_port', pd.Series(0, index=df.index)).fillna(0).astype(float)
        dst_port = df.get('dst_port', pd.Series(0, index=df.index)).fillna(0).astype(float)

        X = np.vstack([
            size.values,
            payload_len.values,
            payload_entropy.values,
            src_port.values,
            dst_port.values,
            proto_num.values
        ]).T
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        return X

    def maybe_retrain(self, df: pd.DataFrame):
        self.counter += 1
        if self.counter < self.retrain_every:
            return
        self.counter = 0
        X = self._features(df)
        if X.shape[0] < 50:
            logger.info("Not enough data to train anomaly model yet.")
            return
        try:
            self.model = IsolationForest(n_estimators=100, contamination=self.contamination, random_state=self.random_state)
            self.model.fit(X)
            logger.info("Anomaly model trained on %d samples", X.shape[0])
        except Exception as e:
            logger.exception("Failed to train anomaly model: %s", e)

    def score(self, df: pd.DataFrame) -> Optional[np.ndarray]:
        X = self._features(df)
        if X.shape[0] == 0 or self.model is None:
            return None
        try:
            raw = -self.model.decision_function(X)
            return raw
        except Exception as e:
            logger.exception("Error scoring anomalies: %s", e)
            return None

# ---------------------------
# Alert Engine
# ---------------------------
class AlertEngine:
    def __init__(self, packet_threshold_per_sec=100, anomaly_threshold=0.6):
        self.packet_threshold_per_sec = packet_threshold_per_sec
        self.anomaly_threshold = anomaly_threshold
        self.last_alert_time = defaultdict(lambda: 0.0)
        self.alert_cooldown = 10.0

    def basic_alerts(self, df: pd.DataFrame) -> list:
        alerts = []
        if df.empty:
            return alerts
        try:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            counts = df.groupby(df['timestamp'].dt.floor('S')).size()
            if not counts.empty:
                recent_pps = counts.iloc[-1]
                if recent_pps > self.packet_threshold_per_sec:
                    alerts.append(('pps_spike', f'High packet rate: {recent_pps} pkt/s'))
        except Exception:
            pass

        top_src = df['source'].value_counts().head(5)
        for ip, cnt in top_src.items():
            if cnt > (len(df) * 0.2) and len(df) > 50:
                alerts.append((f'src_flood_{ip}', f'{ip} sends {cnt} of last {len(df)} packets (possible scan/flood)'))

        high_entropy = df[df['payload_entropy'] > 7.0]
        for idx, row in high_entropy.tail(3).iterrows():
            alerts.append((f'high_entropy_{idx}', f'High payload entropy {row["payload_entropy"]:.2f} from {row["source"]}'))

        return alerts

    def anomaly_alerts(self, df: pd.DataFrame, scores: Optional[np.ndarray]) -> list:
        alerts = []
        if df.empty or scores is None:
            return alerts
        try:
            if len(scores) == 0:
                return alerts
            normalized = (scores - scores.min()) / (scores.max() - scores.min() + 1e-9)
            suspicious_idx = np.where(normalized > self.anomaly_threshold)[0]
            for idx in suspicious_idx[-5:]:
                pkt = df.iloc[idx]
                alerts.append((f'anom_{idx}', f'Anomalous packet from {pkt["source"]}:{pkt.get("src_port")} proto={pkt["protocol"]} score={normalized[idx]:.2f}'))
        except Exception:
            pass
        return alerts

    def rate_limit(self, alerts):
        now = time.time()
        out = []
        for key, msg in alerts:
            if now - self.last_alert_time.get(key, 0) > self.alert_cooldown:
                out.append((key, msg))
                self.last_alert_time[key] = now
        return out

# ---------------------------
# Alerts persistence and notifications
# ---------------------------
# SQLite DB for alerts
conn = sqlite3.connect("alerts.db", check_same_thread=False)
c = conn.cursor()
c.execute("""
CREATE TABLE IF NOT EXISTS alerts (
    timestamp TEXT,
    alert_type TEXT,
    message TEXT
)
""")
conn.commit()

def log_alert(alert_type, message):
    ts = datetime.now().isoformat()
    c.execute("INSERT INTO alerts (timestamp, alert_type, message) VALUES (?, ?, ?)", (ts, alert_type, message))
    conn.commit()

# Webhook / Email
WEBHOOK_URL = ""  # add your webhook URL here
EMAIL_ADDRESS = ""  # sender email
EMAIL_PASSWORD = ""  # app password

def send_webhook(alert_type, message):
    if not WEBHOOK_URL:
        return
    payload = {"content": f"[{alert_type}] {message}"}
    try:
        requests.post(WEBHOOK_URL, json=payload, timeout=3)
    except Exception as e:
        logger.warning(f"Webhook failed: {e}")

def send_email_alert(alert_type, message):
    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        return
    msg = EmailMessage()
    msg['Subject'] = f"Network Alert: {alert_type}"
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = EMAIL_ADDRESS
    msg.set_content(message)
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
    except Exception as e:
        logger.warning(f"Email failed: {e}")

SEVERE_ALERTS = ["pps_spike", "src_flood_"]  # types that trigger notifications

# ---------------------------
# Sniff thread starter
# ---------------------------
def start_packet_capture(keep_last=5000, geoip_db_path: Optional[str] = None):
    processor = PacketProcessor(keep_last=keep_last, geoip_db_path=geoip_db_path)
    def _capture():
        sniff(prn=processor.process_packet, store=False)
    t = threading.Thread(target=_capture, daemon=True)
    t.start()
    return processor

# ---------------------------
# Visualization helpers
# ---------------------------
def create_visualizations(df: pd.DataFrame):
    if df.empty:
        st.info("Waiting for packets...")
        return
    protocol_counts = df['protocol'].value_counts()
    fig = px.pie(values=protocol_counts.values, names=protocol_counts.index, title="Protocol Distribution")
    st.plotly_chart(fig, use_container_width=True)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df_grouped = df.groupby(df['timestamp'].dt.floor('S')).size()
    fig2 = px.line(x=df_grouped.index, y=df_grouped.values, title='Packets per Second')
    st.plotly_chart(fig2, use_container_width=True)
    top_src = df['source'].value_counts().head(15)
    fig3 = px.bar(x=top_src.index, y=top_src.values, title='Top Source IPs')
    st.plotly_chart(fig3, use_container_width=True)
    if 'geo_src_lat' in df.columns and 'geo_src_lon' in df.columns:
        geo_df = df.dropna(subset=['geo_src_lat', 'geo_src_lon'])
        if not geo_df.empty:
            geo_plot = px.scatter_geo(
                geo_df,
                lat='geo_src_lat',
                lon='geo_src_lon',
                hover_name='source',
                size='size',
                title='Geographic distribution of sources'
            )
            st.plotly_chart(geo_plot, use_container_width=True)

# ---------------------------
# Main App
# ---------------------------
def main():
    st.set_page_config(page_title="Network Traffic + ML + GeoIP Dashboard", layout='wide')
    st.title("Network Traffic Analysis — ML, GeoIP, Alerts, Payload")

    # Sidebar controls
    st.sidebar.header("Settings")
    geoip_db_path = st.sidebar.text_input("GeoIP2 DB path (optional)", value="")
    pkt_keep = st.sidebar.number_input("Packets to keep in memory", value=2000, min_value=500, max_value=20000, step=500)
    ml_enabled = st.sidebar.checkbox("Enable ML anomaly detection", value=True)
    ml_retrain_every = st.sidebar.number_input("ML retrain every N checks", value=200, min_value=50, max_value=2000, step=50)
    ml_contamination = st.sidebar.slider("IsolationForest contamination", 0.001, 0.2, value=0.01)
    alert_pps_threshold = st.sidebar.number_input("Alert: packets/sec threshold", value=120, min_value=10)
    anomaly_threshold = st.sidebar.slider("Alert: normalized anomaly score threshold (0..1)", 0.1, 1.0, value=0.6)
    payload_regex = st.sidebar.text_input("Payload regex to search (optional)", value="")
    payload_search_enable = st.sidebar.checkbox("Enable payload regex search", value=False)
    payload_entropy_alert = st.sidebar.checkbox("Alert on high payload entropy (>7.0)", value=True)
    show_payload_preview = st.sidebar.checkbox("Show payload preview in table", value=False)
    auto_refresh = st.sidebar.checkbox("Auto refresh every N seconds", value=True)
    auto_refresh_seconds = st.sidebar.number_input("Refresh interval (s)", value=3, min_value=1, max_value=30)

    # Initialize persistent objects
    if 'processor' not in st.session_state:
        st.session_state.processor = start_packet_capture(keep_last=pkt_keep, geoip_db_path=(geoip_db_path or None))
        st.session_state.start_time = time.time()
        st.session_state.detector = AnomalyDetector(retrain_every=ml_retrain_every, contamination=ml_contamination)
        st.session_state.alert_engine = AlertEngine(packet_threshold_per_sec=alert_pps_threshold, anomaly_threshold=anomaly_threshold)
        st.session_state.manual_alerts = deque(maxlen=200)

    st.session_state.detector.retrain_every = ml_retrain_every
    st.session_state.detector.contamination = ml_contamination
    st.session_state.alert_engine.packet_threshold_per_sec = alert_pps_threshold
    st.session_state.alert_engine.anomaly_threshold = anomaly_threshold

    df = st.session_state.processor.get_dataframe()

    # Metrics
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Packets stored", len(df))
    with col2:
        duration = time.time() - st.session_state.start_time
        st.metric("Capture duration", f"{duration:.1f}s")
    with col3:
        avg_pps = 0
        if not df.empty:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            last_window = df[df['timestamp'] >= (pd.Timestamp.now() - pd.Timedelta(seconds=10))]
            if not last_window.empty:
                avg_pps = round(len(last_window)/10.0, 2)
        st.metric("Avg pkt/s (est, 10s)", avg_pps)

    create_visualizations(df)

    # ML: retrain + score
    scores = None
    if ml_enabled:
        st.session_state.detector.maybe_retrain(df)
        scores = st.session_state.detector.score(df)

    # Alerts
    alerts = []
    alerts += st.session_state.alert_engine.basic_alerts(df)
    alerts += st.session_state.alert_engine.anomaly_alerts(df, scores)

    # Payload regex search
    if payload_search_enable and payload_regex and not df.empty:
        try:
            pattern = re.compile(payload_regex)
            for idx, row in df.iterrows():
                preview = row.get('payload_preview', '') or ''
                if pattern.search(preview):
                    alerts.append((f'payload_regex_{idx}', f'Payload regex matched in pkt {idx} source={row["source"]}'))
        except re.error as e:
            st.sidebar.error(f"Invalid regex: {e}")

    # entropy alert toggle
    if payload_entropy_alert and not df.empty:
        high_entropy = df[df['payload_entropy'] > 7.0]
        for idx, row in high_entropy.tail(3).iterrows():
            alerts.append((f'entropy_{idx}', f'High entropy payload from {row["source"]}, entropy={row["payload_entropy"]:.2f}'))

    # filter rate limit
    alerts = st.session_state.alert_engine.rate_limit(alerts)

    # Display alerts + log + notify
    if alerts:
        for key, msg in alerts:
            st.warning(msg)
            log_alert(key, msg)
            if any(key.startswith(sa) for sa in SEVERE_ALERTS):
                send_webhook(key, msg)
                send_email_alert(key, msg)

    # Manual alerts
    st.sidebar.header("Manual Alerts")
    manual_text = st.sidebar.text_input("Raise a manual alert", "")
    if st.sidebar.button("Raise Alert"):
        if manual_text.strip():
            st.session_state.manual_alerts.appendleft((time.time(), manual_text))
            st.sidebar.success("Alert raised")
            log_alert("manual", manual_text)
            send_webhook("manual", manual_text)
            send_email_alert("manual", manual_text)
    if st.session_state.manual_alerts:
        st.sidebar.markdown("**Recent manual alerts**")
        for ts, text in list(st.session_state.manual_alerts)[:10]:
            st.sidebar.write(f"- {datetime.fromtimestamp(ts).isoformat()} — {text}")

    # Export alerts
    if st.sidebar.button("Export Alerts as CSV"):
        df_alerts = pd.read_sql_query("SELECT * FROM alerts", conn)
        df_alerts.to_csv("alerts_export.csv", index=False)
        st.sidebar.success("Alerts exported to alerts_export.csv")

    # Recent packets table
    st.subheader("Recent packets (tail)")
    if df.empty:
        st.write("No packets captured yet.")
    else:
        display_cols = ['timestamp', 'source', 'destination', 'protocol', 'size', 'payload_len', 'payload_entropy']
        if show_payload_preview:
            display_cols.append('payload_preview')
        st.dataframe(df.tail(50)[display_cols].iloc[::-1], use_container_width=True)

    # Inspect packet
    st.subheader("Inspect a packet")
    if not df.empty:
        idx_to_inspect = st.number_input("Index (0 = oldest)", min_value=0, max_value=len(df)-1, value=len(df)-1, step=1)
        pkt_row = df.iloc[int(idx_to_inspect)]
        st.json({
            'timestamp': str(pkt_row['timestamp']),
            'source': pkt_row['source'],
            'destination': pkt_row['destination'],
            'protocol': pkt_row['protocol'],
            'size': int(pkt_row['size']),
            'src_port': pkt_row.get('src_port'),
            'dst_port': pkt_row.get('dst_port'),
            'payload_len': int(pkt_row.get('payload_len', 0)),
            'payload_entropy': float(pkt_row.get('payload_entropy', 0)),
            'payload_preview': pkt_row.get('payload_preview', '')[:200],
            'geo': {
                'country': pkt_row.get('geo_src_country'),
                'city': pkt_row.get('geo_src_city'),
                'lat': pkt_row.get('geo_src_lat'),
                'lon': pkt_row.get('geo_src_lon')
            }
        }, expanded=True)

    # Controls
    if st.button("Refresh Now"):
        st.rerun()

    if auto_refresh:
        time.sleep(auto_refresh_seconds)
        st.rerun()

if __name__ == "__main__":
    main()
