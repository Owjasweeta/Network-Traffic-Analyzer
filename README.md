#  Network Traffic Analysis Dashboard

**Real-time Packet Capture • ML Anomaly Detection • GeoIP • Alerts**

A **real-time network traffic monitoring and analysis dashboard** built with **Streamlit**, **Scapy**, and **Machine Learning**.
The system captures live packets, visualizes traffic patterns, detects anomalies using **Isolation Forest**, enriches IPs with **GeoIP**, and raises alerts with persistence and notifications.

---

##  Features

###  Live Packet Capture

* Real-time packet sniffing using **Scapy**
* Supports **TCP, UDP, ICMP**
* Captures:

  * Source & destination IPs
  * Ports
  * Packet size
  * Payload length
  * Payload entropy
  * Payload preview (safe text)

###  Interactive Dashboard (Streamlit + Plotly)

* Protocol distribution (pie chart)
* Packets per second (time series)
* Top source IPs (bar chart)
* Geographic distribution of traffic (map view)
* Recent packets table with optional payload preview
* Packet-level inspection panel

###  Machine Learning – Anomaly Detection

* Uses **Isolation Forest**
* Features used:

  * Packet size
  * Payload length
  * Payload entropy
  * Source & destination ports
  * Protocol type
* Configurable retraining frequency
* Normalized anomaly scores with threshold-based alerts

### GeoIP Enrichment

* IP-to-location mapping
* Supports:

  * **GeoIP2 database** (offline, optional)
  * **ipinfo.io API** fallback
* Displays country, city, latitude & longitude

###  Alert Engine

* High packet-rate detection (PPS spikes)
* Source IP flood detection
* High-entropy payload alerts
* ML-based anomaly alerts
* Payload regex-based alerts
* Alert rate-limiting to avoid spam

###  Alert Persistence

* Alerts stored in **SQLite**
* Export alerts as CSV
* Manual alert creation from UI

###  Notifications (Optional)

* Webhook alerts (Slack / Discord / custom)
* Email alerts (SMTP)
* Configurable severity-based notifications

---

##  System Architecture

```
Packet Capture (Scapy)
        ↓
Packet Processor
        ↓
Feature Extraction
        ↓
ML Anomaly Detector (Isolation Forest)
        ↓
Alert Engine
        ↓
Dashboard + Notifications + SQLite
```

---

##  Tech Stack

* **Python**
* **Streamlit** – UI & dashboard
* **Scapy** – Packet sniffing
* **Plotly** – Interactive charts
* **Pandas / NumPy** – Data processing
* **Scikit-learn** – ML anomaly detection
* **SQLite** – Alert storage
* **GeoIP2 / ipinfo.io** – Geolocation

---

## ⚙️ Installation

### Clone the Repository

```bash
git clone https://github.com/your-username/network-traffic-dashboard.git
cd network-traffic-dashboard
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

> ⚠️ **Run with root/admin privileges** for packet sniffing:

```bash
sudo streamlit run net_dashboard_full.py
```

---

##  Configuration

### Optional: GeoIP2 Database

* Download **GeoLite2-City.mmdb**
* Provide the path in the sidebar

### Optional: Notifications

Edit the following variables in the code:

```python
WEBHOOK_URL = ""
EMAIL_ADDRESS = ""
EMAIL_PASSWORD = ""
```

---

##  Use Cases

* Network traffic monitoring
* Intrusion & anomaly detection
* Cybersecurity learning projects
* SOC dashboard prototype
* ML-based traffic behavior analysis

---


##  Future Enhancements

* Protocol-specific deep inspection
* Signature-based IDS rules
* Dashboard authentication
* Model persistence
* Multi-interface capture support

