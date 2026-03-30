# Network Packet Monitoring Toolkit

A comprehensive Python toolkit for capturing, analysing, and visualising network traffic — with GeoIP enrichment, ML traffic classification, VoIP/RTP analysis, PII redaction, and real-time alerting.

> **Legal Notice:** For educational and authorised network monitoring only. Ensure you have explicit written permission before capturing traffic on any network you do not own.

---

## Table of Contents

1. [Project Structure](#project-structure)
2. [Step-by-Step Setup](#step-by-step-setup)
3. [Step-by-Step Usage Guide](#step-by-step-usage-guide)
   - [Step 1 — Capture live traffic](#step-1--capture-live-traffic)
   - [Step 2 — Analyse a PCAP file](#step-2--analyse-a-pcap-file)
   - [Step 3 — Scan a network](#step-3--scan-a-network)
   - [Step 4 — Extract SSL/TLS certificates](#step-4--extract-ssltls-certificates)
   - [Step 5 — GeoIP enrichment](#step-5--geoip-enrichment)
   - [Step 6 — ML traffic classification](#step-6--ml-traffic-classification)
   - [Step 7 — VoIP / RTP analysis](#step-7--voip--rtp-analysis)
   - [Step 8 — PII redaction before export](#step-8--pii-redaction-before-export)
   - [Step 9 — Real-time alerts](#step-9--real-time-alerts)
   - [Step 10 — Visualise results](#step-10--visualise-results)
4. [Python API Quick Reference](#python-api-quick-reference)
5. [Configuration](#configuration)
6. [Running Tests](#running-tests)

---

## Project Structure

```
packet_sniffers/
├── main.py                     ← CLI entry point (all commands)
├── requirements.txt
├── config/
│   └── default.yaml            ← Runtime configuration
├── src/
│   ├── capture/
│   │   └── packet_sniffer.py   ← Live capture (IPv4 + IPv6)
│   ├── analysis/
│   │   └── protocol_analyzer.py ← PCAP analysis (Scapy + PyShark)
│   ├── scanning/
│   │   └── network_scanner.py  ← Host discovery, port scanning, nmap
│   ├── decryption/
│   │   └── traffic_decryptor.py ← TLS/SSL metadata + cert extraction
│   ├── visualization/
│   │   └── network_visualizer.py ← Charts, dashboards
│   ├── geo/
│   │   └── geo_lookup.py       ← GeoIP (MaxMind DB or ip-api.com)
│   ├── ml/
│   │   └── traffic_classifier.py ← RandomForest + anomaly detection
│   ├── voip/
│   │   └── rtp_analyzer.py     ← SIP sessions + RTP stream quality
│   ├── privacy/
│   │   └── pii_redactor.py     ← PII scanning + redaction
│   ├── alerts/
│   │   └── alert_manager.py    ← Real-time rule-based alerting
│   └── utils/
│       └── common.py           ← Config, logging, export helpers
├── tests/
│   └── test_toolkit.py         ← 82-test suite (pytest)
└── examples/                   ← Standalone example scripts
```

---

## Step-by-Step Setup

### Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.8+ | 3.10+ recommended (enables full TLS chain extraction) |
| tshark | any | Required by PyShark backend — install via Wireshark |
| nmap | any | Optional — enables advanced scanning |

### 1. Clone and enter the project

```bash
git clone <repository-url>
cd packet_sniffers
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate        # macOS / Linux
# .venv\Scripts\activate         # Windows
```

### 3. Install system dependencies (macOS)

```bash
brew install wireshark nmap
```

For Debian/Ubuntu:

```bash
sudo apt install tshark nmap
```

### 4. Install Python dependencies

**Core only** (no ML, no GeoIP local DB):

```bash
pip install scapy pyshark cryptography matplotlib seaborn pandas numpy \
            requests pyyaml psutil python-nmap rich colorama
```

**Full install** (includes ML classification and GeoIP):

```bash
pip install -r requirements.txt
```

> `scikit-learn` and `geoip2` are listed as optional in `requirements.txt`.
> The toolkit degrades gracefully — rule-based classification works without sklearn,
> and GeoIP falls back to the free ip-api.com API without the local database.

### 5. Verify the installation

```bash
python3 -m pytest tests/test_toolkit.py -q
# Expected: 82 passed
```

### 6. Check available commands

```bash
python3 main.py --help
```

---

## Step-by-Step Usage Guide

### Step 1 — Capture live traffic

Packet capture requires root/admin privileges.

```bash
# List available interfaces
python3 main.py capture --list-interfaces

# Capture 200 packets on en0, save to file
sudo python3 main.py capture -i en0 -c 200 -o capture.pcap

# Capture only HTTP/HTTPS traffic for 60 seconds
sudo python3 main.py capture -i en0 -f "tcp port 80 or tcp port 443" -t 60 -o web.pcap

# Capture indefinitely (Ctrl+C to stop)
sudo python3 main.py capture -i en0
```

Captured packets are saved as PCAP files that feed all other commands.

**Python API:**

```python
from src.capture.packet_sniffer import PacketSniffer

sniffer = PacketSniffer(interface="en0", filter_expr="tcp port 443")
sniffer.start_capture(count=100, save_to_file="capture.pcap")
sniffer.print_statistics()
```

---

### Step 2 — Analyse a PCAP file

```bash
# Print analysis report to console
python3 main.py analyze capture.pcap

# Save text report and JSON export
python3 main.py analyze capture.pcap -r report.txt -j results.json

# Analyse and generate visualisations
python3 main.py analyze capture.pcap --visualize

# Analyse, export JSON, and redact PII before saving
python3 main.py analyze capture.pcap -j results.json --redact-pii
```

The report includes:
- Protocol distribution (IPv4, IPv6, TCP, UDP, HTTP, DNS, TLS, QUIC, …)
- Top IP conversations
- HTTP hosts and user-agents
- DNS query analysis
- Suspicious pattern detection (port scans, SYN floods, bad TLDs)
- IPv6 enumeration detection

**Python API:**

```python
from src.analysis.protocol_analyzer import ProtocolAnalyzer

analyzer = ProtocolAnalyzer("capture.pcap")
analyzer.load_pcap("capture.pcap")
results = analyzer.analyze_protocols()

report = analyzer.generate_report("report.txt")
analyzer.export_to_json("results.json")

suspicious = analyzer.detect_suspicious_patterns()
for item in suspicious:
    print(f"[!] {item['description']}")
```

---

### Step 3 — Scan a network

> **Rate limiting is on by default** (`--scan-delay 0.05`).
> Increase for quieter scanning; set to 0 for speed (may trigger IDS).

```bash
# Discover all live hosts on a subnet
python3 main.py scan 192.168.1.0/24

# Comprehensive scan of a single host (ports + services + OS)
python3 main.py scan 192.168.1.1 --comprehensive

# Comprehensive scan with custom port range
python3 main.py scan 192.168.1.1 --comprehensive -p 1-10000

# Use nmap for richer results (version detection)
python3 main.py scan 192.168.1.0/24 --nmap --nmap-type tcp

# Ping scan only (no port scanning)
python3 main.py scan 192.168.1.0/24 --ping-only

# Discover hosts and enrich with GeoIP
python3 main.py scan 192.168.1.0/24 --ping-only --geo

# Adjust rate limiting (slower = stealthier)
python3 main.py scan 192.168.1.1 --comprehensive --scan-delay 0.2 --max-threads 20
```

**Python API:**

```python
from src.scanning.network_scanner import NetworkScanner

scanner = NetworkScanner("192.168.1.0/24", max_threads=50, scan_delay=0.05)

# Host discovery
hosts = scanner.scan_network()

# Full host scan
result = scanner.comprehensive_scan("192.168.1.1", port_range=(1, 1024))
print(result['open_ports'])
print(result['services'])
print(result['os_detection'])

# Nmap scan (if python-nmap is installed)
nmap_results = scanner.nmap_scan("tcp", port_range="1-1024", service_detection=True)
```

---

### Step 4 — Extract SSL/TLS certificates

```bash
# Extract the full certificate chain from a live server
python3 main.py ssl-cert google.com
python3 main.py ssl-cert example.com -p 8443
```

Output includes subject CN, issuer CN, validity period, SHA-256 fingerprint, and SANs.

**Python API:**

```python
from src.decryption.traffic_decryptor import TrafficDecryptor

decryptor = TrafficDecryptor()
certs = decryptor.extract_certificate_chain("google.com", 443)

for cert in certs:
    print(cert['subject_cn'], cert['not_after'], cert['san'])
```

To analyse encrypted traffic metadata from a PCAP (no decryption — metadata only):

```python
# Pass raw payload bytes from captured packets
metadata = decryptor.analyze_encrypted_metadata(packet_payloads)
print(decryptor.generate_encryption_report(metadata))
```

---

### Step 5 — GeoIP enrichment

```bash
# Look up one or more IP addresses
python3 main.py geo 8.8.8.8 1.1.1.1 142.250.191.14

# Use a local MaxMind GeoLite2 database (faster, no rate limits)
python3 main.py geo 8.8.8.8 --db /path/to/GeoLite2-City.mmdb

# Add geo enrichment to any network scan
python3 main.py scan 192.168.1.0/24 --ping-only --geo
```

Without a local DB the tool uses the free [ip-api.com](http://ip-api.com) API (45 req/min).
To get a free MaxMind database: [maxmind.com/en/geolite2/signup](https://www.maxmind.com/en/geolite2/signup)

**Python API:**

```python
from src.geo.geo_lookup import GeoIPLookup

geo = GeoIPLookup()                              # ip-api.com fallback
# geo = GeoIPLookup(db_path="GeoLite2-City.mmdb")  # local DB

info = geo.lookup("8.8.8.8")
# {'country': 'United States', 'city': 'Mountain View', 'isp': 'Google LLC', ...}

# Enrich conversation data from a protocol analysis
enriched = geo.enrich_conversations(results['ip_conversations'])
```

---

### Step 6 — ML traffic classification

Classification works in two modes:
- **Rule-based** (always): port-number heuristics, no dependencies required
- **ML** (optional): RandomForest trained on your own captures; requires `scikit-learn`

```bash
# Rule-based classification (no training needed)
python3 main.py classify capture.pcap

# Train on the PCAP, then classify it (self-supervised using port rules as labels)
python3 main.py classify capture.pcap --train

# Train, save the model, then classify
python3 main.py classify capture.pcap --train --save-model model.joblib

# Use a previously trained model
python3 main.py classify new_capture.pcap --model model.joblib
```

**Python API:**

```python
from src.ml.traffic_classifier import TrafficClassifier

clf = TrafficClassifier()

# Rule-based (instant, no training)
label = clf.rule_based_classify({'src_port': 55123, 'dst_port': 443})
# → 'web'

# Batch classification with anomaly detection
packet_list = [...]   # list of packet info dicts from ProtocolAnalyzer
clf.train(packet_list)
results = clf.classify_traffic_batch(packet_list)

print(results['category_distribution'])
print(f"Anomalies: {results['anomalies_detected']}")
print(clf.get_feature_importance())
```

---

### Step 7 — VoIP / RTP analysis

```bash
# Analyse SIP sessions and RTP stream quality in a PCAP
python3 main.py voip capture.pcap

# Save the full report as JSON
python3 main.py voip capture.pcap -j voip_report.json
```

Output includes:
- SIP call states (inviting / active / terminated)
- Per-stream RTP quality: packet loss %, jitter, codec, out-of-order count
- Average loss rate across all streams

**Python API:**

```python
from src.voip.rtp_analyzer import VoIPAnalyzer
from src.analysis.protocol_analyzer import ProtocolAnalyzer

# Load packets
analyzer = ProtocolAnalyzer("capture.pcap")
analyzer.load_pcap("capture.pcap")

# Analyse
voip = VoIPAnalyzer()
report = voip.analyze_scapy_packets(analyzer.packets)

for stream in report['stream_quality']:
    print(f"SSRC {stream['ssrc']}: loss={stream['loss_rate_pct']}%  "
          f"jitter={stream['jitter']}  codec={stream['codec']}")

for call in report['sip_calls']:
    print(f"[{call['state']}] {call['from']} → {call['to']}")
```

---

### Step 8 — PII redaction before export

Use this before saving any analysis results that may contain personal data.

```bash
# Auto-redact PII from JSON export during analysis
python3 main.py analyze capture.pcap -j clean_results.json --redact-pii
```

Redacted types: emails, US phone numbers, SSNs, credit cards, public IPv4 addresses,
MAC addresses, URLs with embedded credentials, Bearer/Basic auth tokens, AWS access keys, JWTs.

**Python API:**

```python
from src.privacy.pii_redactor import PIIRedactor

redactor = PIIRedactor()

# Redact a string
clean = redactor.redact_string("Contact admin@corp.com, card: 4111111111111111")
# → "Contact [EMAIL], card: [CREDIT_CARD]"

# Recursively redact a full analysis result dict
clean_results = redactor.redact_dict(analysis_results)

# Audit first — find PII without redacting
findings = redactor.scan_for_pii(analysis_results)
print(findings)   # {'email': ['admin@corp.com'], ...}

# Check what was redacted
print(redactor.get_stats())   # {'email': 3, 'credit_card': 1}
```

---

### Step 9 — Real-time alerts

```bash
# Run alert detection against a PCAP
python3 main.py alerts capture.pcap

# Save all triggered alerts to a JSONL file
python3 main.py alerts capture.pcap --output alerts.jsonl
```

Built-in rules: port scan detection, SYN flood, DNS flood, suspicious TLDs,
jumbo frame detection. All fire with configurable cooldown periods.

**Python API — integrate into live capture:**

```python
from src.alerts.alert_manager import AlertManager, AlertRule, AlertSeverity

mgr = AlertManager()
mgr.add_file_channel("alerts.jsonl")
mgr.add_webhook_channel("https://hooks.example.com/alerts",
                         min_severity=AlertSeverity.HIGH)
mgr.start()

# After each analysis run:
results = analyzer.analyze_protocols()
mgr.check(results)

# Fire a manual alert
mgr.fire(AlertSeverity.CRITICAL, "custom_rule", "Detected C2 beacon pattern",
         details={"dst_ip": "1.2.3.4"})

print(mgr.get_summary())
mgr.stop()
```

**Add a custom rule:**

```python
from src.alerts.alert_manager import AlertRule, AlertSeverity

def my_rule(data):
    convs = data.get('ip_conversations', {})
    heavy = {k: v for k, v in convs.items() if v > 10000}
    if heavy:
        return f"High-volume conversation: {list(heavy.keys())[0]}", heavy, None, None
    return None

mgr.add_rule(AlertRule("high_volume", my_rule, AlertSeverity.MEDIUM, cooldown_seconds=120))
```

---

### Step 10 — Visualise results

```bash
# Create all charts from a saved JSON analysis
python3 main.py visualize results.json

# Create a single comprehensive dashboard image
python3 main.py visualize results.json --dashboard

# Auto-generate charts during analysis
python3 main.py analyze capture.pcap --visualize
```

Charts are saved as PNG files in `visualizations/`:
- `protocol_distribution.png` — pie chart
- `port_activity.png` — bar chart of top ports
- `ip_conversations.png` — horizontal bar chart
- `traffic_timeline.png` — packets-per-minute over time
- `packet_size_distribution.png` — histogram + box plot
- `network_map.png` — host topology
- `dashboard.png` — all panels combined

**Python API:**

```python
from src.visualization.network_visualizer import NetworkVisualizer

viz = NetworkVisualizer(output_dir="visualizations")
viz.plot_protocol_distribution(results['protocols'])
viz.plot_port_activity(results['port_analysis'])
viz.plot_ip_conversations(results['ip_conversations'])
viz.create_comprehensive_dashboard(results)
```

---

## Python API Quick Reference

| Import | Class | Key methods |
|---|---|---|
| `src.capture.packet_sniffer` | `PacketSniffer` | `start_capture()`, `print_statistics()` |
| `src.analysis.protocol_analyzer` | `ProtocolAnalyzer` | `load_pcap()`, `analyze_protocols()`, `generate_report()`, `export_to_json()` |
| `src.scanning.network_scanner` | `NetworkScanner` | `scan_network()`, `comprehensive_scan()`, `nmap_scan()` |
| `src.decryption.traffic_decryptor` | `TrafficDecryptor` | `extract_certificate_chain()`, `analyze_ssl_tls_traffic()`, `detect_ssh_traffic()` |
| `src.geo.geo_lookup` | `GeoIPLookup` | `lookup()`, `batch_lookup()`, `enrich_conversations()` |
| `src.ml.traffic_classifier` | `TrafficClassifier` | `rule_based_classify()`, `classify_traffic_batch()`, `train()`, `save_model()` |
| `src.voip.rtp_analyzer` | `VoIPAnalyzer` | `analyze_scapy_packets()`, `calculate_stream_quality()`, `generate_report()` |
| `src.privacy.pii_redactor` | `PIIRedactor` | `redact_string()`, `redact_dict()`, `scan_for_pii()` |
| `src.alerts.alert_manager` | `AlertManager` | `start()`, `check()`, `fire()`, `get_alerts()`, `get_summary()` |
| `src.visualization.network_visualizer` | `NetworkVisualizer` | `plot_protocol_distribution()`, `create_comprehensive_dashboard()` |

---

## Configuration

Edit `config/default.yaml` to tune defaults:

```yaml
capture:
  interface: auto          # interface name or 'auto'
  buffer_size: 65536
  promiscuous_mode: true
  max_packets: 0           # 0 = unlimited

analysis:
  deep_inspection: true
  suspicious_pattern_detection: true
  export_format: json

scanning:
  ping_timeout: 3          # ping timeout in seconds
  port_scan_timeout: 1     # per-port TCP timeout
  max_threads: 100         # thread pool size
  common_ports_only: false # true = only scan well-known ports

visualization:
  output_dir: visualizations
  image_format: png
  dpi: 300

logging:
  level: INFO
  log_file: packet_sniffer.log
  max_file_size: 10MB
  backup_count: 5

security:
  require_admin: true      # set false to skip the privilege warning
  allowed_interfaces: []   # empty = all interfaces allowed
  encryption_analysis: true

performance:
  enable_monitoring: true
  memory_limit_mb: 1024
  cpu_limit_percent: 80
```

> **Note:** `--scan-delay` and `--max-threads` are CLI flags on the `scan` command, not config file keys. They override the scanner defaults at runtime.

---

## Running Tests

```bash
# Run the full test suite
python3 -m pytest tests/test_toolkit.py -v

# Quick pass/fail summary
python3 -m pytest tests/test_toolkit.py -q

# Run a single test class
python3 -m pytest tests/test_toolkit.py::TestVoIPAnalyzer -v
```

Expected output: **82 tests, 0 failures**.

---

## Requirements

- Python 3.8+ (3.10+ for full TLS chain extraction)
- root/admin privileges for live packet capture
- tshark (Wireshark CLI) for PyShark backend
- nmap for advanced scanning (optional)
- scikit-learn for ML classification (optional)
- MaxMind GeoLite2-City.mmdb for offline GeoIP (optional — falls back to ip-api.com)
