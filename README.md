# AI-Powered SOC Alert Triage & Risk Scoring System

> **A production-grade Security Operations Center automation pipeline that ingests Suricata IDS alerts, enriches them with AbuseIPDB + VirusTotal threat intelligence, scores risk using a trained Random Forest ML model, and delivers prioritized HIGH/CRITICAL alerts to a Kibana analyst dashboard with MITRE ATT&CK mapping.**

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    LAYER 1 — DETECTION                                  │
│  [Network Traffic]  ──►  [Suricata IDS]  ──►  /var/log/suricata/eve.json│
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────────────┐
│                    LAYER 2 — LOG PIPELINE                               │
│  [Filebeat] ──► [Logstash (GeoIP + parse)] ──► [Elasticsearch 8.x]    │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────────────┐
│                    LAYER 3 — ENRICHMENT & SCORING (Python)              │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │  pipeline.py  (polls ES every 30s)                               │  │
│  │    ├── AbuseIPDB API  →  IP reputation score (0-100)            │  │
│  │    ├── VirusTotal API →  malicious engine count                 │  │
│  │    ├── IP Freq Tracker → sliding 60min window count             │  │
│  │    ├── MITRE ATT&CK   → tactic + technique mapping              │  │
│  │    └── Random Forest  → LOW / MEDIUM / HIGH / CRITICAL          │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│  [Redis Cache]  ←─── API result caching (1hr TTL)                     │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────────────┐
│                    LAYER 4 — ROUTING & VISUALIZATION                    │
│  LOW      →  suppressed (stored, not shown)                            │
│  MEDIUM   →  stored for weekly review                                  │
│  HIGH     →  Kibana dashboard + Slack notification                     │
│  CRITICAL →  Kibana dashboard + Slack + Email                          │
│  [Kibana Dashboard] — Attack map, risk distribution, MITRE heatmap     │
└─────────────────────────────────────────────────────────────────────────┘
```

## Technology Stack

| Component        | Version | Purpose                                    |
|------------------|---------|--------------------------------------------|
| Python           | 3.10+   | Enrichment engine, ML pipeline             |
| Suricata IDS     | 7.x     | Network intrusion detection                |
| Elasticsearch    | 8.x     | Alert storage, indexing, fast search       |
| Logstash         | 8.x     | Log parsing, GeoIP enrichment pipeline     |
| Kibana           | 8.x     | Analyst dashboard & visualization          |
| Filebeat         | 8.x     | Real-time log shipping agent               |
| scikit-learn     | 1.4+    | Random Forest risk scoring model           |
| AbuseIPDB API    | v2      | IP reputation (0-100 abuse score)          |
| VirusTotal API   | v3      | IP/hash/domain threat intelligence         |
| Redis            | 7.x     | API result caching layer                   |
| Docker Compose   | 3.8     | Full-stack container deployment            |

---

## Project Structure

```
soc-triage/
├── config/
│   ├── config.py                 # All settings via environment variables
│   ├── logstash-suricata.conf    # Logstash pipeline for Suricata EVE JSON
│   └── filebeat.yml              # Filebeat agent configuration
├── enrichment/
│   └── enrichment.py             # AbuseIPDB, VirusTotal, MITRE ATT&CK
├── ml/
│   ├── generate_training_data.py # Synthetic training data generator
│   ├── train_model.py            # Random Forest training pipeline
│   └── ml_scorer.py              # Real-time risk scoring engine
├── pipeline/
│   └── pipeline.py               # Main orchestration loop
├── scripts/
│   └── simulate_attacks.py       # Nmap, Hydra, SQLi attack simulation
├── dashboards/
│   └── kibana-dashboard.json     # Kibana dashboard definition
├── tests/
│   └── test_suite.py             # 32 unit + integration tests
├── model/                        # Trained model artefacts (git-ignored)
│   ├── rf_model.pkl
│   ├── le_category.pkl
│   ├── le_protocol.pkl
│   ├── le_label.pkl
│   ├── feature_columns.pkl
│   └── model_metadata.json
├── data/                         # Training data (git-ignored)
│   └── training_data.csv
├── logs/                         # Pipeline logs (git-ignored)
├── Dockerfile                    # Multi-stage Python container
├── docker-compose.yml            # Full ELK + Python stack
├── requirements.txt              # Pinned Python dependencies
├── .env.example                  # Configuration template
└── README.md
```

---

## Quick Start — Docker Deployment (Recommended)

### Prerequisites
- Docker 24+ and Docker Compose 2+
- API keys from AbuseIPDB and VirusTotal (free tiers available)
- 16 GB RAM recommended (ELK is memory-heavy)

### 1. Clone and configure

```bash
git clone https://github.com/YOUR_USERNAME/soc-alert-triage.git
cd soc-alert-triage

# Set your API keys
cp .env.example .env
nano .env   # Fill in ABUSEIPDB_API_KEY and VIRUSTOTAL_API_KEY
```

### 2. Create Elasticsearch data directory

```bash
mkdir -p data/elasticsearch
```

### 3. Start the stack

```bash
docker-compose up -d

# Watch the pipeline start up
docker-compose logs -f soc-pipeline
```

### 4. Verify services are running

```bash
# Elasticsearch
curl http://localhost:9200/_cluster/health?pretty

# Kibana (wait ~90s for startup)
curl http://localhost:5601/api/status

# Check pipeline logs
docker-compose logs soc-pipeline --tail=50
```

### 5. Open Kibana dashboard

Navigate to: **http://localhost:5601**

---

## Manual / Bare-Metal Setup

### Step 1 — System dependencies

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip python3-venv git curl wget net-tools nmap hydra
```

### Step 2 — Python environment

```bash
cd ~/soc-triage
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Step 3 — Configure environment

```bash
cp .env.example .env
nano .env
# Set: ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY
```

### Step 4 — Install Suricata

```bash
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update && sudo apt install -y suricata
sudo suricata-update
```

Edit `/etc/suricata/suricata.yaml`:
```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16]"

af-packet:
  - interface: enp0s3   # Change to your interface: ip link show

outputs:
  - eve-log:
      enabled: yes
      filename: /var/log/suricata/eve.json
      types:
        - alert:
            payload: yes
```

```bash
sudo systemctl start suricata && sudo systemctl enable suricata
```

### Step 5 — Install ELK Stack

```bash
# Add Elastic repository
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | \
  sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] \
  https://artifacts.elastic.co/packages/8.x/apt stable main" | \
  sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt update

# Install components
sudo apt install -y elasticsearch logstash kibana filebeat

# Configure Elasticsearch (disable security for lab)
sudo nano /etc/elasticsearch/elasticsearch.yml
# Set: xpack.security.enabled: false
# Set: network.host: 127.0.0.1

# Set JVM heap (use half your RAM, max 8G)
echo "-Xms2g
-Xmx2g" | sudo tee /etc/elasticsearch/jvm.options.d/heap.options

# Start services
sudo systemctl start elasticsearch kibana
sudo systemctl enable elasticsearch kibana

# Deploy Logstash pipeline
sudo cp config/logstash-suricata.conf /etc/logstash/conf.d/
sudo systemctl start logstash && sudo systemctl enable logstash

# Deploy Filebeat config
sudo cp config/filebeat.yml /etc/filebeat/filebeat.yml
sudo systemctl start filebeat && sudo systemctl enable filebeat
```

### Step 6 — Train the ML model

```bash
# Generate synthetic training data
python3 ml/generate_training_data.py

# Train the Random Forest model
python3 ml/train_model.py
```

### Step 7 — Start the pipeline

```bash
# Foreground (development)
python3 pipeline/pipeline.py

# Background (production)
nohup python3 pipeline/pipeline.py > logs/pipeline.log 2>&1 &

# As a systemd service (production)
sudo cp scripts/soc-pipeline.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start soc-pipeline
sudo systemctl enable soc-pipeline
```

---

## Kibana Dashboard Setup

1. Open **http://localhost:5601**
2. Go to: **Stack Management → Index Patterns → Create index pattern**
   - Pattern: `suricata-alerts-*`
   - Time field: `@timestamp`
3. Go to: **Stack Management → Saved Objects → Import**
   - Import `dashboards/kibana-dashboard.json`
4. Go to: **Analytics → Dashboard → SOC Alert Triage — Main Dashboard**
5. Set time range: **Last 24 hours**, auto-refresh: **30 seconds**

### Dashboard Panels

| Panel | Type | Purpose |
|-------|------|---------|
| Alert Risk Distribution | Donut chart | LOW/MEDIUM/HIGH/CRITICAL breakdown |
| Top 10 Attacking IPs | Bar chart | Most active source IPs by volume |
| Alerts Over Time | Area chart | Attack timeline with risk level split |
| Global Attack Origin Map | Map (heatmap) | Geographic source of attacks |
| Alert Category Breakdown | Horizontal bar | Suricata category distribution |
| MITRE ATT&CK Techniques | Data table | Technique ID, tactic, count |
| HIGH/CRITICAL Alert Feed | Data table | Live feed for analyst triage |
| Targeted Ports | Pie chart | Top destination ports |
| AbuseIPDB Score Distribution | Histogram | Threat intelligence score spread |

---

## Attack Simulation

Generate real alerts in your lab environment:

```bash
# ⚠️  ONLY run against machines you OWN / have permission to test

# Full simulation suite
python3 scripts/simulate_attacks.py --target 192.168.56.101 --attack all

# Individual attack types
python3 scripts/simulate_attacks.py --target 192.168.56.101 --attack nmap
python3 scripts/simulate_attacks.py --target 192.168.56.101 --attack brute
python3 scripts/simulate_attacks.py --target 192.168.56.101 --attack sqli
python3 scripts/simulate_attacks.py --target 192.168.56.101 --attack dos

# Verify alerts flowing to Suricata
sudo tail -f /var/log/suricata/eve.json | python3 -m json.tool

# Verify alerts in Elasticsearch
curl 'http://localhost:9200/suricata-alerts-*/_count?pretty'
```

### What Each Attack Triggers

| Attack | Tool | Suricata Rule Category |
|--------|------|------------------------|
| SYN port scan | Nmap `-sS` | ET SCAN, Attempted Information Leak |
| OS fingerprinting | Nmap `-A` | ET SCAN, Information Leak |
| SSH brute force | Hydra | ET BRUTE, Brute Force |
| FTP brute force | Hydra | ET BRUTE, Brute Force |
| SQL injection | curl/sqlmap | ET SQL, Web Application Attack |
| Directory traversal | curl | ET WEB_SERVER, Attempted Information Leak |
| Slowloris DoS | Python sockets | ET DOS, Denial of Service |

---

## ML Model Details

### Features

| Feature | Source | Importance |
|---------|--------|-----------|
| `threat_composite` | Computed | ~29% — weighted TI signal |
| `abuse_confidence_score` | AbuseIPDB | ~23% — IP reputation |
| `src_ip_freq_log` | Computed | ~15% — log-scaled frequency |
| `src_ip_frequency` | Pipeline | ~14% — sliding window count |
| `vt_malicious_count` | VirusTotal | ~14% — engine detections |
| `alert_severity` | Suricata | ~2% — native severity |
| `alert_category_encoded` | Suricata | ~2% — attack category |

### Model Performance (on synthetic data)

```
Test Accuracy:  99.9%
CV Accuracy:    99.9% ± 0.1%
OOB Score:      99.9%
Macro ROC-AUC:  1.000
```

### Confidence-Based Downgrading

| Predicted | Condition | Result |
|-----------|-----------|--------|
| CRITICAL | confidence < 85% | Downgraded to HIGH |
| HIGH | confidence < 70% | Downgraded to MEDIUM |

### Rule-Based Overrides (pre-ML)

| Condition | Result |
|-----------|--------|
| AbuseIPDB=100 AND VT≥10 | Force CRITICAL |
| TOR exit node AND VT≥5 | Force HIGH |

---

## Testing

```bash
# Run full test suite (32 tests)
pytest tests/ -v

# Run with coverage report
pytest tests/ -v --cov=. --cov-report=term-missing

# Run specific test class
pytest tests/test_suite.py::TestMitreMapping -v
pytest tests/test_suite.py::TestIPFrequencyTracker -v
pytest tests/test_suite.py::TestRuleBasedOverrides -v
```

---

## Pipeline Configuration

All settings are controlled via environment variables in `.env`:

| Variable | Default | Description |
|----------|---------|-------------|
| `ABUSEIPDB_API_KEY` | — | AbuseIPDB API key (required) |
| `VIRUSTOTAL_API_KEY` | — | VirusTotal API key (required) |
| `ELASTICSEARCH_HOST` | `http://localhost:9200` | ES endpoint |
| `ELASTICSEARCH_INDEX` | `suricata-alerts-*` | Index pattern |
| `POLL_INTERVAL` | `30` | Seconds between ES polls |
| `BATCH_SIZE` | `50` | Alerts per processing cycle |
| `CACHE_TTL` | `3600` | TI result cache TTL in seconds |
| `CONFIDENCE_THRESHOLD` | `0.70` | HIGH→MEDIUM downgrade threshold |
| `USE_REDIS` | `false` | Enable Redis for distributed caching |
| `SLACK_WEBHOOK_URL` | — | Slack webhook for HIGH/CRITICAL alerts |

---

## Troubleshooting

### Elasticsearch won't start
```bash
# Check JVM heap — must be less than 50% of total RAM
cat /etc/elasticsearch/jvm.options.d/heap.options
sudo journalctl -u elasticsearch -n 50
```

### No alerts appearing in Kibana
```bash
# Check each stage of the pipeline
sudo systemctl status suricata filebeat logstash
sudo tail -f /var/log/suricata/eve.json
sudo journalctl -u filebeat -n 30
curl 'http://localhost:9200/suricata-alerts-*/_count'
```

### Pipeline exits immediately
```bash
# Model not trained yet
python3 ml/generate_training_data.py
python3 ml/train_model.py
# Then restart pipeline
```

### API rate limit errors
- AbuseIPDB free tier: 1,000 req/day → increase `ABUSEIPDB_RATE_LIMIT_DELAY`
- VirusTotal free tier: 4 req/min → `VIRUSTOTAL_RATE_LIMIT_DELAY=15` (default)
- Enable Redis caching: `USE_REDIS=true` to dramatically reduce API calls

### High memory usage
```bash
# Reduce Elasticsearch heap
sudo nano /etc/elasticsearch/jvm.options.d/heap.options
# Change -Xms2g / -Xmx2g to -Xms1g / -Xmx1g
```

---

## Production Improvements

| Feature | Implementation |
|---------|----------------|
| Redis caching | Set `USE_REDIS=true` — dramatically reduces TI API calls |
| Async pipeline | Replace requests with aiohttp + asyncio for 10x throughput |
| Alert deduplication | Built-in `AlertDeduplicator` with 5-min TTL window |
| Sliding window frequency | Built-in `IPFrequencyTracker` with 60-min window |
| Confidence thresholding | Prevents uncertain HIGH predictions from flooding analysts |
| Rule-based overrides | Handles deterministic edge cases before ML |
| Batch ES updates | Uses Elasticsearch bulk API for write performance |
| Slack/Email notifications | Built-in for CRITICAL alerts |
| Systemd service | Run pipeline as a managed background service |
| Docker Compose | Full stack deployment with health checks |

---

## Security Notes

- **Never** commit `.env` to git — contains API keys
- Disable `xpack.security.enabled: false` in production Elasticsearch
- Use network isolation (firewall rules) to restrict ES/Kibana to localhost
- Run the Python pipeline as a non-root user
- Rotate API keys regularly and monitor usage in AbuseIPDB/VirusTotal dashboards

---

## License

MIT License — see LICENSE file.

## Author

Built as a real SOC automation project demonstrating:
- End-to-end IDS → SIEM → ML → Dashboard pipeline
- Production Python engineering patterns
- Security operations automation at scale
