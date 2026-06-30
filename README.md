# 🎰 Gambling OSINT — Cyber Threat Intelligence Automation Platform

An end-to-end OSINT automation pipeline for discovering, classifying, enriching, and reporting on online gambling websites targeting Indian users.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Pipeline Stages](#pipeline-stages)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Extending the System](#extending-the-system)
- [Output Files](#output-files)

---

## Overview

This platform automates the intelligence collection and analysis workflow for identifying and profiling online gambling operations, particularly those targeting Indian users. It combines domain discovery, web content analysis, DNS/infrastructure enrichment, and infrastructure correlation into a single, modular pipeline.

### Key Capabilities

- **Multi-source domain discovery** with plugin architecture
- **Automated web content classification** using weighted scoring
- **Comprehensive infrastructure analysis** (DNS, WHOIS, ASN, hosting)
- **Infrastructure correlation** to identify related domain networks
- **Professional Excel reporting** with color-coded sheets and statistics

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    PIPELINE ORCHESTRATOR                     │
│                      (pipeline.py)                          │
├──────────┬──────────┬──────────┬──────────┬─────────────────┤
│ Stage 1  │ Stage 2  │ Stage 3  │ Stage 4  │    Reporting    │
│Discovery │Classify  │ Enrich   │Correlate │   Generator     │
│          │          │          │          │                 │
│ Excel    │ HTTP     │ DNS A/   │ Hosting  │ Multi-sheet     │
│ Manual   │ Fetch    │ AAAA/NS/ │ ASN      │ Excel with      │
│ CSV      │ BS4      │ MX/TXT   │ Country  │ charts &        │
│ Keyword  │ Parse    │ SOA      │ Namesvr  │ statistics      │
│ CT Logs* │ Score    │ RDAP/    │ IP       │                 │
│ Search*  │ Classify │ IPWhois  │ CIDR     │                 │
├──────────┴──────────┴──────────┴──────────┴─────────────────┤
│                 config.py  │  utils.py                      │
│            (Configuration) │ (Shared Utilities)             │
└─────────────────────────────────────────────────────────────┘
                        * = stub/future
```

---

## Pipeline Stages

### Stage 1 — Domain Discovery (`discover.py`)

Collects candidate gambling-related domains from multiple sources:

| Source | Status | Description |
|--------|--------|-------------|
| Excel Import | ✅ Active | Imports from existing investigation spreadsheet |
| Manual List | ✅ Active | Plain-text file, one domain per line |
| CSV Import | ✅ Active | Auto-detects domain column in CSV files |
| Keyword Generation | ✅ Active | Generates candidates from keyword × TLD combinations |
| Certificate Transparency | 🔲 Stub | Ready for crt.sh API integration |
| Search Engine | 🔲 Stub | Ready for search API integration |

All domains are normalized, validated, deduplicated, and stored with their discovery source.

### Stage 2 — Classification & Scoring (`classify.py`)

For each domain, the system:
1. Fetches the live website (HTTPS → HTTP fallback)
2. Extracts title, meta tags, visible text
3. Scores **gambling relevance** (30+ keyword indicators)
4. Scores **India targeting** (payment methods, sports, language, currency, TLD)
5. Assigns classification categories with confidence scores

**Classification Categories:**
- `Gambling-Related` / `Possibly Gambling-Related` / `Not Gambling-Related`
- `India-Focused` / `Possibly India-Focused`

### Stage 3 — Infrastructure Enrichment (`enrich.py`)

Extends the original `main2.py` script into a batch-processing engine:

| Record Type | Description |
|-------------|-------------|
| A (IPv4) | IPv4 addresses |
| AAAA (IPv6) | IPv6 addresses |
| NS | Nameservers |
| MX | Mail exchange servers |
| TXT | TXT records (SPF, DKIM, etc.) |
| SOA | Start of Authority |
| RDAP/IPWhois | ASN, hosting provider, country, network CIDR |

Features rate limiting, graceful error handling, and skip-if-already-processed logic.

### Stage 4 — Intelligence Correlation (`correlate.py`)

Identifies relationships between domains by clustering on shared:
- Hosting providers
- ASN numbers
- Nameservers
- IP addresses
- Countries
- Network CIDR ranges

---

## Project Structure

```
gambling_osint/
├── main2.py                  # Original infrastructure lookup script (preserved)
├── pipeline.py               # Main pipeline orchestrator (entry point)
├── config.py                 # Central configuration (all settings)
├── utils.py                  # Shared utilities (domain normalization, I/O)
├── discover.py               # Stage 1: Domain discovery engine
├── classify.py               # Stage 2: Classification & scoring
├── enrich.py                 # Stage 3: Infrastructure enrichment
├── correlate.py              # Stage 4: Intelligence correlation
├── report_generator.py       # Excel report generator
├── requirements.txt          # Python dependencies
├── README.md                 # This file
├── sites betting updated list (1).xlsx  # Original investigation data
├── data/
│   └── manual_domains.txt    # Manual domain input file
├── output/                   # Pipeline outputs (auto-created)
│   ├── discovered_domains.csv
│   ├── classified_domains.csv
│   ├── enriched_domains.csv
│   ├── correlation_clusters.csv
│   └── gambling_osint_report_YYYYMMDD_HHMMSS.xlsx
└── logs/                     # Execution logs (auto-created)
    └── pipeline_YYYYMMDD_HHMMSS.log
```

---

## Installation

### Prerequisites
- Python 3.9 or higher

### Setup

```bash
# 1. Navigate to the project directory
cd gambling_osint

# 2. (Recommended) Create a virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux/Mac

# 3. Install dependencies
pip install -r requirements.txt
```

---

## Usage

### Run the Full Pipeline

```bash
python pipeline.py
```

### Run Individual Stages

```bash
# Stage 1 only — Discovery
python pipeline.py --stage 1

# Stages 1 and 2 — Discovery + Classification
python pipeline.py --stage 1 2

# Stage 3 only — Enrichment (requires discovery/classification CSV)
python pipeline.py --stage 3

# Stage 4 + Report — Correlation and reporting
python pipeline.py --stage 4
```

### Re-generate Report

```bash
# Generate report from existing CSV outputs (no re-processing)
python pipeline.py --report-only
```

### Include Keyword Domain Generation

```bash
# WARNING: Generates thousands of candidate domains
python pipeline.py --keywords
```

### Interactive Domain Lookup (like original main2.py)

```bash
python enrich.py --interactive
```

### Run Individual Modules

```bash
python discover.py       # Run discovery standalone
python classify.py       # Run classification standalone
python enrich.py         # Run enrichment standalone
python correlate.py      # Run correlation standalone
python report_generator.py  # Generate report standalone
```

---

## Configuration

All settings are centralized in `config.py`:

| Setting | Description |
|---------|-------------|
| `GAMBLING_KEYWORDS` | Keywords for domain discovery |
| `GAMBLING_CONTENT_KEYWORDS` | Keywords for content classification |
| `INDIA_FOCUS_KEYWORDS` | India-targeting indicators |
| `SCORING_WEIGHTS` | Weight for each scoring indicator |
| `CLASSIFICATION_THRESHOLDS` | Score thresholds for categories |
| `DNS_NAMESERVERS` | DNS resolvers (Google + Cloudflare) |
| `HTTP_TIMEOUT` | Timeout for website fetching |
| `ENRICHMENT_DELAY` | Rate limiting between lookups |
| `CLUSTER_MIN_SIZE` | Minimum domains to form a cluster |

### Adjusting Scoring

Edit `SCORING_WEIGHTS` in `config.py` to change how different indicators affect classification:

```python
SCORING_WEIGHTS = {
    "gambling_keyword_match": 2,     # per keyword found
    "title_contains_gambling": 10,   # gambling term in page title
    "inr_symbol_found": 10,          # ₹ symbol detected
    "indian_payment_method": 8,      # UPI/Paytm/PhonePe found
    # ... etc
}
```

---

## Extending the System

### Adding a New Discovery Source

1. Create a new class that inherits from `DiscoverySource`
2. Implement `name` property and `discover()` method
3. Register it with the engine

```python
from discover import DiscoverySource

class MyCustomSource(DiscoverySource):
    @property
    def name(self) -> str:
        return "My Custom Source"
    
    def discover(self) -> list:
        # Your discovery logic here
        domains = [...]
        return [
            self._make_record(domain=d, raw_input=d)
            for d in domains
        ]
```

Register in `pipeline.py` or use the `extra_sources` parameter:

```python
from discover import run_discovery
results = run_discovery(extra_sources=[MyCustomSource()])
```

### Adding New Scoring Indicators

1. Add weight in `config.py` → `SCORING_WEIGHTS`
2. Add detection logic in `classify.py` → `ScoringEngine.score()`
3. Optionally add new keywords to the keyword lists in `config.py`

---

## Output Files

| File | Description |
|------|-------------|
| `output/discovered_domains.csv` | All unique discovered domains with sources |
| `output/classified_domains.csv` | Classification scores and categories |
| `output/enriched_domains.csv` | Full infrastructure data per domain |
| `output/correlation_clusters.csv` | Infrastructure cluster memberships |
| `output/gambling_osint_report_*.xlsx` | Final Excel report (5 sheets) |
| `logs/pipeline_*.log` | Detailed execution log |

---

## Notes

- The original `main2.py` script is **preserved unchanged**
- The `enrich.py --interactive` flag replicates the original interactive experience
- SSL certificate warnings are suppressed for gambling sites (many use self-signed certs)
- Rate limiting is built-in to avoid IP blocking during bulk processing
- All processing stages are **idempotent** — re-running skips already-processed domains

---

## License

For educational and research purposes only.
