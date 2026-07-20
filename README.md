# 🎰 Gambling OSINT — Cyber Threat Intelligence Automation Platform

An end-to-end OSINT automation platform for discovering, analyzing, and reporting on online gambling websites targeting Indian users. Features a **web-based dashboard** with 4 analysis steps.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Web Dashboard](#web-dashboard)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Output Files](#output-files)
- [Tech Stack](#tech-stack)

---

## Overview

This platform automates the intelligence collection and analysis workflow for identifying and profiling online gambling operations, particularly those targeting Indian users. It combines domain discovery, infrastructure analysis, content scanning, and threat reporting into a single web-based dashboard.

### Key Capabilities

- **Fast domain discovery** — generates domain variations from seed lists and validates via parallel DNS (50 threads, ~100–200 new domains in 60 seconds)
- **Infrastructure enrichment** — DNS lookups (A, AAAA), RDAP/IPWhois for ASN, hosting provider, country
- **Reverse IP pivoting** — automatically discovers new gambling domains sharing the same non-CDN hosting servers
- **Content analysis** — extracts HTTP titles, body keywords, body size, and scans for hardcoded credentials (API keys, tokens, passwords)
- **Liveness & screenshot reporting** — headless browser verification with automated Word document (.docx) report generation

---

## Web Dashboard

The primary interface is a **Flask-based web dashboard** (`app.py`) with 4 steps arranged in a 2×2 grid layout.

### Step 1 — Find New Gambling Domains

Upload a CSV/Excel/TXT file containing known gambling sites. The system:

1. Reads seed domains from the uploaded file (smart column detection — works with any header)
2. Generates thousands of domain variations using gambling brand patterns, prefixes, suffixes, and TLD combinations
3. Validates all candidates via **parallel DNS resolution** (50 concurrent threads using Google & Cloudflare DNS)
4. Deduplicates to **main domains only** (e.g., `betway.com`, `betway.in`, `betway.net` → keeps `betway.com`)
5. Filters out IP-like domains (e.g., `154.198.173.1.co`)

**Output**: CSV of new unique main domains with IP addresses

### Step 2 — Infrastructure Lookup + Reverse IP Pivot

Upload the domains CSV from Step 1 (or any domain list). The system:

1. Runs bulk infrastructure lookups for each domain:
   - IPv4 & IPv6 addresses
   - Hosting provider
   - ASN number & description
   - Country
2. **Automatically pivots** on non-CDN IPs to discover new gambling domains:
   - Skips major CDN/cloud ASNs (Cloudflare, AWS, Google, Azure, Akamai, Fastly, Meta)
   - Queries remaining dedicated IPs via HackerTarget reverse IP API
   - Filters results for gambling-related keywords
   - Returns newly discovered domains with hosting server info

**Output**: Two CSVs — infrastructure data + newly discovered domains from reverse IP

### Step 3 — Liveness & Screenshot Report

Upload a domain list. The system:

1. Visits each domain using a headless Chromium browser (Playwright)
2. Checks if the site is live/working
3. Captures a full-page screenshot of each active site
4. Compiles a professionally formatted **Word document (.docx)** with screenshots, domain info, and liveness status
5. Auto-installs Playwright browser binaries if missing

**Output**: Downloadable .docx report with screenshots

### Step 4 — Content Analysis

Upload a domain list. The system:

1. Fetches each website's homepage (HTTPS → HTTP fallback, with browser-like User-Agent)
2. Extracts the **HTTP Title** from the `<title>` tag using BeautifulSoup
3. Measures **Body Size** in bytes/KB (indicator of site legitimacy — parked domains are < 5KB)
4. Scans the HTML body for **3 keyword categories**:
   - **Gambling keywords** (22): bet, casino, poker, slot, rummy, satta, matka, etc.
   - **India-targeting keywords** (17): india, ₹, UPI, Paytm, PhonePe, IPL, cricket, etc.
   - **Payment method keywords** (17): UPI, Paytm, Bitcoin, Visa, Mastercard, etc.
5. Scans for **hardcoded credentials** using 8 regex patterns:
   - Google API Keys (`AIzaSy...`)
   - AWS Access Keys (`AKIA...`)
   - Stripe Keys (`sk_live_`, `pk_live_`)
   - Generic API keys, passwords, auth tokens
   - Database connection strings (MongoDB, MySQL, PostgreSQL, Redis)
   - Bearer tokens

**Output**: CSV with domain, liveness status, HTTP title, body size, keyword matches, and exposed credentials

---

## Project Structure

```
gambling_osint/
├── app.py                    # Flask web dashboard (main entry point)
├── templates/
│   └── index.html            # Dashboard frontend (dark-themed, 2×2 grid)
├── quick_expand.py           # Fast domain expansion engine (50-thread DNS)
├── screenshot_manager.py     # Playwright screenshot & .docx report generator
├── config.py                 # Central configuration (all settings)
├── utils.py                  # Shared utilities (domain validation, I/O)
├── main2.py                  # Original infrastructure lookup script (preserved)
├── requirements.txt          # Python dependencies
├── .gitignore                # Git ignore rules
├── sites betting updated list (1).xlsx  # Original investigation data
├── output/                   # All outputs (auto-created)
│   ├── temp/                 # Temporary download files from web interface
│   └── screenshots/          # Captured screenshots
└── logs/                     # Execution logs (auto-created)
```

---

## Installation

### Prerequisites
- Python 3.9 or higher

### Setup

```bash
# 1. Clone the repository
git clone https://github.com/harshitbadera/Gambling-Sites-OSINT.git
cd Gambling-Sites-OSINT

# 2. (Recommended) Create a virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux/Mac

# 3. Install dependencies
pip install -r requirements.txt

# 4. Install Playwright browser binaries (required for Step 3 screenshots)
playwright install chromium
```

> **Note**: Step 4 (Playwright install) is only required if you plan to use Step 3 (Liveness & Screenshot Report). The app will automatically attempt to install Chromium if missing when Step 3 is triggered.

---

## Usage

### Run the Web Dashboard

```bash
python app.py
```

Open **http://localhost:5000** in your browser. The dashboard provides 4 steps:

| Step | Function | Input | Output |
|------|----------|-------|--------|
| **Step 1** | Find New Gambling Domains | CSV/Excel with known domains | CSV of new main domains |
| **Step 2** | Infrastructure Lookup + Reverse IP Pivot | Domain list CSV | Infrastructure CSV + discovered domains CSV |
| **Step 3** | Liveness & Screenshot Report | Domain list CSV | Word document (.docx) with screenshots |
| **Step 4** | Content Analysis | Domain list CSV | CSV with titles, keywords, body size, credentials |

### Fast Domain Expansion (Standalone)

```bash
# Use default Excel as seed
python quick_expand.py

# Use custom input
python quick_expand.py --input found.csv
python quick_expand.py --input my_seeds.xlsx

# Adjust thread count
python quick_expand.py --workers 80
```

### Original Infrastructure Lookup (Standalone)

```bash
python main2.py
```

---

## Configuration

All settings are centralized in `config.py`:

| Setting | Description |
|---------|-------------|
| `GAMBLING_KEYWORDS` | Keywords for domain discovery |
| `GAMBLING_CONTENT_KEYWORDS` | Keywords for content classification |
| `INDIA_FOCUS_KEYWORDS` | India-targeting indicators |
| `DNS_NAMESERVERS` | DNS resolvers (Google + Cloudflare) |
| `HTTP_TIMEOUT` | Timeout for website fetching |
| `ENRICHMENT_DELAY` | Rate limiting between lookups |

---

## Output Files

| File | Step | Description |
|------|------|-------------|
| `expanded_*.csv` | Step 1 | New domains discovered via pattern expansion |
| `lookup_*.csv` | Step 2 | Infrastructure lookup results (IPs, ASN, hosting) |
| `pivot_*.csv` | Step 2 | Domains discovered via reverse IP pivoting |
| `liveness_report_*.docx` | Step 3 | Screenshot & liveness report |
| `content_*.csv` | Step 4 | Content analysis (titles, keywords, credentials) |

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python 3.9+, Flask |
| Frontend | HTML, CSS, JavaScript (vanilla) |
| DNS Resolution | dnspython |
| IP/ASN Lookup | ipwhois (RDAP) |
| Domain Parsing | tldextract |
| HTTP Fetching | requests |
| HTML Parsing | BeautifulSoup4 |
| Browser Automation | Playwright (Chromium) |
| Report Generation | python-docx, openpyxl |

---

## Notes

- The original `main2.py` script is **preserved unchanged**
- SSL certificate warnings are suppressed for gambling sites (many use self-signed certs)
- Rate limiting is built-in to avoid IP blocking during bulk processing
- The reverse IP pivot skips CDN providers (Cloudflare, AWS, Google, etc.) — only queries dedicated hosting IPs
- HackerTarget reverse IP API has a free limit of 100 queries/day
- Step 3 auto-installs Playwright Chromium browser binaries if missing
- All domain validation filters out IP-like domains (e.g., `154.198.173.1.co`)

---

## License

For educational and research purposes only.
