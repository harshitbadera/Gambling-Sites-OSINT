"""
=============================================================================
GAMBLING OSINT - CONFIGURATION MODULE
=============================================================================
Central configuration for the entire pipeline.
All tunable parameters, file paths, keywords, scoring weights, and
operational constants are defined here.

Modify this file to adjust pipeline behavior without touching core logic.
=============================================================================
"""

import os
import logging
from datetime import datetime

# ─────────────────────────────────────────────────────────────────────────────
# PROJECT PATHS
# ─────────────────────────────────────────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
LOGS_DIR = os.path.join(BASE_DIR, "logs")

# Ensure directories exist
for _dir in [DATA_DIR, OUTPUT_DIR, LOGS_DIR]:
    os.makedirs(_dir, exist_ok=True)

# Input files
EXISTING_EXCEL = os.path.join(BASE_DIR, "sites betting updated list (1).xlsx")
MANUAL_DOMAINS_FILE = os.path.join(DATA_DIR, "manual_domains.txt")

# Pipeline output files
DISCOVERY_CSV = os.path.join(OUTPUT_DIR, "discovered_domains.csv")
CLASSIFICATION_CSV = os.path.join(OUTPUT_DIR, "classified_domains.csv")
ENRICHMENT_CSV = os.path.join(OUTPUT_DIR, "enriched_domains.csv")
CORRELATION_CSV = os.path.join(OUTPUT_DIR, "correlation_clusters.csv")
FINAL_REPORT_XLSX = os.path.join(
    OUTPUT_DIR,
    f"gambling_osint_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
)

# ─────────────────────────────────────────────────────────────────────────────
# LOGGING CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

LOG_FILE = os.path.join(
    LOGS_DIR,
    f"pipeline_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
)
LOG_LEVEL = logging.INFO
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging():
    """Configure project-wide logging to both file and console."""
    root_logger = logging.getLogger()
    root_logger.setLevel(LOG_LEVEL)

    # Prevent duplicate handlers on repeated calls
    if root_logger.handlers:
        return root_logger

    # File handler
    file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    file_handler.setLevel(LOG_LEVEL)
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT))

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(LOG_LEVEL)
    console_handler.setFormatter(logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT))

    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    return root_logger


# ─────────────────────────────────────────────────────────────────────────────
# DNS RESOLVER SETTINGS
# ─────────────────────────────────────────────────────────────────────────────

DNS_NAMESERVERS = ["8.8.8.8", "1.1.1.1"]
DNS_TIMEOUT = 10          # seconds per query
DNS_LIFETIME = 15         # total seconds for resolution

# ─────────────────────────────────────────────────────────────────────────────
# DISCOVERY KEYWORDS
# ─────────────────────────────────────────────────────────────────────────────

GAMBLING_KEYWORDS = [
    "bet", "betting", "casino", "poker", "sportsbook",
    "rummy", "teenpatti", "teen patti", "jackpot", "lottery",
    "spin", "winner", "gaming", "playwin", "bookmaker",
    "exchange", "slot", "slots", "baccarat", "blackjack",
    "roulette", "wager", "punt", "gamble", "odds",
    "satta", "matka", "cricket betting", "ipl betting",
    "live casino", "online casino", "sports betting",
]

# ─────────────────────────────────────────────────────────────────────────────
# CLASSIFICATION / SCORING CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

# HTTP settings for website content fetching
HTTP_TIMEOUT = 15         # seconds
HTTP_MAX_RETRIES = 2
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

# --- Gambling indicator keywords (found in page content) ---
GAMBLING_CONTENT_KEYWORDS = [
    "bet", "betting", "casino", "poker", "slot", "slots",
    "rummy", "teen patti", "teenpatti", "jackpot", "lottery",
    "sportsbook", "bookmaker", "live dealer", "blackjack",
    "roulette", "baccarat", "spin", "wager", "odds",
    "deposit", "withdraw", "payout", "bonus", "free spins",
    "welcome bonus", "signup bonus", "promo code",
    "gamble", "gambling", "wagering",
]

# --- India-focus indicator keywords ---
INDIA_FOCUS_KEYWORDS = [
    "india", "indian", "bharat", "desi",
    "inr", "₹", "rupee", "rupees",
    "upi", "paytm", "phonepe", "phone pe", "google pay", "gpay",
    "imps", "neft", "rtgs", "net banking",
    "teen patti", "teenpatti", "rummy", "andar bahar",
    "ipl", "cricket", "kabaddi", "pro kabaddi",
    "premier league", "t20", "test match",
    "hindi", "हिन्दी", "हिंदी",
    ".in", "indian premier",
]

# --- Payment method indicators ---
PAYMENT_KEYWORDS = [
    "upi", "paytm", "phonepe", "phone pe", "google pay", "gpay",
    "imps", "neft", "rtgs", "net banking", "bank transfer",
    "bitcoin", "btc", "ethereum", "eth", "usdt", "crypto",
    "visa", "mastercard", "skrill", "neteller",
    "astropay", "ecopayz", "muchbetter",
]

# --- Scoring weights ---
# Each indicator match adds its weight to the score.
# Final score determines the classification category.
SCORING_WEIGHTS = {
    # Gambling content indicators
    "gambling_keyword_match": 2,        # per unique keyword found
    "gambling_keyword_max": 20,         # cap for gambling keywords
    "title_contains_gambling": 10,      # gambling keyword in <title>
    "meta_contains_gambling": 5,        # gambling keyword in meta description

    # India-focus indicators
    "india_keyword_match": 3,           # per unique India keyword found
    "india_keyword_max": 25,            # cap for India keywords
    "inr_symbol_found": 10,             # ₹ symbol present
    "indian_payment_method": 8,         # UPI / Paytm / PhonePe etc.
    "indian_sport_reference": 7,        # IPL, cricket, kabaddi etc.
    "hindi_content_detected": 10,       # Hindi text detected
    "dot_in_domain": 5,                 # domain ends with .in

    # Domain-level indicators
    "domain_contains_gambling": 5,      # domain name has gambling keyword
    "domain_contains_india": 5,         # domain name has india keyword
}

# --- Classification thresholds ---
# Based on combined gambling + India-focus scores
CLASSIFICATION_THRESHOLDS = {
    "gambling_high": 15,        # gambling score >= this → "Gambling-Related"
    "gambling_low": 5,          # gambling score >= this → "Possibly Gambling-Related"
    "india_high": 15,           # india score >= this → add "India-Focused" tag
    "india_low": 5,             # india score >= this → add "Possibly India-Focused" tag
}

# Classification categories
CATEGORY_GAMBLING = "Gambling-Related"
CATEGORY_POSSIBLY_GAMBLING = "Possibly Gambling-Related"
CATEGORY_NOT_GAMBLING = "Not Gambling-Related"
CATEGORY_INDIA_FOCUSED = "India-Focused"
CATEGORY_POSSIBLY_INDIA = "Possibly India-Focused"
CATEGORY_UNKNOWN = "Unknown"

# ─────────────────────────────────────────────────────────────────────────────
# ENRICHMENT SETTINGS
# ─────────────────────────────────────────────────────────────────────────────

ENRICHMENT_BATCH_SIZE = 50         # domains per batch for progress reporting
ENRICHMENT_DELAY = 0.5             # seconds between RDAP lookups (rate limiting)
MAX_ENRICHMENT_WORKERS = 5         # max parallel workers (conservative)

# ─────────────────────────────────────────────────────────────────────────────
# CORRELATION SETTINGS
# ─────────────────────────────────────────────────────────────────────────────

# Minimum number of domains sharing an attribute to flag as a cluster
CLUSTER_MIN_SIZE = 2

# Attributes to correlate on
CORRELATION_ATTRIBUTES = [
    "hosting_provider",
    "asn",
    "asn_description",
    "country",
    "nameservers",
]

# ─────────────────────────────────────────────────────────────────────────────
# REPORT SETTINGS
# ─────────────────────────────────────────────────────────────────────────────

REPORT_SHEET_NAMES = {
    "discovery": "Discovery",
    "classification": "Classification",
    "infrastructure": "Infrastructure",
    "correlation": "Correlation",
    "summary": "Summary Statistics",
}

# Top-N items to show in summary statistics
SUMMARY_TOP_N = 15
