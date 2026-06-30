"""
=============================================================================
GAMBLING OSINT - FAST DOMAIN EXPANSION
=============================================================================
Finds NEW gambling/betting domains quickly.

Strategy:
  1. Read seed domains from Excel (or CSV of previously found domains)
  2. Generate smart domain variations (gambling patterns + TLD combos)
  3. Parallel DNS validation (50 threads — 100x faster than sequential)
  4. Output only domains that EXIST (DNS resolves)

Speed: ~2-3 minutes for 35 seeds -> 100-200 new domains

Usage:
  python quick_expand.py                         # Use default Excel
  python quick_expand.py --input found.csv       # Use previously found CSV
  python quick_expand.py --input my_seeds.xlsx   # Use custom Excel
=============================================================================
"""

import os
import sys
import csv
import time
import argparse
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.resolver
import tldextract

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config
from utils import normalize_domain, is_valid_domain, read_excel_domains

logger = logging.getLogger(__name__)

# ── Output path ─────────────────────────────────────────────────────────────
OUTPUT_CSV = os.path.join(config.OUTPUT_DIR, "expanded_new_domains.csv")

# ── Gambling keywords for filtering ─────────────────────────────────────────
GAMBLING_KEYWORDS = [
    "bet", "betting", "casino", "poker", "slot", "slots",
    "gambl", "rummy", "satta", "matka", "teenpatti",
    "jackpot", "lottery", "bingo", "wager", "punt",
    "bookmaker", "sportsbook", "odds", "spin",
    "roulette", "baccarat", "blackjack", "playwin",
    "winner", "lotto", "keno",
]

# ── Known gambling brand bases (common patterns in the wild) ────────────────
# These are NOT seeds — they're common gambling brand name patterns
# that we combine with TLDs to find real sites
KNOWN_GAMBLING_PATTERNS = [
    # Major international brands (often have India variants)
    "1xbet", "22bet", "4rabet", "10cric", "betway", "bet365",
    "betwinner", "mostbet", "melbet", "parimatch", "dafabet",
    "fun88", "betfair", "pinnacle", "stake", "cloudbet",
    # India-focused patterns
    "rajbet", "rajabets", "indiabet", "betindia", "cricketbet",
    "iplbet", "indiacasino", "casinoindia", "teenpattiindia",
    "rummyindia", "indiarummy", "sattaking", "sattamatka",
    "yolo247", "fairplay", "betbhai", "betbazar", "betbazzar",
    # Common gambling domain patterns
    "megabet", "superbet", "royalbet", "kingbet", "acebet",
    "goldbet", "luckybet", "maxbet", "probet", "topbet",
    "winbet", "bigbet", "fastbet", "easybet", "livebet",
    "megacasino", "royalcasino", "livecasino", "onlinecasino",
    "supercasino", "kingcasino", "goldcasino", "luckcasino",
    "betcity", "betzone", "betstar", "betkings", "betmaster",
    "betsafe", "betsson", "betworld", "betclub", "betpro",
    "sportbet", "sportbetting", "betsport", "sportsbet",
    "casinoland", "casinoroom", "slottica", "slotwolf",
    "spinwin", "jackpotcity", "lotteryindia", "lottoland",
    "pokerstars", "pokerking", "pokerindia", "rummycircle",
    "rummyculture", "rummypassion", "rummyola", "rummybo",
    "linebet", "jeetwin", "jeetbuzz", "baazi", "adda52",
    "casinoguru", "casinodays", "purewin", "glassi",
    "betano", "betzest", "novibet", "leovegas", "genesis",
    "betclic", "marathonbet", "betvictor", "bwin", "unibet",
    "888casino", "888sport", "williamhill", "ladbrokes",
    "betfred", "paddypower", "coral", "bodog", "bovada",
    "megapari", "sapphirebet", "bluechip", "fairplay",
    "odds96", "bc-game", "bcgame", "rolletto", "n1bet",
    "betshah", "bettilt", "casinodays", "betindi",
    "winzo", "mpl", "bigcash", "playerzpot",
]

# TLDs commonly used by gambling sites
GAMBLING_TLDS = [
    ".com", ".in", ".co.in", ".net", ".org",
    ".bet", ".casino", ".poker",
    ".win", ".live", ".online", ".io",
    ".co", ".pro", ".top", ".one", ".club",
    ".site", ".fun", ".vip", ".xyz",
]


# ═══════════════════════════════════════════════════════════════════════════
# STEP 1: READ SEEDS
# ═══════════════════════════════════════════════════════════════════════════

def read_seeds(input_path: str) -> set:
    """Read seed domains from Excel or CSV."""
    seeds = set()

    if input_path.endswith(".xlsx") or input_path.endswith(".xls"):
        excel_data = read_excel_domains(input_path)
        for entry in excel_data:
            d = entry.get("domain", "")
            if d and is_valid_domain(d):
                seeds.add(d)
    elif input_path.endswith(".csv"):
        with open(input_path, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                raw = row.get("domain", "") or row.get("Domain", "") or ""
                d = normalize_domain(raw)
                if d and is_valid_domain(d):
                    seeds.add(d)
    else:
        # Plain text, one domain per line
        with open(input_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    d = normalize_domain(line)
                    if d and is_valid_domain(d):
                        seeds.add(d)

    return seeds


# ═══════════════════════════════════════════════════════════════════════════
# STEP 2: GENERATE CANDIDATE DOMAINS
# ═══════════════════════════════════════════════════════════════════════════

def generate_candidates(seeds: set) -> set:
    """Generate candidate gambling domains from seeds + known patterns."""
    candidates = set()

    # --- Method A: Variations from seed domains ---
    for seed in seeds:
        ext = tldextract.extract(seed)
        base = ext.domain.lower()

        # Strip trailing numbers and common suffixes to get core
        import re
        core = re.sub(r'[\d]+$', '', base)
        core = re.sub(r'(india|ind|online|live|pro|247|game|games|play)$', '', core)

        if len(core) < 3:
            core = base  # fallback to full base

        # TLD variations of the seed base
        for tld in GAMBLING_TLDS:
            candidates.add(f"{base}{tld}")
            if core != base:
                candidates.add(f"{core}{tld}")

        # Common suffix variations
        for suffix in ["247", "india", "online", "live", "pro", "games"]:
            for tld in [".com", ".in", ".net", ".live", ".online"]:
                candidates.add(f"{core}{suffix}{tld}")
                candidates.add(f"{base}{suffix}{tld}")

        # Common prefix variations
        for prefix in ["play", "my", "go", "real", "live"]:
            for tld in [".com", ".in", ".net"]:
                candidates.add(f"{prefix}{core}{tld}")

    # --- Method B: Known gambling brand patterns × TLDs ---
    for pattern in KNOWN_GAMBLING_PATTERNS:
        for tld in GAMBLING_TLDS:
            candidates.add(f"{pattern}{tld}")

        # Also try common number suffixes
        for num in ["1", "2", "3", "7", "9", "24", "77", "99", "365", "247"]:
            for tld in [".com", ".in", ".net", ".live", ".online"]:
                candidates.add(f"{pattern}{num}{tld}")

    # --- Clean up ---
    # Remove seeds
    candidates -= seeds
    # Filter valid domains only
    candidates = {d for d in candidates if is_valid_domain(d)}

    return candidates


# ═══════════════════════════════════════════════════════════════════════════
# STEP 3: PARALLEL DNS VALIDATION (the speed magic)
# ═══════════════════════════════════════════════════════════════════════════

def check_dns(domain: str) -> tuple:
    """Check if a domain resolves. Returns (domain, ip) or (domain, None)."""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
    resolver.timeout = 3
    resolver.lifetime = 4

    try:
        answers = resolver.resolve(domain, "A", lifetime=4)
        ip = answers[0].to_text()
        return (domain, ip)
    except Exception:
        return (domain, None)


def validate_parallel(candidates: set, max_workers: int = 50) -> list:
    """
    Validate domains using parallel DNS lookups.
    50 threads = ~50 domains checked per 3-4 seconds = ~750/minute
    """
    results = []
    total = len(candidates)
    checked = 0
    found = 0

    print(f"  Validating {total} candidates with {max_workers} parallel threads...")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_dns, d): d for d in sorted(candidates)}

        for future in as_completed(futures):
            domain, ip = future.result()
            checked += 1

            if ip:
                results.append({"domain": domain, "ip_address": ip})
                found += 1

            # Progress every 500 or at the end
            if checked % 500 == 0 or checked == total:
                print(f"  ... {checked}/{total} checked, {found} found")

    return results


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    config.setup_logging()

    parser = argparse.ArgumentParser(
        description="Fast Gambling Domain Expansion",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python quick_expand.py                           Default Excel
  python quick_expand.py --input found.csv         Feed back previous results
  python quick_expand.py --input my_seeds.xlsx     Custom Excel file
  python quick_expand.py --workers 80              More parallel threads
        """,
    )
    parser.add_argument(
        "--input", "-i", default=None,
        help="Input file (Excel/CSV/TXT). Default: existing spreadsheet",
    )
    parser.add_argument(
        "--output", "-o", default=None,
        help="Output CSV path",
    )
    parser.add_argument(
        "--workers", "-w", type=int, default=50,
        help="Number of parallel DNS threads (default: 50)",
    )
    args = parser.parse_args()

    input_path = args.input or config.EXISTING_EXCEL
    output_path = args.output or OUTPUT_CSV

    start_time = time.time()

    # ── Step 1: Read seeds ──
    print()
    print("=" * 60)
    print("  FAST GAMBLING DOMAIN EXPANSION")
    print("=" * 60)
    print(f"\n[1/3] Reading seeds from: {os.path.basename(input_path)}")

    seeds = read_seeds(input_path)
    print(f"  Loaded {len(seeds)} seed domains")

    if not seeds:
        print("  ERROR: No valid domains found in input file!")
        return

    # ── Step 2: Generate candidates ──
    print(f"\n[2/3] Generating candidate domains...")

    candidates = generate_candidates(seeds)
    print(f"  Generated {len(candidates)} unique candidates")

    # ── Step 3: Validate ──
    print(f"\n[3/3] DNS validation (parallel)...")

    live_domains = validate_parallel(candidates, max_workers=args.workers)

    elapsed = time.time() - start_time

    # ── Save results ──
    if live_domains:
        # Sort alphabetically
        live_domains.sort(key=lambda x: x["domain"])

        # Add metadata
        for record in live_domains:
            record["is_gambling_name"] = (
                "Yes" if any(kw in record["domain"] for kw in GAMBLING_KEYWORDS) else "Maybe"
            )

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f, fieldnames=["domain", "ip_address", "is_gambling_name"]
            )
            writer.writeheader()
            writer.writerows(live_domains)

        print(f"\n{'=' * 60}")
        print(f"  DONE in {elapsed:.1f} seconds")
        print(f"  Seeds: {len(seeds)} | Candidates: {len(candidates)} | NEW FOUND: {len(live_domains)}")
        print(f"  Saved to: {output_path}")
        print(f"{'=' * 60}")
        print(f"\nAll {len(live_domains)} new domains:")
        print("-" * 50)
        for d in live_domains:
            print(f"  {d['domain']:40s}  {d['ip_address']}")
        print("-" * 50)

        print(f"\nTo expand AGAIN with these results as new seeds:")
        print(f"  python quick_expand.py --input \"{output_path}\"")
    else:
        print(f"\n  No new domains found. Elapsed: {elapsed:.1f}s")


if __name__ == "__main__":
    main()
