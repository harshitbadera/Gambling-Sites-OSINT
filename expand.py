"""
=============================================================================
GAMBLING OSINT - DOMAIN EXPANSION ENGINE
=============================================================================
Given seed domains (from Excel), discovers NEW gambling/betting domains
through infrastructure pivoting and OSINT techniques:

  1. Certificate Transparency (crt.sh) - Specific domain pattern searches
  2. Reverse IP Lookup (HackerTarget)  - FREE, 100 req/day
  3. Domain Pattern Variations         - Offline generation + DNS validation

Flow:
  Excel seeds -> Enrich (get IPs) -> Pivot -> Filter -> Validate -> NEW domains

Usage:
  python expand.py
  python expand.py --excel "path/to/file.xlsx"
  python expand.py --no-reverse-ip      (skip reverse IP lookups)
  python expand.py --no-crt             (skip crt.sh search)
=============================================================================
"""

import os
import re
import time
import logging
import argparse
from datetime import datetime

import requests
import dns.resolver
import tldextract

import config
from config import setup_logging
from utils import (
    normalize_domain,
    is_valid_domain,
    read_excel_domains,
    write_csv,
    ProgressTracker,
)
from enrich import InfrastructureLookup

logger = logging.getLogger(__name__)

EXPANDED_CSV = os.path.join(config.OUTPUT_DIR, "expanded_new_domains.csv")

# ---------------------------------------------------------------------------
# GAMBLING KEYWORD FILTER
# ---------------------------------------------------------------------------

GAMBLING_DOMAIN_KEYWORDS = [
    "bet", "betting", "casino", "poker", "slot", "slots",
    "gambl", "gambling", "rummy", "satta", "matka",
    "teenpatti", "jackpot", "lottery", "bingo", "wager",
    "punt", "bookmaker", "sportsbook", "odds",
    "spin", "roulette", "baccarat", "blackjack",
    "playwin", "winner", "lotto", "keno",
]

FALSE_POSITIVE_DOMAINS = {
    "alphabet.com", "beta.com", "diabetes.org",
    "betterment.com", "between.com",
}


def is_gambling_domain(domain: str) -> bool:
    """Check if a domain name looks like a gambling/betting site."""
    if not domain:
        return False
    if domain in FALSE_POSITIVE_DOMAINS:
        return False
    ext = tldextract.extract(domain)
    name_part = (ext.subdomain + ext.domain).lower()
    for kw in GAMBLING_DOMAIN_KEYWORDS:
        if kw in name_part:
            return True
    return False


# ---------------------------------------------------------------------------
# METHOD 1: CERTIFICATE TRANSPARENCY (crt.sh)
# ---------------------------------------------------------------------------

class CertTransparencySearch:
    """
    Search crt.sh for new gambling domains. Uses short, specific queries
    to avoid timeouts. crt.sh is free but slow for broad wildcards,
    so we search for specific gambling domain patterns.
    """

    BASE_URL = "https://crt.sh/"
    # Per-query timeout — crt.sh can be very slow
    TIMEOUT = 30

    # Short, specific patterns that return fast results
    # Format: each is a crt.sh Identity/wildcard pattern
    QUERIES = [
        # Specific gambling domain patterns
        "betindia%", "indiabet%", "rajbet%", "betraj%",
        "casinoindia%", "indiacasino%",
        "cricketbet%", "betcricket%", "iplbet%",
        "rummyindia%", "indiarummy%",
        "teenpatti%", "teenpattiindia%",
        "sattaking%", "sattamatka%",
        "mostbet%", "melbet%", "1xbet%",
        "bet365%", "betwinner%", "betway%",
        "22bet%", "4rabet%", "parimatch%",
        "fun88%", "dafabet%", "10cric%",
        "rajabets%", "yolo247%", "betbazar%",
        "bettilt%", "megapari%", "stake%casino%",
        # Common gambling brand patterns
        "cloudbet%", "sportbet%", "pinnacle%",
        "bingo%bet%", "lucky%spin%", "slot%india%",
    ]

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": config.USER_AGENT})

    def search_all(self, extra_queries: list = None) -> set:
        """Run all CT queries and return unique gambling domains."""
        all_domains = set()
        queries = self.QUERIES + (extra_queries or [])

        logger.info(f"[crt.sh] Running {len(queries)} queries...")

        for i, query in enumerate(queries, 1):
            try:
                domains = self._search_single(query)
                new_count = len(domains - all_domains)
                all_domains.update(domains)

                if domains:
                    logger.info(
                        f"[crt.sh] ({i}/{len(queries)}) '{query}' -> "
                        f"{len(domains)} found ({new_count} new)"
                    )
                else:
                    logger.debug(f"[crt.sh] ({i}/{len(queries)}) '{query}' -> 0")

            except Exception as e:
                logger.debug(f"[crt.sh] ({i}/{len(queries)}) '{query}' failed: {e}")

            time.sleep(2)

        logger.info(f"[crt.sh] Total unique gambling domains: {len(all_domains)}")
        return all_domains

    def _search_single(self, query: str) -> set:
        """Execute a single crt.sh query."""
        # Use the Identity search which is faster for prefix matches
        url = f"{self.BASE_URL}?q={query}&output=json"
        domains = set()

        try:
            resp = self.session.get(url, timeout=self.TIMEOUT)

            if resp.status_code != 200:
                return domains

            entries = resp.json()

            for entry in entries[:3000]:
                name_value = entry.get("name_value", "")
                common_name = entry.get("common_name", "")

                for raw_name in (name_value + "\n" + common_name).split("\n"):
                    raw_name = raw_name.strip().lower()
                    if raw_name.startswith("*."):
                        raw_name = raw_name[2:]

                    domain = normalize_domain(raw_name)
                    if domain and is_valid_domain(domain) and is_gambling_domain(domain):
                        domains.add(domain)

        except requests.exceptions.Timeout:
            logger.debug(f"[crt.sh] Timeout for: {query}")
        except (requests.exceptions.JSONDecodeError, ValueError):
            logger.debug(f"[crt.sh] Invalid JSON for: {query}")
        except Exception as e:
            logger.debug(f"[crt.sh] Error for {query}: {e}")

        return domains


# ---------------------------------------------------------------------------
# METHOD 2: REVERSE IP LOOKUP (HackerTarget)
# ---------------------------------------------------------------------------

class ReverseIPSearch:
    """
    Find other domains hosted on the same IPs as seed domains.
    HackerTarget API — FREE, 100 requests/day without API key.
    """

    BASE_URL = "https://api.hackertarget.com/reverseiplookup/"

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": config.USER_AGENT})
        self.queries_made = 0
        self.max_queries = 80

    def lookup_all(self, ip_list: list) -> dict:
        """Reverse lookup for a list of IPs. Returns {ip: set(domains)}."""
        results = {}
        unique_ips = list(set(ip.strip() for ip in ip_list if ip.strip()))

        if len(unique_ips) > self.max_queries:
            logger.warning(
                f"[ReverseIP] {len(unique_ips)} IPs > limit ({self.max_queries}). "
                f"Using first {self.max_queries}."
            )
            unique_ips = unique_ips[:self.max_queries]

        logger.info(f"[ReverseIP] Looking up {len(unique_ips)} unique IPs...")
        tracker = ProgressTracker(len(unique_ips), "Reverse IP")

        for ip in unique_ips:
            try:
                domains = self._lookup_single(ip)
                results[ip] = domains
                self.queries_made += 1
                tracker.update(success=True)
            except Exception as e:
                logger.debug(f"[ReverseIP] Error for {ip}: {e}")
                results[ip] = set()
                tracker.update(success=False)

            time.sleep(1.5)

        return results

    def _lookup_single(self, ip: str) -> set:
        """Reverse IP lookup for a single IP."""
        domains = set()

        try:
            resp = self.session.get(f"{self.BASE_URL}?q={ip}", timeout=15)
            if resp.status_code != 200:
                return domains

            text = resp.text.strip()
            if "error" in text.lower() or "api count" in text.lower():
                logger.warning(f"[ReverseIP] API limit or error: {text[:100]}")
                return domains

            for line in text.split("\n"):
                line = line.strip()
                if line:
                    domain = normalize_domain(line)
                    if domain and is_valid_domain(domain):
                        domains.add(domain)

        except Exception as e:
            logger.debug(f"[ReverseIP] Error for {ip}: {e}")

        return domains


# ---------------------------------------------------------------------------
# METHOD 3: DOMAIN VARIATION GENERATOR
# ---------------------------------------------------------------------------

class DomainVariationGenerator:
    """Generate domain name variations from seed domains."""

    TLDS = [
        ".com", ".in", ".co.in", ".net", ".org", ".bet",
        ".casino", ".poker", ".win", ".live", ".online",
        ".io", ".co", ".pro", ".top", ".one", ".club",
    ]

    SUFFIXES = ["247", "india", "ind", "online", "live", "pro"]
    PREFIXES = ["play", "my", "go", "real", "live"]

    def generate(self, seed_domains: list) -> set:
        """Generate variations from seed domain names."""
        candidates = set()

        for seed in seed_domains:
            ext = tldextract.extract(seed)
            base_name = ext.domain.lower()

            core = re.sub(r'\d+$', '', base_name)
            core = re.sub(r'(india|ind|online|live|pro|247)$', '', core)

            if len(core) < 3:
                continue

            for tld in self.TLDS:
                candidate = f"{base_name}{tld}"
                if candidate != seed:
                    candidates.add(candidate)
                if core != base_name:
                    candidate = f"{core}{tld}"
                    if candidate != seed:
                        candidates.add(candidate)

            for tld in [".com", ".in", ".net", ".live", ".online", ".bet"]:
                for suffix in self.SUFFIXES:
                    candidates.add(f"{core}{suffix}{tld}")
                for prefix in self.PREFIXES:
                    candidates.add(f"{prefix}{core}{tld}")

        # Filter valid domains only
        candidates = {d for d in candidates if is_valid_domain(d)}
        logger.info(f"[Variations] Generated {len(candidates)} domain variations")
        return candidates


# ---------------------------------------------------------------------------
# DOMAIN VALIDATOR (DNS + HTTP)
# ---------------------------------------------------------------------------

class DomainValidator:
    """Validates domains via DNS resolution and HTTP liveness check."""

    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = config.DNS_NAMESERVERS
        self.resolver.timeout = 5
        self.resolver.lifetime = 8

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": config.USER_AGENT})
        self.session.verify = False
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def validate_batch(self, domains: list) -> list:
        """Validate domains. Returns only LIVE ones (DNS + HTTP)."""
        logger.info(f"[Validator] Validating {len(domains)} candidates...")

        live_domains = []
        tracker = ProgressTracker(len(domains), "Validation")

        for domain in domains:
            ip = self._dns_check(domain)
            if not ip:
                tracker.update(success=False)
                continue

            http_status, final_url = self._http_check(domain)
            if http_status:
                live_domains.append({
                    "domain": domain,
                    "ip_address": ip,
                    "http_status": http_status,
                    "final_url": final_url,
                    "is_live": "Yes",
                })
                tracker.update(success=True)
            else:
                tracker.update(success=False)

            time.sleep(0.15)

        logger.info(f"[Validator] {len(live_domains)} live out of {len(domains)}")
        return live_domains

    def _dns_check(self, domain: str) -> str:
        try:
            answers = self.resolver.resolve(domain, "A", lifetime=8)
            for answer in answers:
                return answer.to_text()
        except Exception:
            pass
        return ""

    def _http_check(self, domain: str) -> tuple:
        for scheme in ["https", "http"]:
            try:
                resp = self.session.head(
                    f"{scheme}://{domain}", timeout=8, allow_redirects=True,
                )
                return resp.status_code, resp.url
            except Exception:
                continue
        return None, None


# ---------------------------------------------------------------------------
# MAIN EXPANSION ENGINE
# ---------------------------------------------------------------------------

class DomainExpander:
    """
    Orchestrates the full expansion pipeline.
    Given seeds, finds NEW gambling domains via CT, reverse IP, and variations.
    """

    def __init__(self, seed_domains, use_crt=True, use_reverse_ip=True, use_variations=True):
        self.seeds = set(normalize_domain(d) for d in seed_domains if d)
        self.use_crt = use_crt
        self.use_reverse_ip = use_reverse_ip
        self.use_variations = use_variations
        self.seed_ips = []

    def expand(self) -> list:
        """Run the full expansion. Returns list of new live gambling domain dicts."""
        print()
        print("=" * 60)
        print("  DOMAIN EXPANSION ENGINE")
        print(f"  Seed domains: {len(self.seeds)}")
        print("=" * 60)

        all_candidates = set()

        # Step 0: Enrich seeds to get IPs
        if self.use_reverse_ip:
            self._enrich_seeds()

        # Step 1: Certificate Transparency
        if self.use_crt:
            print("\n[1/4] Searching Certificate Transparency logs (crt.sh)...")
            print("      (Using specific gambling domain patterns)")
            try:
                ct = CertTransparencySearch()

                # Build extra queries from seed domain names
                extra = []
                for seed in self.seeds:
                    ext = tldextract.extract(seed)
                    name = ext.domain.lower()
                    if len(name) >= 4:
                        extra.append(f"{name}%")

                ct_domains = ct.search_all(extra_queries=extra)
                all_candidates.update(ct_domains)
                print(f"      [OK] Found {len(ct_domains)} gambling domains from crt.sh")
            except Exception as e:
                logger.error(f"crt.sh failed: {e}")
                print(f"      crt.sh search failed: {e}")

        # Step 2: Reverse IP
        if self.use_reverse_ip and self.seed_ips:
            print(f"\n[2/4] Reverse IP lookups on {len(self.seed_ips)} IPs...")
            try:
                rip = ReverseIPSearch()
                rip_results = rip.lookup_all(self.seed_ips)

                rip_gambling = set()
                rip_all = set()
                for ip, domains in rip_results.items():
                    rip_all.update(domains)
                    for d in domains:
                        if is_gambling_domain(d):
                            rip_gambling.add(d)

                before = len(all_candidates)
                all_candidates.update(rip_gambling)
                new_from_rip = len(all_candidates) - before
                print(
                    f"      [OK] Found {len(rip_all)} co-hosted domains, "
                    f"{len(rip_gambling)} are gambling ({new_from_rip} new)"
                )
            except Exception as e:
                logger.error(f"Reverse IP failed: {e}")
                print(f"      Reverse IP failed: {e}")

        # Step 3: Domain variations
        if self.use_variations:
            print("\n[3/4] Generating domain name variations from seeds...")
            try:
                var_gen = DomainVariationGenerator()
                variations = var_gen.generate(list(self.seeds))
                before = len(all_candidates)
                all_candidates.update(variations)
                new_var = len(all_candidates) - before
                print(f"      [OK] Generated {len(variations)} variations ({new_var} new)")
            except Exception as e:
                logger.error(f"Variation generation failed: {e}")

        # Step 4: Remove seeds
        all_candidates -= self.seeds
        print(f"\n[4/4] Total unique candidates (excluding seeds): {len(all_candidates)}")

        if not all_candidates:
            print("\nNo new candidate domains found.")
            return []

        # Step 5: Validate
        print(f"\nValidating {len(all_candidates)} candidates (DNS + HTTP)...")
        print("(This may take a while...)\n")

        validator = DomainValidator()
        live_domains = validator.validate_batch(sorted(all_candidates))

        for record in live_domains:
            record["discovery_method"] = "expansion"
            record["discovered_at"] = datetime.now().isoformat()
            record["is_gambling_name"] = (
                "Yes" if is_gambling_domain(record["domain"]) else "No"
            )

        return live_domains

    def _enrich_seeds(self):
        """Get IP addresses from seed domains for reverse lookups."""
        print("[0/4] Enriching seed domains to get IP addresses...")

        lookup = InfrastructureLookup()
        all_ips = []

        for seed in sorted(self.seeds):
            try:
                result = lookup.lookup(seed)
                ipv4 = result.get("ipv4_addresses", "")
                if ipv4:
                    for ip in ipv4.split("; "):
                        ip = ip.strip()
                        if ip:
                            all_ips.append(ip)
            except Exception:
                pass
            time.sleep(0.3)

        self.seed_ips = list(set(all_ips))
        print(f"      [OK] Got {len(self.seed_ips)} unique IPs from {len(self.seeds)} seeds")


# ---------------------------------------------------------------------------
# CONVENIENCE FUNCTION
# ---------------------------------------------------------------------------

def expand_from_excel(excel_path=None, use_crt=True, use_reverse_ip=True,
                      use_variations=True, output_path=None) -> list:
    """Read seeds from Excel, find new domains, save results."""
    excel_path = excel_path or config.EXISTING_EXCEL
    output_path = output_path or EXPANDED_CSV

    logger.info(f"Reading seeds from: {excel_path}")
    excel_data = read_excel_domains(excel_path)

    if not excel_data:
        print(f"ERROR: No domains found in {excel_path}")
        return []

    seed_domains = [e["domain"] for e in excel_data if e.get("domain")]
    print(f"\nLoaded {len(seed_domains)} seed domains from Excel")
    for d in sorted(seed_domains)[:10]:
        print(f"  - {d}")
    if len(seed_domains) > 10:
        print(f"  ... and {len(seed_domains) - 10} more")

    expander = DomainExpander(
        seed_domains=seed_domains,
        use_crt=use_crt,
        use_reverse_ip=use_reverse_ip,
        use_variations=use_variations,
    )
    new_domains = expander.expand()

    if new_domains:
        write_csv(output_path, new_domains)
        print(f"\n{'=' * 60}")
        print(f"  EXPANSION COMPLETE")
        print(f"  NEW live gambling domains found: {len(new_domains)}")
        print(f"  Results saved to: {output_path}")
        print(f"{'=' * 60}")
        print(f"\nNew domains found:")
        for d in new_domains[:40]:
            print(f"  - {d['domain']:40s}  IP: {d['ip_address']}")
        if len(new_domains) > 40:
            print(f"  ... and {len(new_domains) - 40} more (see CSV)")
    else:
        print(f"\n{'=' * 60}")
        print("  No new live gambling domains found.")
        print(f"{'=' * 60}")

    return new_domains


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    setup_logging()

    parser = argparse.ArgumentParser(
        description="Gambling OSINT - Domain Expansion Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python expand.py                          Use default Excel file
  python expand.py --excel "my_sites.xlsx"  Custom Excel file
  python expand.py --no-reverse-ip          Skip reverse IP (faster)
  python expand.py --no-crt                 Skip crt.sh (faster)
  python expand.py --crt-only              Only use crt.sh search
        """,
    )
    parser.add_argument("--excel", "-e", default=None, help="Path to Excel file")
    parser.add_argument("--no-crt", action="store_true", help="Skip crt.sh")
    parser.add_argument("--no-reverse-ip", action="store_true", help="Skip reverse IP")
    parser.add_argument("--no-variations", action="store_true", help="Skip variations")
    parser.add_argument("--crt-only", action="store_true", help="Only crt.sh")
    parser.add_argument("--output", "-o", default=None, help="Output CSV path")

    args = parser.parse_args()

    use_crt = not args.no_crt
    use_rip = not args.no_reverse_ip
    use_var = not args.no_variations

    if args.crt_only:
        use_crt, use_rip, use_var = True, False, False

    expand_from_excel(
        excel_path=args.excel,
        use_crt=use_crt,
        use_reverse_ip=use_rip,
        use_variations=use_var,
        output_path=args.output,
    )


if __name__ == "__main__":
    main()
