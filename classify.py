"""
=============================================================================
GAMBLING OSINT - STAGE 2: CLASSIFICATION & SCORING ENGINE
=============================================================================
Visits publicly available website content and performs passive analysis to
classify each domain:
  - Extracts page title, meta tags, visible text, payment refs, language cues
  - Scores gambling relevance using configurable weighted indicators
  - Scores India-targeting using payment, language, sport, and currency cues
  - Produces a confidence score and classification category

Categories:
  - Gambling-Related / Possibly Gambling-Related / Not Gambling-Related
  - India-Focused / Possibly India-Focused
  - Unknown (if site is unreachable)
=============================================================================
"""

import re
import logging
import time
from datetime import datetime

import requests

import config
from utils import write_csv, read_csv_domains, ProgressTracker

logger = logging.getLogger(__name__)

# Try to import BeautifulSoup; provide clear error if missing
try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
    logger.warning(
        "BeautifulSoup4 not installed. Classification will use basic text extraction. "
        "Install with: pip install beautifulsoup4"
    )


# ─────────────────────────────────────────────────────────────────────────────
# WEB CONTENT FETCHER
# ─────────────────────────────────────────────────────────────────────────────

class WebContentFetcher:
    """
    Fetches and parses web page content for analysis.
    Uses requests + BeautifulSoup for robust HTML parsing.
    Falls back to regex-based extraction if BS4 is unavailable.
    """

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": config.USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,hi;q=0.8",
            "Accept-Encoding": "gzip, deflate",
        })
        # Disable SSL verification warnings for sketchy gambling sites
        self.session.verify = False
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def fetch(self, domain: str) -> dict:
        """
        Fetch and extract structured content from a domain.
        
        Returns dict with:
          - status: 'success' | 'error' | 'timeout'
          - status_code: HTTP status code (if success)
          - url: final URL after redirects
          - title: page title
          - meta_description: meta description content
          - meta_keywords: meta keywords content
          - visible_text: all visible text content (lowercased)
          - raw_html: raw HTML (truncated)
          - error: error message (if failed)
        """
        result = {
            "status": "error",
            "status_code": None,
            "url": "",
            "title": "",
            "meta_description": "",
            "meta_keywords": "",
            "visible_text": "",
            "raw_html": "",
            "error": "",
        }

        # Try HTTPS first, then HTTP
        urls_to_try = [f"https://{domain}", f"http://{domain}"]

        for url in urls_to_try:
            try:
                response = self.session.get(
                    url,
                    timeout=config.HTTP_TIMEOUT,
                    allow_redirects=True,
                )

                result["status"] = "success"
                result["status_code"] = response.status_code
                result["url"] = response.url

                # Parse content
                html = response.text[:500_000]  # Cap at 500KB
                result["raw_html"] = html[:10_000]  # Store only first 10KB

                if BS4_AVAILABLE:
                    result.update(self._parse_with_bs4(html))
                else:
                    result.update(self._parse_with_regex(html))

                return result

            except requests.exceptions.Timeout:
                result["status"] = "timeout"
                result["error"] = f"Timeout after {config.HTTP_TIMEOUT}s"
            except requests.exceptions.ConnectionError as e:
                result["error"] = f"Connection error: {str(e)[:200]}"
            except requests.exceptions.TooManyRedirects:
                result["error"] = "Too many redirects"
            except Exception as e:
                result["error"] = f"Unexpected error: {str(e)[:200]}"

        return result

    def _parse_with_bs4(self, html: str) -> dict:
        """Parse HTML using BeautifulSoup."""
        soup = BeautifulSoup(html, "html.parser")

        # Title
        title = ""
        if soup.title and soup.title.string:
            title = soup.title.string.strip()

        # Meta description
        meta_desc = ""
        meta_tag = soup.find("meta", attrs={"name": re.compile(r"description", re.I)})
        if meta_tag:
            meta_desc = meta_tag.get("content", "").strip()

        # Meta keywords
        meta_kw = ""
        meta_kw_tag = soup.find("meta", attrs={"name": re.compile(r"keywords", re.I)})
        if meta_kw_tag:
            meta_kw = meta_kw_tag.get("content", "").strip()

        # Remove script, style, nav, footer elements
        for tag in soup(["script", "style", "noscript", "iframe", "svg"]):
            tag.decompose()

        # Get visible text
        visible_text = soup.get_text(separator=" ", strip=True)
        # Normalize whitespace
        visible_text = re.sub(r'\s+', ' ', visible_text).lower()

        return {
            "title": title,
            "meta_description": meta_desc,
            "meta_keywords": meta_kw,
            "visible_text": visible_text[:50_000],  # Cap at 50K chars
        }

    def _parse_with_regex(self, html: str) -> dict:
        """Fallback: Parse HTML using regex (when BS4 is unavailable)."""
        # Title
        title_match = re.search(r'<title[^>]*>(.*?)</title>', html, re.I | re.S)
        title = title_match.group(1).strip() if title_match else ""

        # Meta description
        meta_match = re.search(
            r'<meta[^>]*name=["\']description["\'][^>]*content=["\']([^"\']*)["\']',
            html, re.I
        )
        meta_desc = meta_match.group(1).strip() if meta_match else ""

        # Meta keywords
        kw_match = re.search(
            r'<meta[^>]*name=["\']keywords["\'][^>]*content=["\']([^"\']*)["\']',
            html, re.I
        )
        meta_kw = kw_match.group(1).strip() if kw_match else ""

        # Strip all HTML tags for visible text
        text = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.S | re.I)
        text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.S | re.I)
        text = re.sub(r'<[^>]+>', ' ', text)
        text = re.sub(r'\s+', ' ', text).strip().lower()

        return {
            "title": title,
            "meta_description": meta_desc,
            "meta_keywords": meta_kw,
            "visible_text": text[:50_000],
        }


# ─────────────────────────────────────────────────────────────────────────────
# SCORING ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class ScoringEngine:
    """
    Configurable scoring engine that analyzes web content and produces
    gambling relevance scores and India-targeting scores.
    """

    def __init__(self):
        self.weights = config.SCORING_WEIGHTS
        self.thresholds = config.CLASSIFICATION_THRESHOLDS

    def score(self, domain: str, content: dict) -> dict:
        """
        Score a domain based on its fetched content.
        
        Args:
            domain: the domain name
            content: dict from WebContentFetcher.fetch()
        
        Returns:
            dict with scoring breakdown and classification
        """
        result = {
            "gambling_score": 0,
            "india_score": 0,
            "gambling_keywords_found": [],
            "india_keywords_found": [],
            "payment_methods_found": [],
            "classification": config.CATEGORY_UNKNOWN,
            "india_classification": "",
            "combined_classification": config.CATEGORY_UNKNOWN,
            "confidence": 0,
        }

        # If site was unreachable, classify as Unknown
        if content.get("status") != "success":
            return result

        visible_text = content.get("visible_text", "").lower()
        title = content.get("title", "").lower()
        meta_desc = content.get("meta_description", "").lower()
        meta_kw = content.get("meta_keywords", "").lower()
        domain_lower = domain.lower()

        # Combined text for analysis
        all_text = f"{visible_text} {title} {meta_desc} {meta_kw}"

        # --- Gambling Score ---
        gambling_score = 0

        # Check gambling keywords in content
        gambling_found = []
        for keyword in config.GAMBLING_CONTENT_KEYWORDS:
            if keyword.lower() in all_text:
                gambling_found.append(keyword)

        kw_score = len(gambling_found) * self.weights["gambling_keyword_match"]
        kw_score = min(kw_score, self.weights["gambling_keyword_max"])
        gambling_score += kw_score

        # Title contains gambling keyword
        for keyword in config.GAMBLING_CONTENT_KEYWORDS:
            if keyword.lower() in title:
                gambling_score += self.weights["title_contains_gambling"]
                break

        # Meta contains gambling keyword
        for keyword in config.GAMBLING_CONTENT_KEYWORDS:
            if keyword.lower() in meta_desc:
                gambling_score += self.weights["meta_contains_gambling"]
                break

        # Domain name contains gambling keyword
        for keyword in config.GAMBLING_CONTENT_KEYWORDS:
            kw_clean = keyword.replace(" ", "")
            if kw_clean in domain_lower.split(".")[0]:
                gambling_score += self.weights["domain_contains_gambling"]
                break

        result["gambling_score"] = gambling_score
        result["gambling_keywords_found"] = gambling_found

        # --- India Score ---
        india_score = 0

        # Check India keywords
        india_found = []
        for keyword in config.INDIA_FOCUS_KEYWORDS:
            if keyword.lower() in all_text:
                india_found.append(keyword)

        india_kw_score = len(india_found) * self.weights["india_keyword_match"]
        india_kw_score = min(india_kw_score, self.weights["india_keyword_max"])
        india_score += india_kw_score

        # INR symbol
        if "₹" in all_text or "inr" in all_text:
            india_score += self.weights["inr_symbol_found"]

        # Payment methods
        payment_found = []
        indian_payment_keywords = ["upi", "paytm", "phonepe", "phone pe", "google pay", "gpay"]
        for pm in indian_payment_keywords:
            if pm in all_text:
                payment_found.append(pm)
                india_score += self.weights["indian_payment_method"]

        result["payment_methods_found"] = payment_found

        # Indian sports
        indian_sports = ["ipl", "cricket", "kabaddi", "pro kabaddi", "indian premier"]
        for sport in indian_sports:
            if sport in all_text:
                india_score += self.weights["indian_sport_reference"]
                break

        # Hindi content detection (check for Devanagari script)
        if re.search(r'[\u0900-\u097F]', all_text):
            india_score += self.weights["hindi_content_detected"]

        # .in domain
        if domain_lower.endswith(".in") or ".in/" in domain_lower:
            india_score += self.weights["dot_in_domain"]

        # Domain contains india keyword
        india_domain_keywords = ["india", "ind", "bharat", "desi"]
        for kw in india_domain_keywords:
            if kw in domain_lower.split(".")[0]:
                india_score += self.weights["domain_contains_india"]
                break

        result["india_score"] = india_score
        result["india_keywords_found"] = india_found

        # --- Classification ---
        # Gambling classification
        if gambling_score >= self.thresholds["gambling_high"]:
            result["classification"] = config.CATEGORY_GAMBLING
        elif gambling_score >= self.thresholds["gambling_low"]:
            result["classification"] = config.CATEGORY_POSSIBLY_GAMBLING
        else:
            result["classification"] = config.CATEGORY_NOT_GAMBLING

        # India classification
        if india_score >= self.thresholds["india_high"]:
            result["india_classification"] = config.CATEGORY_INDIA_FOCUSED
        elif india_score >= self.thresholds["india_low"]:
            result["india_classification"] = config.CATEGORY_POSSIBLY_INDIA
        else:
            result["india_classification"] = ""

        # Combined classification
        parts = [result["classification"]]
        if result["india_classification"]:
            parts.append(result["india_classification"])
        result["combined_classification"] = " | ".join(parts)

        # Confidence (0-100 scale)
        max_possible = (
            self.weights["gambling_keyword_max"]
            + self.weights["title_contains_gambling"]
            + self.weights["meta_contains_gambling"]
            + self.weights["domain_contains_gambling"]
            + self.weights["india_keyword_max"]
            + self.weights["inr_symbol_found"]
            + self.weights["indian_payment_method"] * 3
            + self.weights["indian_sport_reference"]
            + self.weights["hindi_content_detected"]
            + self.weights["dot_in_domain"]
            + self.weights["domain_contains_india"]
        )
        raw_score = gambling_score + india_score
        result["confidence"] = min(100, int((raw_score / max_possible) * 100))

        return result


# ─────────────────────────────────────────────────────────────────────────────
# CLASSIFICATION PIPELINE
# ─────────────────────────────────────────────────────────────────────────────

def classify_domains(
    domains: list,
    output_path: str = None,
    skip_existing: bool = True,
) -> list:
    """
    Classify a list of domain records.
    
    Args:
        domains: list of dicts with 'domain' key (from discovery stage)
        output_path: path to save classification CSV
        skip_existing: if True, skip domains already classified
    
    Returns:
        list of dicts with classification results
    """
    output_path = output_path or config.CLASSIFICATION_CSV

    logger.info("=" * 60)
    logger.info("STAGE 2: CLASSIFICATION & SCORING")
    logger.info("=" * 60)

    # Load existing classifications to avoid re-processing
    existing = {}
    if skip_existing and os.path.exists(output_path):
        for row in read_csv_domains(output_path):
            existing[row.get("domain", "")] = row
        logger.info(f"Loaded {len(existing)} existing classifications")

    fetcher = WebContentFetcher()
    scorer = ScoringEngine()
    results = list(existing.values())  # Start with existing results

    # Filter domains that need classification
    domains_to_classify = [
        d for d in domains
        if d.get("domain", "") not in existing
    ]

    if not domains_to_classify:
        logger.info("All domains already classified — nothing to do")
        return results

    logger.info(f"Classifying {len(domains_to_classify)} new domains")
    tracker = ProgressTracker(len(domains_to_classify), "Classification")

    for domain_record in domains_to_classify:
        domain = domain_record.get("domain", "")
        if not domain:
            tracker.update(success=False)
            continue

        try:
            # Fetch web content
            content = fetcher.fetch(domain)

            # Score and classify
            scores = scorer.score(domain, content)

            # Build result record
            record = {
                "domain": domain,
                "source": domain_record.get("source", ""),
                "site_name": domain_record.get("site_name", ""),
                "fetch_status": content.get("status", "error"),
                "http_status_code": content.get("status_code", ""),
                "final_url": content.get("url", ""),
                "page_title": content.get("title", ""),
                "meta_description": content.get("meta_description", "")[:500],
                "gambling_score": scores["gambling_score"],
                "india_score": scores["india_score"],
                "confidence": scores["confidence"],
                "classification": scores["classification"],
                "india_classification": scores["india_classification"],
                "combined_classification": scores["combined_classification"],
                "gambling_keywords_found": "; ".join(scores["gambling_keywords_found"]),
                "india_keywords_found": "; ".join(scores["india_keywords_found"]),
                "payment_methods_found": "; ".join(scores["payment_methods_found"]),
                "fetch_error": content.get("error", ""),
                "classified_at": datetime.now().isoformat(),
            }

            results.append(record)
            tracker.update(success=True)

        except Exception as e:
            logger.error(f"Classification failed for {domain}: {e}")
            results.append({
                "domain": domain,
                "source": domain_record.get("source", ""),
                "fetch_status": "error",
                "classification": config.CATEGORY_UNKNOWN,
                "fetch_error": str(e)[:300],
                "classified_at": datetime.now().isoformat(),
            })
            tracker.update(success=False)

        # Small delay to be polite
        time.sleep(0.3)

    # Save results
    write_csv(output_path, results)

    summary = tracker.summary()
    logger.info(
        f"Classification complete: {summary['successes']} classified, "
        f"{summary['failures']} failed, {summary['skipped']} skipped"
    )

    return results


# ─────────────────────────────────────────────────────────────────────────────
# STANDALONE EXECUTION
# ─────────────────────────────────────────────────────────────────────────────

import os

if __name__ == "__main__":
    config.setup_logging()
    logger.info("Running Classification module standalone")

    # Load domains from discovery output
    if os.path.exists(config.DISCOVERY_CSV):
        domains = read_csv_domains(config.DISCOVERY_CSV)
    else:
        logger.error(
            f"Discovery CSV not found at {config.DISCOVERY_CSV}. "
            f"Run discover.py first."
        )
        exit(1)

    results = classify_domains(domains)

    print(f"\n{'='*60}")
    print(f"CLASSIFICATION COMPLETE: {len(results)} domains processed")
    print(f"{'='*60}")

    # Summary
    categories = {}
    for r in results:
        cat = r.get("combined_classification", "Unknown")
        categories[cat] = categories.get(cat, 0) + 1

    for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
        print(f"  {cat:45s} → {count}")
