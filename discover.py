"""
=============================================================================
GAMBLING OSINT - STAGE 1: DOMAIN DISCOVERY ENGINE
=============================================================================
Modular discovery engine for collecting candidate gambling-related domains.

Supported sources (plugin architecture):
  - ExcelImportSource:     Import from the existing investigation spreadsheet
  - ManualListSource:      Import from a plain-text file (one domain per line)
  - CSVImportSource:       Import from CSV files
  - KeywordDomainSource:   Generate candidate domains from keyword patterns
  - CertTransparencySource: (Stub) Certificate Transparency log search
  - SearchEngineSource:     (Stub) Search engine scraping

Every source implements the DiscoverySource interface. New sources can be
added by subclassing DiscoverySource without modifying any existing code.
=============================================================================
"""

import os
import csv
import logging
from abc import ABC, abstractmethod
from datetime import datetime

import config
from utils import (
    normalize_domain,
    is_valid_domain,
    deduplicate_domains,
    read_excel_domains,
    write_csv,
    read_csv_domains,
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# DISCOVERY SOURCE INTERFACE
# ─────────────────────────────────────────────────────────────────────────────

class DiscoverySource(ABC):
    """
    Abstract base class for all domain discovery sources.
    
    Each source must implement:
      - name: a human-readable name for the source
      - discover(): returns a list of dicts with at least 'domain' and 'source' keys
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable source name."""
        pass

    @abstractmethod
    def discover(self) -> list:
        """
        Execute discovery and return candidate domains.
        
        Returns:
            list of dicts, each containing at minimum:
              - 'domain': the normalized registrable domain
              - 'source': the source identifier string
              - 'raw_input': the original input before normalization
              - 'discovered_at': ISO timestamp of discovery
        """
        pass

    def _make_record(self, domain: str, raw_input: str = "", extra: dict = None) -> dict:
        """Helper to create a standardized discovery record."""
        record = {
            "domain": domain,
            "source": self.name,
            "raw_input": raw_input or domain,
            "discovered_at": datetime.now().isoformat(),
        }
        if extra:
            record.update(extra)
        return record


# ─────────────────────────────────────────────────────────────────────────────
# SOURCE: EXCEL IMPORT (existing investigation spreadsheet)
# ─────────────────────────────────────────────────────────────────────────────

class ExcelImportSource(DiscoverySource):
    """
    Import domains from the existing Excel investigation spreadsheet.
    """

    def __init__(self, filepath: str = None):
        self.filepath = filepath or config.EXISTING_EXCEL

    @property
    def name(self) -> str:
        return "Excel Import"

    def discover(self) -> list:
        logger.info(f"[{self.name}] Reading from: {self.filepath}")

        if not os.path.exists(self.filepath):
            logger.warning(f"[{self.name}] File not found: {self.filepath}")
            return []

        excel_data = read_excel_domains(self.filepath)
        results = []

        for entry in excel_data:
            domain = entry.get("domain", "")
            if domain and is_valid_domain(domain):
                record = self._make_record(
                    domain=domain,
                    raw_input=entry.get("url", domain),
                    extra={
                        "site_name": entry.get("site_name", ""),
                    }
                )
                results.append(record)

        logger.info(f"[{self.name}] Discovered {len(results)} domains")
        return results


# ─────────────────────────────────────────────────────────────────────────────
# SOURCE: MANUAL DOMAIN LIST (plain text file, one domain per line)
# ─────────────────────────────────────────────────────────────────────────────

class ManualListSource(DiscoverySource):
    """
    Import domains from a plain-text file (one domain/URL per line).
    Lines starting with # are treated as comments.
    """

    def __init__(self, filepath: str = None):
        self.filepath = filepath or config.MANUAL_DOMAINS_FILE

    @property
    def name(self) -> str:
        return "Manual List"

    def discover(self) -> list:
        logger.info(f"[{self.name}] Reading from: {self.filepath}")

        if not os.path.exists(self.filepath):
            logger.info(f"[{self.name}] No manual list found at {self.filepath} — skipping")
            return []

        results = []

        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()

                    # Skip empty lines and comments
                    if not line or line.startswith("#"):
                        continue

                    domain = normalize_domain(line)
                    if domain and is_valid_domain(domain):
                        results.append(self._make_record(
                            domain=domain,
                            raw_input=line,
                        ))
                    else:
                        logger.debug(
                            f"[{self.name}] Skipping invalid entry on line {line_num}: '{line}'"
                        )
        except Exception as e:
            logger.error(f"[{self.name}] Error reading file: {e}")

        logger.info(f"[{self.name}] Discovered {len(results)} domains")
        return results


# ─────────────────────────────────────────────────────────────────────────────
# SOURCE: CSV IMPORT
# ─────────────────────────────────────────────────────────────────────────────

class CSVImportSource(DiscoverySource):
    """
    Import domains from a CSV file. Automatically detects the domain column
    by looking for columns named 'domain', 'url', 'website', 'site', etc.
    """

    def __init__(self, filepath: str = None, domain_column: str = None):
        self.filepath = filepath
        self.domain_column = domain_column

    @property
    def name(self) -> str:
        return "CSV Import"

    def _detect_domain_column(self, headers: list) -> str:
        """Auto-detect which column contains domains/URLs."""
        priority = ["domain", "url", "website", "site", "host", "address"]
        headers_lower = [h.lower().strip() for h in headers]

        for keyword in priority:
            for idx, header in enumerate(headers_lower):
                if keyword in header:
                    return headers[idx]

        # Fallback: use first column
        return headers[0] if headers else None

    def discover(self) -> list:
        if not self.filepath or not os.path.exists(self.filepath):
            logger.info(f"[{self.name}] No CSV file specified or file not found — skipping")
            return []

        logger.info(f"[{self.name}] Reading from: {self.filepath}")
        results = []

        try:
            with open(self.filepath, "r", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                col = self.domain_column or self._detect_domain_column(reader.fieldnames or [])

                if not col:
                    logger.warning(f"[{self.name}] Could not detect domain column")
                    return []

                for row in reader:
                    raw = row.get(col, "").strip()
                    if not raw:
                        continue
                    domain = normalize_domain(raw)
                    if domain and is_valid_domain(domain):
                        results.append(self._make_record(
                            domain=domain,
                            raw_input=raw,
                        ))

        except Exception as e:
            logger.error(f"[{self.name}] Error reading CSV: {e}")

        logger.info(f"[{self.name}] Discovered {len(results)} domains")
        return results


# ─────────────────────────────────────────────────────────────────────────────
# SOURCE: KEYWORD-BASED DOMAIN GENERATION
# ─────────────────────────────────────────────────────────────────────────────

class KeywordDomainSource(DiscoverySource):
    """
    Generate candidate domains by combining gambling keywords with
    common TLDs. Useful for proactive discovery of new gambling sites.
    
    Example: keyword='betking' → betking.com, betking.in, betking.net, ...
    """

    # Common TLDs used by gambling sites
    TLDS = [
        ".com", ".in", ".net", ".org", ".co.in", ".bet",
        ".casino", ".poker", ".win", ".live", ".online",
        ".io", ".co", ".pro", ".top", ".one", ".club",
    ]

    # Common gambling domain patterns
    PATTERNS = [
        "{keyword}",
        "{keyword}india",
        "{keyword}247",
        "{keyword}online",
        "{keyword}live",
        "play{keyword}",
        "my{keyword}",
        "go{keyword}",
        "{keyword}pro",
        "india{keyword}",
    ]

    def __init__(self, keywords: list = None, tlds: list = None):
        self.keywords = keywords or config.GAMBLING_KEYWORDS
        self.tlds = tlds or self.TLDS

    @property
    def name(self) -> str:
        return "Keyword Generation"

    def discover(self) -> list:
        logger.info(f"[{self.name}] Generating candidates from {len(self.keywords)} keywords")

        candidates = set()

        for keyword in self.keywords:
            # Clean keyword (remove spaces for domain construction)
            kw_clean = keyword.lower().replace(" ", "")

            for pattern in self.PATTERNS:
                domain_base = pattern.format(keyword=kw_clean)
                for tld in self.tlds:
                    candidate = domain_base + tld
                    candidates.add(candidate)

        results = []
        for candidate in sorted(candidates):
            if is_valid_domain(candidate):
                results.append(self._make_record(
                    domain=candidate,
                    raw_input=candidate,
                    extra={"generation_method": "keyword_pattern"}
                ))

        logger.info(f"[{self.name}] Generated {len(results)} candidate domains")
        return results


# ─────────────────────────────────────────────────────────────────────────────
# STUB: CERTIFICATE TRANSPARENCY SOURCE
# ─────────────────────────────────────────────────────────────────────────────

class CertTransparencySource(DiscoverySource):
    """
    Stub for Certificate Transparency log search.
    Can be implemented to query crt.sh or similar CT log aggregators
    for certificates containing gambling-related keywords.
    
    TODO: Implement CT log querying via crt.sh API
    """

    def __init__(self, keywords: list = None):
        self.keywords = keywords or config.GAMBLING_KEYWORDS[:10]  # Use top keywords

    @property
    def name(self) -> str:
        return "Certificate Transparency"

    def discover(self) -> list:
        logger.info(
            f"[{self.name}] Certificate Transparency source is a stub — "
            f"implement CT log querying to enable this source"
        )
        # Future implementation:
        # For each keyword, query crt.sh:
        #   https://crt.sh/?q=%25{keyword}%25&output=json
        # Parse results and extract domain names
        return []


# ─────────────────────────────────────────────────────────────────────────────
# STUB: SEARCH ENGINE SOURCE
# ─────────────────────────────────────────────────────────────────────────────

class SearchEngineSource(DiscoverySource):
    """
    Stub for search engine-based domain discovery.
    Can be implemented to search for gambling-related queries and
    extract domains from search results.
    
    TODO: Implement via Google Custom Search API or similar
    """

    def __init__(self, queries: list = None):
        self.queries = queries or [
            "online betting India",
            "Indian casino online",
            "cricket betting site",
            "IPL betting website",
        ]

    @property
    def name(self) -> str:
        return "Search Engine"

    def discover(self) -> list:
        logger.info(
            f"[{self.name}] Search engine source is a stub — "
            f"implement search API integration to enable this source"
        )
        return []


# ─────────────────────────────────────────────────────────────────────────────
# DISCOVERY ENGINE (orchestrator)
# ─────────────────────────────────────────────────────────────────────────────

class DiscoveryEngine:
    """
    Orchestrates domain discovery from multiple sources.
    
    Handles:
      - Source registration (plugin architecture)
      - Execution of all sources
      - Normalization and deduplication
      - Persistence to CSV
    """

    def __init__(self):
        self.sources: list[DiscoverySource] = []
        self.discovered_domains: list[dict] = []

    def register_source(self, source: DiscoverySource):
        """Register a discovery source."""
        self.sources.append(source)
        logger.info(f"Registered discovery source: {source.name}")

    def run(self, include_keyword_generation: bool = False) -> list:
        """
        Execute all registered sources and aggregate results.
        
        Args:
            include_keyword_generation: If True, also runs the keyword
                domain generation source (can produce thousands of candidates).
        
        Returns:
            List of unique domain records.
        """
        logger.info("=" * 60)
        logger.info("STAGE 1: DOMAIN DISCOVERY")
        logger.info("=" * 60)

        all_records = []

        for source in self.sources:
            try:
                logger.info(f"Running source: {source.name}")
                records = source.discover()
                all_records.extend(records)
                logger.info(
                    f"Source '{source.name}' returned {len(records)} records"
                )
            except Exception as e:
                logger.error(f"Source '{source.name}' failed: {e}", exc_info=True)

        # Deduplicate by normalized domain, keeping the first occurrence
        seen = set()
        unique_records = []
        for record in all_records:
            domain = record.get("domain", "")
            if domain and domain not in seen:
                seen.add(domain)
                unique_records.append(record)

        self.discovered_domains = unique_records

        logger.info(
            f"Discovery complete: {len(all_records)} total → "
            f"{len(unique_records)} unique domains"
        )

        return unique_records

    def save(self, filepath: str = None):
        """Save discovered domains to CSV."""
        filepath = filepath or config.DISCOVERY_CSV
        if self.discovered_domains:
            write_csv(filepath, self.discovered_domains)
            logger.info(f"Saved {len(self.discovered_domains)} domains to {filepath}")
        else:
            logger.warning("No domains to save")

    def load_existing(self, filepath: str = None) -> list:
        """Load previously discovered domains from CSV."""
        filepath = filepath or config.DISCOVERY_CSV
        if os.path.exists(filepath):
            self.discovered_domains = read_csv_domains(filepath)
            logger.info(
                f"Loaded {len(self.discovered_domains)} existing domains from {filepath}"
            )
        return self.discovered_domains


# ─────────────────────────────────────────────────────────────────────────────
# CONVENIENCE FUNCTION
# ─────────────────────────────────────────────────────────────────────────────

def run_discovery(
    include_keyword_generation: bool = False,
    extra_sources: list = None,
    csv_files: list = None,
) -> list:
    """
    Run the full discovery pipeline with default sources.
    
    Args:
        include_keyword_generation: Include keyword-based domain generation.
        extra_sources: Additional DiscoverySource instances to register.
        csv_files: List of CSV file paths to import.
    
    Returns:
        List of unique discovered domain records.
    """
    engine = DiscoveryEngine()

    # Register default sources
    engine.register_source(ExcelImportSource())
    engine.register_source(ManualListSource())

    # Register CSV sources
    if csv_files:
        for csv_path in csv_files:
            engine.register_source(CSVImportSource(filepath=csv_path))

    # Register keyword generation (optional — produces many candidates)
    if include_keyword_generation:
        engine.register_source(KeywordDomainSource())

    # Register stub sources (they'll log and return empty)
    engine.register_source(CertTransparencySource())
    engine.register_source(SearchEngineSource())

    # Register any extra sources
    if extra_sources:
        for source in extra_sources:
            engine.register_source(source)

    # Execute discovery
    results = engine.run(include_keyword_generation=include_keyword_generation)

    # Save results
    engine.save()

    return results


# ─────────────────────────────────────────────────────────────────────────────
# STANDALONE EXECUTION
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    config.setup_logging()
    logger.info("Running Discovery module standalone")

    domains = run_discovery(include_keyword_generation=False)
    print(f"\n{'='*60}")
    print(f"DISCOVERY COMPLETE: {len(domains)} unique domains found")
    print(f"{'='*60}")
    for d in domains[:20]:
        print(f"  • {d['domain']:40s} [{d['source']}]")
    if len(domains) > 20:
        print(f"  ... and {len(domains) - 20} more")
