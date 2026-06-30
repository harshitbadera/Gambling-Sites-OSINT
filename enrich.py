"""
=============================================================================
GAMBLING OSINT - STAGE 3: INFRASTRUCTURE ENRICHMENT
=============================================================================
Integrates and extends the original main2.py infrastructure lookup script
to perform automated bulk enrichment of discovered/classified domains.

For each domain, extracts:
  - Registrable domain (via tldextract)
  - IPv4 addresses (A records)
  - IPv6 addresses (AAAA records)
  - Nameservers (NS records)
  - MX records
  - TXT records
  - ASN number & description (via RDAP/ipwhois)
  - Hosting provider & country
  - SOA record

Handles exceptions gracefully, logs failures, and avoids duplicate processing.
=============================================================================
"""

import os
import time
import logging
from datetime import datetime

import tldextract
import dns.resolver
from ipwhois import IPWhois

import config
from utils import (
    normalize_domain,
    write_csv,
    read_csv_domains,
    ProgressTracker,
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# INFRASTRUCTURE LOOKUP ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class InfrastructureLookup:
    """
    Performs comprehensive DNS and WHOIS-based infrastructure analysis
    for a given domain. This extends the original main2.py functionality
    into a reusable, scriptable class.
    """

    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = config.DNS_NAMESERVERS
        self.resolver.timeout = config.DNS_TIMEOUT
        self.resolver.lifetime = config.DNS_LIFETIME

    def lookup(self, domain: str) -> dict:
        """
        Perform full infrastructure lookup for a domain.
        
        Args:
            domain: registrable domain name (e.g., 'example.com')
        
        Returns:
            dict with all infrastructure data fields
        """
        result = {
            "domain": domain,
            "registrable_domain": "",
            "subdomain": "",
            "tld": "",
            "ipv4_addresses": "",
            "ipv6_addresses": "",
            "nameservers": "",
            "mx_records": "",
            "txt_records": "",
            "soa_record": "",
            "asn": "",
            "asn_description": "",
            "hosting_provider": "",
            "country": "",
            "network_cidr": "",
            "network_name": "",
            "rdap_status": "",
            "enrichment_status": "success",
            "enrichment_error": "",
            "enriched_at": datetime.now().isoformat(),
        }

        # --- Extract domain components ---
        try:
            ext = tldextract.extract(domain)
            result["registrable_domain"] = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
            result["subdomain"] = ext.subdomain or ""
            result["tld"] = ext.suffix or ""
        except Exception as e:
            logger.debug(f"tldextract error for {domain}: {e}")

        main_domain = result["registrable_domain"] or domain

        # --- IPv4 Addresses (A records) ---
        ipv4_list = self._resolve_records(main_domain, "A")
        result["ipv4_addresses"] = "; ".join(ipv4_list)

        # --- IPv6 Addresses (AAAA records) ---
        ipv6_list = self._resolve_records(main_domain, "AAAA")
        result["ipv6_addresses"] = "; ".join(ipv6_list)

        # --- Nameservers (NS records) ---
        ns_list = self._resolve_records(main_domain, "NS")
        result["nameservers"] = "; ".join(ns_list)

        # --- MX Records ---
        mx_list = self._resolve_records(main_domain, "MX")
        result["mx_records"] = "; ".join(mx_list)

        # --- TXT Records ---
        txt_list = self._resolve_records(main_domain, "TXT")
        result["txt_records"] = "; ".join(txt_list)[:2000]  # Cap TXT records

        # --- SOA Record ---
        soa_list = self._resolve_records(main_domain, "SOA")
        result["soa_record"] = "; ".join(soa_list)

        # --- RDAP / IP WHOIS Lookup (hosting provider, ASN, country) ---
        if ipv4_list:
            rdap_data = self._rdap_lookup(ipv4_list[0])
            result.update(rdap_data)

        return result

    def _resolve_records(self, domain: str, record_type: str) -> list:
        """
        Resolve DNS records of a given type.
        Returns list of string values.
        """
        results = []
        try:
            answers = self.resolver.resolve(
                domain,
                record_type,
                lifetime=config.DNS_LIFETIME,
            )
            for answer in answers:
                results.append(answer.to_text())
        except dns.resolver.NXDOMAIN:
            logger.debug(f"NXDOMAIN for {domain} ({record_type})")
        except dns.resolver.NoAnswer:
            logger.debug(f"No {record_type} records for {domain}")
        except dns.resolver.NoNameservers:
            logger.debug(f"No nameservers available for {domain} ({record_type})")
        except dns.resolver.LifetimeTimeout:
            logger.debug(f"Timeout resolving {record_type} for {domain}")
        except Exception as e:
            logger.debug(f"DNS resolution error for {domain} ({record_type}): {e}")

        return results

    def _rdap_lookup(self, ip: str) -> dict:
        """
        Perform RDAP lookup for an IP address using ipwhois.
        Returns hosting provider, ASN, country, and network info.
        """
        rdap_result = {
            "asn": "",
            "asn_description": "",
            "hosting_provider": "",
            "country": "",
            "network_cidr": "",
            "network_name": "",
            "rdap_status": "",
        }

        try:
            obj = IPWhois(ip)
            result = obj.lookup_rdap()

            rdap_result["asn"] = result.get("asn", "")
            rdap_result["asn_description"] = result.get("asn_description", "")
            rdap_result["rdap_status"] = "success"

            network = result.get("network", {})
            if network:
                rdap_result["hosting_provider"] = network.get("name", "")
                rdap_result["country"] = network.get("country", "")
                cidr = network.get("cidr", "")
                rdap_result["network_cidr"] = cidr if cidr else ""
                rdap_result["network_name"] = network.get("name", "")

        except Exception as e:
            rdap_result["rdap_status"] = f"error: {str(e)[:200]}"
            logger.debug(f"RDAP lookup failed for {ip}: {e}")

        return rdap_result


# ─────────────────────────────────────────────────────────────────────────────
# ENRICHMENT PIPELINE
# ─────────────────────────────────────────────────────────────────────────────

def enrich_domains(
    domains: list,
    output_path: str = None,
    skip_existing: bool = True,
) -> list:
    """
    Enrich a list of domain records with infrastructure data.
    
    Args:
        domains: list of dicts with 'domain' key (from classification stage)
        output_path: path to save enrichment CSV
        skip_existing: if True, skip domains already enriched
    
    Returns:
        list of dicts with enrichment results merged with input data
    """
    output_path = output_path or config.ENRICHMENT_CSV

    logger.info("=" * 60)
    logger.info("STAGE 3: INFRASTRUCTURE ENRICHMENT")
    logger.info("=" * 60)

    # Load existing enrichments to avoid re-processing
    existing = {}
    if skip_existing and os.path.exists(output_path):
        for row in read_csv_domains(output_path):
            existing[row.get("domain", "")] = row
        logger.info(f"Loaded {len(existing)} existing enrichments")

    lookup = InfrastructureLookup()
    results = list(existing.values())

    # Filter domains that need enrichment
    domains_to_enrich = [
        d for d in domains
        if d.get("domain", "") not in existing
    ]

    if not domains_to_enrich:
        logger.info("All domains already enriched — nothing to do")
        return results

    logger.info(f"Enriching {len(domains_to_enrich)} new domains")
    tracker = ProgressTracker(len(domains_to_enrich), "Enrichment")

    for domain_record in domains_to_enrich:
        domain = domain_record.get("domain", "")
        if not domain:
            tracker.update(success=False)
            continue

        try:
            # Perform infrastructure lookup
            infra_data = lookup.lookup(domain)

            # Merge classification data with infrastructure data
            merged = {**domain_record, **infra_data}
            results.append(merged)

            tracker.update(success=True)

            logger.debug(
                f"Enriched {domain}: "
                f"IPv4={infra_data.get('ipv4_addresses', 'N/A')}, "
                f"ASN={infra_data.get('asn', 'N/A')}, "
                f"Provider={infra_data.get('hosting_provider', 'N/A')}"
            )

        except Exception as e:
            logger.error(f"Enrichment failed for {domain}: {e}")
            error_record = {
                **domain_record,
                "enrichment_status": "error",
                "enrichment_error": str(e)[:300],
                "enriched_at": datetime.now().isoformat(),
            }
            results.append(error_record)
            tracker.update(success=False)

        # Rate limiting to avoid being blocked
        time.sleep(config.ENRICHMENT_DELAY)

    # Save results
    write_csv(output_path, results)

    summary = tracker.summary()
    logger.info(
        f"Enrichment complete: {summary['successes']} enriched, "
        f"{summary['failures']} failed, {summary['skipped']} skipped"
    )

    return results


# ─────────────────────────────────────────────────────────────────────────────
# SINGLE DOMAIN LOOKUP (interactive mode, preserving main2.py behavior)
# ─────────────────────────────────────────────────────────────────────────────

def interactive_lookup():
    """
    Interactive single-domain lookup — preserves the original main2.py
    user experience with enhanced output.
    """
    print("=" * 60)
    print("DOMAIN INFRASTRUCTURE LOOKUP (Enhanced)")
    print("=" * 60)

    domain = input("\nEnter Website/Domain: ").strip()
    if not domain:
        print("No domain entered. Exiting.")
        return

    domain = normalize_domain(domain)
    print(f"\nLooking up: {domain}")
    print("-" * 60)

    lookup = InfrastructureLookup()
    result = lookup.lookup(domain)

    print(f"\n{'='*60}")
    print("RESULTS")
    print(f"{'='*60}")

    print(f"\nRegistrable Domain : {result['registrable_domain']}")

    print(f"\nIPv4 Addresses:")
    if result["ipv4_addresses"]:
        for ip in result["ipv4_addresses"].split("; "):
            print(f"  - {ip}")
    else:
        print("  Not Found")

    print(f"\nIPv6 Addresses:")
    if result["ipv6_addresses"]:
        for ip in result["ipv6_addresses"].split("; "):
            print(f"  - {ip}")
    else:
        print("  Not Found")

    print(f"\nNameservers:")
    if result["nameservers"]:
        for ns in result["nameservers"].split("; "):
            print(f"  - {ns}")
    else:
        print("  Not Found")

    print(f"\nMX Records:")
    if result["mx_records"]:
        for mx in result["mx_records"].split("; "):
            print(f"  - {mx}")
    else:
        print("  Not Found")

    print(f"\nHosting Information:")
    print(f"  Provider   : {result.get('hosting_provider', 'N/A')}")
    print(f"  Country    : {result.get('country', 'N/A')}")
    print(f"  ASN        : {result.get('asn', 'N/A')}")
    print(f"  ASN Desc   : {result.get('asn_description', 'N/A')}")
    print(f"  Network    : {result.get('network_cidr', 'N/A')}")

    if result.get("txt_records"):
        print(f"\nTXT Records:")
        for txt in result["txt_records"].split("; ")[:5]:
            print(f"  - {txt[:120]}")

    print(f"\n{'='*60}")
    print("DONE")
    print(f"{'='*60}")

    return result


# ─────────────────────────────────────────────────────────────────────────────
# STANDALONE EXECUTION
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    config.setup_logging()

    if "--interactive" in sys.argv or "-i" in sys.argv:
        # Interactive mode (like original main2.py)
        interactive_lookup()
    else:
        # Batch enrichment mode
        logger.info("Running Enrichment module standalone")

        if os.path.exists(config.CLASSIFICATION_CSV):
            domains = read_csv_domains(config.CLASSIFICATION_CSV)
        elif os.path.exists(config.DISCOVERY_CSV):
            domains = read_csv_domains(config.DISCOVERY_CSV)
        else:
            logger.error("No input CSV found. Run discover.py or classify.py first.")
            exit(1)

        results = enrich_domains(domains)

        print(f"\n{'='*60}")
        print(f"ENRICHMENT COMPLETE: {len(results)} domains processed")
        print(f"{'='*60}")

        # Summary of hosting providers
        providers = {}
        for r in results:
            provider = r.get("hosting_provider", "Unknown") or "Unknown"
            providers[provider] = providers.get(provider, 0) + 1

        print("\nTop Hosting Providers:")
        for provider, count in sorted(providers.items(), key=lambda x: -x[1])[:10]:
            print(f"  {provider:40s} → {count}")
