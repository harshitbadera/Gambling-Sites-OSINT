"""
=============================================================================
GAMBLING OSINT - STAGE 4: INTELLIGENCE CORRELATION
=============================================================================
Analyzes enriched infrastructure data to identify relationships and
patterns between domains.

Correlation dimensions:
  - Hosting provider clusters
  - ASN clusters
  - Nameserver clusters
  - Country clusters
  - Shared IP clusters
  - Network CIDR clusters

Produces cluster assignments and statistical summaries for reporting.
=============================================================================
"""

import os
import logging
from collections import defaultdict, Counter
from datetime import datetime

import config
from utils import write_csv, read_csv_domains

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# CORRELATION ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class CorrelationEngine:
    """
    Analyzes enriched domain data to find infrastructure relationships.
    Groups domains by shared hosting, ASN, nameservers, IP, and country.
    """

    def __init__(self, enriched_data: list):
        """
        Args:
            enriched_data: list of dicts from the enrichment stage
        """
        self.data = enriched_data
        self.clusters = {}       # attribute → {value → [domains]}
        self.domain_clusters = {}  # domain → list of cluster memberships
        self.statistics = {}     # summary stats

    def correlate(self) -> dict:
        """
        Run all correlation analyses.
        
        Returns:
            dict with cluster data and statistics
        """
        logger.info("=" * 60)
        logger.info("STAGE 4: INTELLIGENCE CORRELATION")
        logger.info("=" * 60)

        # Build clusters for each attribute
        self._cluster_by_attribute("hosting_provider", "Hosting Provider")
        self._cluster_by_attribute("asn", "ASN")
        self._cluster_by_attribute("asn_description", "ASN Description")
        self._cluster_by_attribute("country", "Country")
        self._cluster_by_shared_values("nameservers", "Nameserver", separator="; ")
        self._cluster_by_shared_values("ipv4_addresses", "IPv4 Address", separator="; ")
        self._cluster_by_shared_values("mx_records", "MX Server", separator="; ")
        self._cluster_by_network_cidr()

        # Build per-domain cluster membership
        self._build_domain_clusters()

        # Compute summary statistics
        self._compute_statistics()

        logger.info(f"Correlation complete. Found clusters in {len(self.clusters)} dimensions.")

        return {
            "clusters": self.clusters,
            "domain_clusters": self.domain_clusters,
            "statistics": self.statistics,
        }

    def _cluster_by_attribute(self, field: str, label: str):
        """
        Group domains by a single-valued attribute.
        """
        groups = defaultdict(list)

        for record in self.data:
            value = (record.get(field) or "").strip()
            if value and value.lower() not in ("", "n/a", "none", "unknown"):
                domain = record.get("domain", "")
                if domain:
                    groups[value].append(domain)

        # Filter to clusters meeting minimum size
        significant = {
            k: v for k, v in groups.items()
            if len(v) >= config.CLUSTER_MIN_SIZE
        }

        self.clusters[label] = significant
        logger.info(
            f"  [{label}] Found {len(significant)} clusters "
            f"(≥{config.CLUSTER_MIN_SIZE} domains each)"
        )

    def _cluster_by_shared_values(self, field: str, label: str, separator: str = "; "):
        """
        Group domains by multi-valued attributes (e.g., nameservers).
        Each individual value creates its own cluster.
        """
        groups = defaultdict(list)

        for record in self.data:
            raw_value = record.get(field) or ""
            if not raw_value:
                continue

            values = [v.strip().rstrip(".").lower() for v in raw_value.split(separator) if v.strip()]
            domain = record.get("domain", "")

            for val in values:
                if val and val not in ("", "n/a", "none"):
                    groups[val].append(domain)

        significant = {
            k: v for k, v in groups.items()
            if len(v) >= config.CLUSTER_MIN_SIZE
        }

        self.clusters[label] = significant
        logger.info(
            f"  [{label}] Found {len(significant)} clusters "
            f"(≥{config.CLUSTER_MIN_SIZE} domains each)"
        )

    def _cluster_by_network_cidr(self):
        """
        Group domains by network CIDR range.
        Domains on the same /24 or allocated block share infrastructure.
        """
        groups = defaultdict(list)

        for record in self.data:
            cidr = (record.get("network_cidr") or "").strip()
            domain = record.get("domain") or ""

            if cidr and domain and cidr.lower() not in ("", "n/a", "none"):
                groups[cidr].append(domain)

        significant = {
            k: v for k, v in groups.items()
            if len(v) >= config.CLUSTER_MIN_SIZE
        }

        self.clusters["Network CIDR"] = significant
        logger.info(
            f"  [Network CIDR] Found {len(significant)} clusters "
            f"(≥{config.CLUSTER_MIN_SIZE} domains each)"
        )

    def _build_domain_clusters(self):
        """
        For each domain, list all clusters it belongs to.
        Useful for identifying domains with significant shared infrastructure.
        """
        domain_memberships = defaultdict(list)

        for dimension, groups in self.clusters.items():
            for group_value, domains in groups.items():
                for domain in domains:
                    domain_memberships[domain].append({
                        "dimension": dimension,
                        "value": group_value,
                        "cluster_size": len(domains),
                    })

        self.domain_clusters = dict(domain_memberships)

    def _compute_statistics(self):
        """Compute summary statistics across all dimensions."""
        stats = {}

        for dimension, groups in self.clusters.items():
            if not groups:
                continue

            # Top N by cluster size
            top_items = sorted(
                groups.items(),
                key=lambda x: len(x[1]),
                reverse=True,
            )[:config.SUMMARY_TOP_N]

            stats[dimension] = {
                "total_clusters": len(groups),
                "total_domains_in_clusters": len(
                    set(d for domains in groups.values() for d in domains)
                ),
                "largest_cluster_size": len(top_items[0][1]) if top_items else 0,
                "largest_cluster_value": top_items[0][0] if top_items else "",
                "top_items": [
                    {"value": k, "count": len(v), "domains": v}
                    for k, v in top_items
                ],
            }

        # Classification distribution
        class_dist = Counter()
        india_dist = Counter()
        for record in self.data:
            class_dist[record.get("classification", "Unknown")] += 1
            india_class = record.get("india_classification", "")
            if india_class:
                india_dist[india_class] += 1

        stats["classification_distribution"] = dict(class_dist)
        stats["india_classification_distribution"] = dict(india_dist)

        # Overall stats
        stats["total_domains_analyzed"] = len(self.data)
        stats["total_unique_ips"] = len(set(
            ip.strip()
            for r in self.data
            for ip in (r.get("ipv4_addresses") or "").split("; ")
            if ip.strip()
        ))
        stats["total_unique_asns"] = len(set(
            r.get("asn", "") for r in self.data if r.get("asn")
        ))
        stats["total_unique_countries"] = len(set(
            r.get("country", "") for r in self.data if r.get("country")
        ))

        self.statistics = stats
        logger.info(
            f"  Statistics: {stats['total_domains_analyzed']} domains, "
            f"{stats['total_unique_ips']} unique IPs, "
            f"{stats['total_unique_asns']} unique ASNs, "
            f"{stats['total_unique_countries']} unique countries"
        )


# ─────────────────────────────────────────────────────────────────────────────
# CORRELATION PIPELINE
# ─────────────────────────────────────────────────────────────────────────────

def correlate_domains(
    enriched_data: list = None,
    output_path: str = None,
) -> dict:
    """
    Run the correlation analysis pipeline.
    
    Args:
        enriched_data: list of enriched domain dicts (from enrich stage).
                       If None, loads from ENRICHMENT_CSV.
        output_path: path to save correlation CSV output
    
    Returns:
        dict with clusters and statistics
    """
    output_path = output_path or config.CORRELATION_CSV

    # Load enriched data if not provided
    if enriched_data is None:
        if os.path.exists(config.ENRICHMENT_CSV):
            enriched_data = read_csv_domains(config.ENRICHMENT_CSV)
            logger.info(f"Loaded {len(enriched_data)} enriched domains from CSV")
        else:
            logger.error(f"Enrichment CSV not found: {config.ENRICHMENT_CSV}")
            return {}

    if not enriched_data:
        logger.warning("No enriched data to correlate")
        return {}

    # Run correlation
    engine = CorrelationEngine(enriched_data)
    correlation_result = engine.correlate()

    # Save cluster memberships to CSV
    cluster_rows = []
    for domain, memberships in engine.domain_clusters.items():
        for membership in memberships:
            cluster_rows.append({
                "domain": domain,
                "cluster_dimension": membership["dimension"],
                "cluster_value": membership["value"],
                "cluster_size": membership["cluster_size"],
                "correlated_at": datetime.now().isoformat(),
            })

    if cluster_rows:
        write_csv(output_path, cluster_rows)

    return correlation_result


# ─────────────────────────────────────────────────────────────────────────────
# STANDALONE EXECUTION
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    config.setup_logging()
    logger.info("Running Correlation module standalone")

    result = correlate_domains()

    if result:
        stats = result.get("statistics", {})

        print(f"\n{'='*60}")
        print("CORRELATION ANALYSIS COMPLETE")
        print(f"{'='*60}")
        print(f"\nDomains analyzed: {stats.get('total_domains_analyzed', 0)}")
        print(f"Unique IPs:       {stats.get('total_unique_ips', 0)}")
        print(f"Unique ASNs:      {stats.get('total_unique_asns', 0)}")
        print(f"Unique Countries: {stats.get('total_unique_countries', 0)}")

        for dimension in ["Hosting Provider", "ASN", "Country", "Nameserver"]:
            dim_stats = stats.get(dimension, {})
            if dim_stats:
                print(f"\n--- {dimension} Clusters ---")
                for item in dim_stats.get("top_items", [])[:5]:
                    print(f"  {item['value']:40s} → {item['count']} domains")
