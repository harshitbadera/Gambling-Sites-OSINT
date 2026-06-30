"""
=============================================================================
GAMBLING OSINT - MAIN PIPELINE ORCHESTRATOR
=============================================================================
End-to-end pipeline that executes all four stages in sequence:
  1. Discovery    → Collect candidate domains from multiple sources
  2. Classification → Fetch websites and score gambling/India relevance
  3. Enrichment   → DNS and infrastructure analysis for each domain
  4. Correlation  → Find relationships between domains
  5. Reporting    → Generate comprehensive Excel report

Usage:
  python pipeline.py                  # Run full pipeline
  python pipeline.py --stage 1       # Run only discovery
  python pipeline.py --stage 2       # Run only classification
  python pipeline.py --stage 3       # Run only enrichment
  python pipeline.py --stage 4       # Run only correlation + reporting
  python pipeline.py --report-only   # Re-generate report from existing data
=============================================================================
"""

import sys
import time
import logging
import argparse
from datetime import datetime

import config
from config import setup_logging

from discover import run_discovery
from classify import classify_domains
from enrich import enrich_domains
from correlate import correlate_domains
from report_generator import generate_report
from utils import read_csv_domains

logger = logging.getLogger(__name__)


def run_pipeline(
    stages: list = None,
    include_keyword_generation: bool = False,
    report_only: bool = False,
):
    """
    Execute the full OSINT automation pipeline.
    
    Args:
        stages: list of stage numbers to run (default: all stages [1,2,3,4])
        include_keyword_generation: include keyword domain generation in discovery
        report_only: only generate the report from existing data
    """
    start_time = time.time()

    print()
    print("+" + "=" * 58 + "+")
    print("|" + "GAMBLING OSINT AUTOMATION PIPELINE".center(58) + "|")
    print("|" + "Cyber Threat Intelligence Platform".center(58) + "|")
    print("+" + "=" * 58 + "+")
    print("|" + f" Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}".ljust(58) + "|")
    print("+" + "=" * 58 + "+")
    print()

    if stages is None:
        stages = [1, 2, 3, 4]

    if report_only:
        stages = []

    discovery_data = None
    classification_data = None
    enrichment_data = None
    correlation_result = None

    # -- Stage 1: Discovery -----------------------------------------------
    if 1 in stages:
        logger.info("-" * 60)
        logger.info("> STAGE 1: DOMAIN DISCOVERY")
        logger.info("-" * 60)

        discovery_data = run_discovery(
            include_keyword_generation=include_keyword_generation,
        )
        print(f"  [OK] Discovery: {len(discovery_data)} unique domains found")
    else:
        # Load existing discovery data
        import os
        if os.path.exists(config.DISCOVERY_CSV):
            discovery_data = read_csv_domains(config.DISCOVERY_CSV)
            logger.info(f"Loaded {len(discovery_data)} domains from existing discovery CSV")

    # -- Stage 2: Classification ------------------------------------------
    if 2 in stages and discovery_data:
        logger.info("-" * 60)
        logger.info("> STAGE 2: CLASSIFICATION & SCORING")
        logger.info("-" * 60)

        classification_data = classify_domains(discovery_data)
        print(f"  [OK] Classification: {len(classification_data)} domains classified")
    else:
        import os
        if os.path.exists(config.CLASSIFICATION_CSV):
            classification_data = read_csv_domains(config.CLASSIFICATION_CSV)

    # -- Stage 3: Enrichment ----------------------------------------------
    if 3 in stages and (classification_data or discovery_data):
        logger.info("-" * 60)
        logger.info("> STAGE 3: INFRASTRUCTURE ENRICHMENT")
        logger.info("-" * 60)

        # Use classification data if available, otherwise discovery data
        input_data = classification_data or discovery_data
        enrichment_data = enrich_domains(input_data)
        print(f"  [OK] Enrichment: {len(enrichment_data)} domains enriched")
    else:
        import os
        if os.path.exists(config.ENRICHMENT_CSV):
            enrichment_data = read_csv_domains(config.ENRICHMENT_CSV)

    # -- Stage 4: Correlation ---------------------------------------------
    if 4 in stages and enrichment_data:
        logger.info("-" * 60)
        logger.info("> STAGE 4: INTELLIGENCE CORRELATION")
        logger.info("-" * 60)

        correlation_result = correlate_domains(enrichment_data)
        print(f"  [OK] Correlation: analysis complete")

    # -- Report Generation ------------------------------------------------
    logger.info("-" * 60)
    logger.info("> GENERATING REPORT")
    logger.info("-" * 60)

    report_path = generate_report(
        discovery_data=discovery_data,
        classification_data=classification_data,
        enrichment_data=enrichment_data,
        correlation_result=correlation_result,
    )

    # -- Summary ----------------------------------------------------------
    elapsed = time.time() - start_time

    print()
    print("+" + "=" * 58 + "+")
    print("|" + "PIPELINE COMPLETE".center(58) + "|")
    print("+" + "=" * 58 + "+")
    if discovery_data:
        print("|" + f"  Domains Discovered:  {len(discovery_data)}".ljust(58) + "|")
    if classification_data:
        print("|" + f"  Domains Classified:  {len(classification_data)}".ljust(58) + "|")
    if enrichment_data:
        print("|" + f"  Domains Enriched:    {len(enrichment_data)}".ljust(58) + "|")
    print("|" + f"  Time Elapsed:        {elapsed:.1f} seconds".ljust(58) + "|")
    print("|" + f"  Report:              {report_path}".ljust(58)[:58] + "|")
    print("+" + "=" * 58 + "+")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# CLI ARGUMENT PARSER
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Gambling OSINT Automation Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python pipeline.py                  Run full pipeline
  python pipeline.py --stage 1       Run only discovery
  python pipeline.py --stage 1 2     Run discovery + classification  
  python pipeline.py --stage 3 4     Run enrichment + correlation
  python pipeline.py --report-only   Re-generate report from existing CSVs
  python pipeline.py --keywords      Include keyword domain generation
        """,
    )

    parser.add_argument(
        "--stage", "-s",
        nargs="+",
        type=int,
        choices=[1, 2, 3, 4],
        help="Specific stage(s) to run (1=Discovery, 2=Classification, 3=Enrichment, 4=Correlation)",
    )

    parser.add_argument(
        "--report-only", "-r",
        action="store_true",
        help="Only generate the report from existing pipeline CSV outputs",
    )

    parser.add_argument(
        "--keywords", "-k",
        action="store_true",
        help="Include keyword-based domain generation in discovery (produces many candidates)",
    )

    return parser.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    setup_logging()

    args = parse_args()

    run_pipeline(
        stages=args.stage,
        include_keyword_generation=args.keywords,
        report_only=args.report_only,
    )
