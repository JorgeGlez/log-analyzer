"""Command Line Interface (CLI) entry point for log analyzer."""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

from log_analyzer.metrics import MetricsAggregator
from log_analyzer.parser import SquidLogParser

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("log_analyzer")


def create_argument_parser() -> argparse.ArgumentParser:
    """Builds and configures the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="log-analyzer",
        description="Command-line log analyzer for Squid proxy access logs.",
    )

    parser.add_argument(
        "-i",
        "--input",
        nargs="+",
        required=True,
        type=Path,
        help="Path to one or more log files (supports plain text and .gz files).",
    )
    parser.add_argument(
        "-o",
        "--output",
        required=True,
        type=Path,
        help="Path to save the analysis output in plain text JSON format.",
    )

    parser.add_argument(
        "--mfip",
        action="store_true",
        help="Calculate the most frequent IP address.",
    )
    parser.add_argument(
        "--lfip",
        action="store_true",
        help="Calculate the least frequent IP address.",
    )
    parser.add_argument(
        "--eps",
        action="store_true",
        help="Calculate the events per second (EPS).",
    )
    parser.add_argument(
        "--bytes",
        action="store_true",
        help="Calculate the total amount of bytes exchanged.",
    )

    return parser


def main() -> None:
    """CLI execution entrypoint."""
    parser = create_argument_parser()
    args = parser.parse_args()

    active_operations = {
        "mfip": args.mfip,
        "lfip": args.lfip,
        "eps": args.eps,
        "bytes": args.bytes,
    }
    if not any(active_operations.values()):
        logger.info("No specific metric flag provided. Enabling all operations by default.")
        for op in active_operations:
            active_operations[op] = True

    aggregator = MetricsAggregator()
    total_files_processed = 0

    for input_file in args.input:
        if not input_file.exists():
            logger.error("Skipping missing file: %s", input_file)
            continue

        logger.info("Processing file: %s", input_file)
        try:
            for entry in SquidLogParser.stream_entries(input_file):
                aggregator.process_entry(entry)
            total_files_processed += 1
        except Exception as error:
            logger.error("Error processing file %s: %s", input_file, error)

    if total_files_processed == 0:
        logger.error("No valid log files were processed. Aborting.")
        sys.exit(1)

    results: dict[str, Any] = {
        "summary": {
            "files_processed": total_files_processed,
            "total_events_parsed": aggregator.total_events,
        }
    }

    if active_operations["mfip"]:
        results["most_frequent_ip"] = aggregator.get_most_frequent_ip()
    if active_operations["lfip"]:
        results["least_frequent_ip"] = aggregator.get_least_frequent_ip()
    if active_operations["eps"]:
        results["events_per_second"] = aggregator.get_events_per_second()
    if active_operations["bytes"]:
        results["total_bytes_exchanged"] = aggregator.get_total_bytes()

    try:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, mode="w", encoding="utf-8") as out_file:
            json.dump(results, out_file, indent=2)
        logger.info("Successfully exported metrics to: %s", args.output)
    except OSError as io_error:
        logger.error("Failed to write output to %s: %s", args.output, io_error)
        sys.exit(1)


if __name__ == "__main__":
    main()
