"""Streaming log parser with error handling and format extensibility."""

import gzip
import logging
from pathlib import Path
from typing import Generator

from log_analyzer.models import LogEntry

logger = logging.getLogger(__name__)


class SquidLogParser:
    """Parser for Squid proxy access logs separated by whitespace."""

    EXPECTED_FIELD_COUNT = 10

    @classmethod
    def parse_line(cls, line: str, line_number: int = 0) -> LogEntry | None:
        """
        Parses a single log line into a LogEntry instance.
        Returns None if line is malformed or corrupted.
        """
        stripped_line = line.strip()
        if not stripped_line or stripped_line.startswith("#"):
            return None

        # Split into at most 10 parts by whitespace
        parts = stripped_line.split(maxsplit=cls.EXPECTED_FIELD_COUNT - 1)
        if len(parts) < cls.EXPECTED_FIELD_COUNT:
            logger.warning("Line %d skipped: insufficient fields (%d)", line_number, len(parts))
            return None

        try:
            timestamp = float(parts[0])
            header_size = int(parts[1])
            client_ip = parts[2]
            response_code = parts[3]
            response_size = int(parts[4])
            http_method = parts[5]
            url = parts[6]
            username = parts[7]
            access_destination = parts[8]
            response_type = parts[9]

            return LogEntry(
                timestamp=timestamp,
                header_size=header_size,
                client_ip=client_ip,
                response_code=response_code,
                response_size=response_size,
                http_method=http_method,
                url=url,
                username=username,
                access_destination=access_destination,
                response_type=response_type,
            )
        except (ValueError, IndexError) as parse_error:
            logger.warning("Line %d parsing error: %s", line_number, parse_error)
            return None

    @classmethod
    def stream_entries(cls, file_path: Path) -> Generator[LogEntry, None, None]:
        """
        Streams LogEntry records from a plain text or gzip-compressed file.
        """
        if not file_path.exists():
            raise FileNotFoundError(f"Input file not found: {file_path}")

        opener = gzip.open if file_path.suffix.lower() == ".gz" else open

        with opener(file_path, mode="rt", encoding="utf-8", errors="replace") as stream:
            for line_idx, line in enumerate(stream, start=1):
                entry = cls.parse_line(line, line_number=line_idx)
                if entry is not None:
                    yield entry
