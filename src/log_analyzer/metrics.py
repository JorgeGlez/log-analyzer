"""Metrics calculation and aggregation logic."""

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from log_analyzer.models import LogEntry


@dataclass
class MetricsAggregator:
    """Aggregates log events and calculates requested analytics."""

    total_events: int = 0
    total_bytes_transferred: int = 0
    ip_counter: Counter[str] = field(default_factory=Counter)
    min_timestamp: float = float("inf")
    max_timestamp: float = float("-inf")

    def process_entry(self, entry: LogEntry) -> None:
        """Ingests a single LogEntry into the running statistics."""
        self.total_events += 1
        self.total_bytes_transferred += entry.total_bytes
        self.ip_counter[entry.client_ip] += 1

        if entry.timestamp < self.min_timestamp:
            self.min_timestamp = entry.timestamp
        if entry.timestamp > self.max_timestamp:
            self.max_timestamp = entry.timestamp

    def get_most_frequent_ip(self) -> dict[str, Any] | None:
        """Returns the most frequent IP address and its hit count."""
        if not self.ip_counter:
            return None
        ip, count = self.ip_counter.most_common(1)[0]
        return {"ip": ip, "count": count}

    def get_least_frequent_ip(self) -> dict[str, Any] | None:
        """Returns the least frequent IP address and its hit count."""
        if not self.ip_counter:
            return None
        ip, count = self.ip_counter.most_common()[-1]
        return {"ip": ip, "count": count}

    def get_events_per_second(self) -> float:
        """Calculates overall events per second across the time range."""
        if self.total_events == 0 or self.min_timestamp == float("inf"):
            return 0.0

        duration_seconds = self.max_timestamp - self.min_timestamp
        if duration_seconds <= 0:
            return float(self.total_events)

        return round(self.total_events / duration_seconds, 4)

    def get_total_bytes(self) -> int:
        """Returns total bytes exchanged across all parsed records."""
        return self.total_bytes_transferred
