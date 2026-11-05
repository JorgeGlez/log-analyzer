"""Domain models for the log analyzer tool."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class LogEntry:
    """Represents a structured Squid access log entry."""

    timestamp: float
    header_size: int
    client_ip: str
    response_code: str
    response_size: int
    http_method: str
    url: str
    username: str
    access_destination: str
    response_type: str

    @property
    def total_bytes(self) -> int:
        """Calculate total bytes transferred (header + payload)."""
        return self.header_size + self.response_size
