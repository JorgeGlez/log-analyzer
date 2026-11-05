"""Automated unit tests for the log analyzer components."""

import unittest
from log_analyzer.metrics import MetricsAggregator
from log_analyzer.parser import SquidLogParser


class TestLogAnalyzer(unittest.TestCase):

    def test_parser_valid_line(self) -> None:
        sample_line = (
            "1157689324.156 1372 10.105.21.199 TCP_MISS/200 399 GET "
            "http://www.google-analytics.com/__utm.gif? badeyek DIRECT/66.102.9.147 image/gif"
        )
        entry = SquidLogParser.parse_line(sample_line)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.timestamp, 1157689324.156)
        self.assertEqual(entry.header_size, 1372)
        self.assertEqual(entry.client_ip, "10.105.21.199")
        self.assertEqual(entry.response_code, "TCP_MISS/200")
        self.assertEqual(entry.response_size, 399)
        self.assertEqual(entry.total_bytes, 1372 + 399)

    def test_parser_malformed_line_returns_none(self) -> None:
        malformed_line = "1157689324.156 invalid_log_entry_too_few_fields"
        self.assertIsNone(SquidLogParser.parse_line(malformed_line))

    def test_metrics_aggregator(self) -> None:
        line_1 = (
            "100.0 100 192.168.1.10 TCP_MISS/200 200 GET http://example.com/a user DIRECT/ip text/html"
        )
        line_2 = (
            "110.0 50 192.168.1.10 TCP_MISS/200 50 GET http://example.com/b user DIRECT/ip text/html"
        )
        line_3 = (
            "120.0 300 10.0.0.5 TCP_MISS/200 300 GET http://example.com/c user DIRECT/ip text/html"
        )

        aggregator = MetricsAggregator()
        for line in [line_1, line_2, line_3]:
            entry = SquidLogParser.parse_line(line)
            self.assertIsNotNone(entry)
            aggregator.process_entry(entry)

        self.assertEqual(aggregator.total_events, 3)
        self.assertEqual(aggregator.get_total_bytes(), (300 + 100 + 600))
        self.assertEqual(aggregator.get_most_frequent_ip(), {"ip": "192.168.1.10", "count": 2})
        self.assertEqual(aggregator.get_least_frequent_ip(), {"ip": "10.0.0.5", "count": 1})
        self.assertEqual(aggregator.get_events_per_second(), 0.15)


if __name__ == "__main__":
    unittest.main()
