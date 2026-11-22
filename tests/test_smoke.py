import unittest

from main import analyze


class AccessLogLensTests(unittest.TestCase):
    def test_parses_request_and_status_distribution(self):
        sample = (
            '198.51.100.3 - - [22/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 230\n'
            '198.51.100.3 - - [22/Nov/2026:10:00:03 +0000] "GET /missing HTTP/1.1" 404 120\n'
        )
        report = analyze(sample, threshold=2)
        self.assertEqual(report["requests"], 2)
        self.assertEqual(report["status_codes"]["200"], 1)
        self.assertEqual(report["status_codes"]["404"], 1)
        self.assertEqual(report["client_threshold_alerts"][0]["ip"], "198.51.100.3")

    def test_counts_server_errors(self):
        sample = '203.0.113.5 - - [22/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 503 30'
        report = analyze(sample)
        self.assertEqual(report["server_error_responses_5xx"], 1)

    def test_invalid_line_is_counted(self):
        report = analyze("not an access log line")
        self.assertEqual(report["malformed_lines"], 1)
        self.assertEqual(report["requests"], 0)

    def test_threshold_must_be_positive(self):
        with self.assertRaises(ValueError):
            analyze("", threshold=0)


if __name__ == "__main__":
    unittest.main()
