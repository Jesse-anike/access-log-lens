# ACCESS LOG LENS — Apache Access Log Analyzer

A read-only Python analyzer for Apache/Nginx-style combined access logs. Summarizes request volume, HTTP status codes, HTTP methods, and the busiest client IP addresses.

## Features

- Parses common combined-log request lines.
- Counts requests by client IP, HTTP method and status code.
- Highlights frequent clients using a configurable threshold.
- Reports 4xx and 5xx totals for quick triage.
- Outputs JSON to the terminal or an optional report file.
- Uses only the Python standard library.

## Requirements

- Python 3.10+
- No third-party packages or credentials.

## Quick start

```bash
python main.py sample.log
```

Flag clients with at least 100 requests:

```bash
python main.py access.log --threshold 100
```

Read from stdin and save a JSON report:

```bash
cat /var/log/apache2/access.log | python main.py - --threshold 50 --output report.json
```

## Tests

```bash
python -m unittest discover -s tests -v
python main.py --help
```

## Security and operational notes

The analyzer is read-only and does not block clients or alter server configuration. A high request count is not proof of malicious activity; compare traffic with known crawlers, expected application behavior, proxy/load-balancer configuration, and the relevant time window. Consider trusted reverse proxies when interpreting client IP addresses.

Use only logs you are authorized to access. Review and redact personal or sensitive data before sharing reports.

## Portfolio context

Built for Anike-Moses Melie Jesse's defensive cybersecurity and cloud-security portfolio, demonstrating Python parsing, HTTP telemetry analysis, event aggregation, and incident-triage reporting.
