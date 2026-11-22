from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+"(?P<method>\S+)\s+[^"]*"\s+(?P<status>\d{3})\b'
)


def analyze(text: str, threshold: int = 100) -> dict:
    if threshold < 1:
        raise ValueError("threshold must be at least 1")

    clients = collections.Counter()
    statuses = collections.Counter()
    methods = collections.Counter()
    malformed = 0
    requests = 0

    for line in text.splitlines():
        match = LOG_PATTERN.match(line)
        if not match:
            if line.strip():
                malformed += 1
            continue

        requests += 1
        clients[match.group("ip")] += 1
        methods[match.group("method")] += 1
        statuses[match.group("status")] += 1

    return {
        "requests": requests,
        "malformed_lines": malformed,
        "status_codes": dict(sorted(statuses.items())),
        "methods": dict(sorted(methods.items())),
        "client_count": len(clients),
        "top_clients": [
            {"ip": ip, "requests": count, "threshold_exceeded": count >= threshold}
            for ip, count in clients.most_common(20)
        ],
        "client_threshold": threshold,
        "client_threshold_alerts": [
            {"ip": ip, "requests": count}
            for ip, count in clients.most_common()
            if count >= threshold
        ],
        "client_error_responses_4xx": sum(count for code, count in statuses.items() if code.startswith("4")),
        "server_error_responses_5xx": sum(count for code, count in statuses.items() if code.startswith("5")),
        "note": "High request volume is a triage signal, not proof of malicious activity. No blocking action is performed.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Summarize HTTP status distribution and frequent client IPs in combined access logs."
    )
    parser.add_argument("target", nargs="?", default="-", help="Access log path; use - or omit to read standard input.")
    parser.add_argument("--threshold", type=int, default=100, help="Minimum client requests to flag (default: 100).")
    parser.add_argument("--output", help="Optional JSON report output path.")
    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("--threshold must be at least 1")

    raw = (
        sys.stdin.read()
        if args.target == "-"
        else Path(args.target).read_text(encoding="utf-8", errors="replace")
    )
    report = analyze(raw, threshold=args.threshold)
    rendered = json.dumps(report, indent=2)

    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")

    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
