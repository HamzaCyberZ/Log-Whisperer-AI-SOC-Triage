# utils/log_parser.py
"""
Log parsing and normalization utilities.

Handles multiple log formats:
- SSH / auth.log (syslog style)
- nginx / Apache access logs (combined format)
- Kubernetes / container logs (ISO timestamp + level)
- Generic fallback
"""
import re
from datetime import datetime


# ---------------------------------------------------------------------------
# Timestamp patterns
# ---------------------------------------------------------------------------
SYSLOG_TS = re.compile(r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})')
ISO_TS = re.compile(r'^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})')
NGINX_TS = re.compile(r'\[(\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}[^\]]*)\]')

IP_RE = re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b')
HASH_RE = re.compile(r'\b[0-9a-f]{8,}\b')
NUM_RE = re.compile(r'\b\d+\b')
PATH_RE = re.compile(r'(/[A-Za-z0-9_\-./]+)')


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------
def normalize_line(line: str) -> str:
    """
    Replace variable parts of a log line with placeholders.
    Keeps *structure* intact so anomaly detection focuses on patterns.
    """
    line = SYSLOG_TS.sub('<TS>', line)
    line = ISO_TS.sub('<TS>', line)
    line = NGINX_TS.sub('[<TS>]', line)
    line = IP_RE.sub('<IP>', line)
    line = HASH_RE.sub('<HASH>', line)
    line = NUM_RE.sub('<NUM>', line)
    return line


def split_logs(raw_logs: str) -> list[str]:
    """Split raw pasted text into clean, non-empty lines."""
    return [l.rstrip() for l in raw_logs.strip().split('\n') if l.strip()]


# ---------------------------------------------------------------------------
# Extraction helpers used by the report layer
# ---------------------------------------------------------------------------
def extract_ips(line: str) -> list[str]:
    """Return all IPv4 addresses present in a line."""
    return IP_RE.findall(line)


def extract_timestamp(line: str) -> str:
    """
    Best-effort timestamp extraction. Returns empty string if none found.
    """
    for pat in (ISO_TS, SYSLOG_TS):
        m = pat.search(line)
        if m:
            return m.group(1).strip()

    m = NGINX_TS.search(line)
    if m:
        return m.group(1).split()[0]

    return ""


def extract_status_code(line: str) -> int | None:
    """
    Extract HTTP status code from nginx/Apache-style logs.
    Looks for the token following the request-in-quotes block.
    """
    # e.g. ... "GET /x HTTP/1.1" 404 152
    m = re.search(r'"\s+(\d{3})\s+\d+', line)
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            return None
    return None


def extract_path(line: str) -> str:
    """Extract the first URL path in the line (nginx / generic)."""
    m = re.search(r'"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+([^\s"]+)', line)
    if m:
        return m.group(1)
    m = PATH_RE.search(line)
    return m.group(1) if m else ""


# ---------------------------------------------------------------------------
# Signature dictionary (used by llm_triage for rule hints)
# ---------------------------------------------------------------------------
ATTACK_SIGNATURES = {
    "ssh_bruteforce": [
        r'Failed password for',
        r'Invalid user',
        r'authentication failure',
        r'Failed publickey',
    ],
    "ssh_success": [
        r'Accepted password for',
        r'Accepted publickey for',
        r'session opened for user',
    ],
    "web_scan": [
        r'/admin',
        r'/wp-login',
        r'/phpmyadmin',
        r'/\.env',
        r'/\.git',
        r'/config\.php',
        r'/backup\.zip',
    ],
    "command_injection": [
        r'cmd=',
        r'exec=',
        r';cat\s',
        r'\|\s*sh',
        r'%7C',
        r'\$\(.*\)',
    ],
    "sql_injection": [
        r"'\s*OR\s*'1'\s*=\s*'1",
        r'UNION\s+SELECT',
        r'--\s',
        r"OR\s+1=1",
    ],
    "path_traversal": [
        r'\.\./\.\./',
        r'%2e%2e%2f',
    ],
}


def signature_matches(line: str) -> list[str]:
    """Return the names of attack signatures matching this line."""
    hits = []
    for name, patterns in ATTACK_SIGNATURES.items():
        for p in patterns:
            if re.search(p, line, re.IGNORECASE):
                hits.append(name)
                break
    return hits