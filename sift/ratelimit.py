"""
In-memory rate limiting for login attempts and webhook ingestion.

Counters reset on restart, which is acceptable for stdlib-only design. Each
bucket tracks (count, window_start) per source IP and returns True when the
caller should be allowed, False when the limit is exceeded.
"""

import threading
import time

import config

_lock = threading.Lock()

# {ip: [timestamp, ...]}  — sliding window per IP
_login_failures: dict = {}
_webhook_requests: dict = {}


def _sliding_count(bucket: dict, ip: str, window_s: int) -> int:
    """Count events in the last window_s seconds and prune stale entries."""
    now = time.monotonic()
    cutoff = now - window_s
    events = [t for t in bucket.get(ip, []) if t >= cutoff]
    bucket[ip] = events
    return len(events)


def _record(bucket: dict, ip: str) -> None:
    bucket.setdefault(ip, []).append(time.monotonic())


def check_login(ip: str) -> bool:
    """
    Return True if this IP is allowed another login attempt.
    Call record_login_failure() separately when the attempt fails.
    """
    with _lock:
        count = _sliding_count(_login_failures, ip, config.RATE_LIMIT_LOGIN_WINDOW_S)
    return count < config.RATE_LIMIT_LOGIN_MAX


def record_login_failure(ip: str) -> None:
    with _lock:
        _record(_login_failures, ip)


def check_webhook(ip: str) -> bool:
    """Return True if this IP is allowed to POST to a webhook endpoint."""
    with _lock:
        count = _sliding_count(_webhook_requests, ip, config.RATE_LIMIT_WEBHOOK_WINDOW_S)
        if count < config.RATE_LIMIT_WEBHOOK_MAX:
            _record(_webhook_requests, ip)
            return True
        return False
