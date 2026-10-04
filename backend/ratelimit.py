"""Tiny in-memory rate limiter (per IP). Only active on a public deployment (DEVGUARD_PUBLIC=1),
so strangers cannot burn your AI quota or hammer OSV through your server."""
import os
import threading
import time
from collections import defaultdict, deque

from errors import AppError

_hits = defaultdict(deque)
_lock = threading.Lock()


def check(ip, bucket, max_calls, window=3600):
    if os.environ.get("DEVGUARD_PUBLIC") != "1":
        return
    now = time.time()
    with _lock:
        q = _hits[(ip, bucket)]
        while q and q[0] < now - window:
            q.popleft()
        if len(q) >= max_calls:
            raise AppError(429, "rate_limited", "Too many requests. Please try again later.")
        q.append(now)
