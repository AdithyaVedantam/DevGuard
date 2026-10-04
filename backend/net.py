"""Tiny HTTP helper built on Python's standard library (no `requests` needed).
Used for OSV, GitHub and Gemini. Retries on timeouts / 429 / 5xx."""
import json
import logging
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

log = logging.getLogger("devguard")


class NetError(Exception):
    def __init__(self, message, status=None, body=""):
        super().__init__(message)
        self.status, self.body = status, body


def _ssl_context():
    try:  # certifi gives reliable certificates on every OS (installed via requirements.txt)
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def fetch(url, method="GET", body=None, headers=None, timeout=30, retries=1, max_bytes=None):
    """Return the response body as bytes. `body` (a dict) is sent as JSON."""
    data = json.dumps(body).encode() if body is not None else None
    hdrs = {"User-Agent": "DevGuard", **(headers or {})}
    if body is not None:
        hdrs.setdefault("Content-Type", "application/json")
    last = NetError("request failed")
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
            with urllib.request.urlopen(req, timeout=timeout, context=_ssl_context()) as resp:
                raw = resp.read(max_bytes + 1) if max_bytes else resp.read()
            if max_bytes and len(raw) > max_bytes:
                raise NetError("response too large")
            return raw
        except urllib.error.HTTPError as e:  # must come before URLError (it is a subclass)
            detail = e.read(500).decode("utf-8", "replace") if hasattr(e, "read") else ""
            e.close()
            log.warning("HTTP %s from %s: %s", e.code, urllib.parse.urlparse(url).netloc, detail[:200])
            if e.code != 429 and e.code < 500:
                raise NetError(f"HTTP {e.code}", e.code, detail) from e
            last = NetError(f"HTTP {e.code}", e.code, detail)
        except NetError:
            raise
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            log.warning("network error calling %s: %s", urllib.parse.urlparse(url).netloc, e)
            last = NetError("network error")  # details stay in the server log, not in user-visible text
        if attempt < retries - 1:
            time.sleep(0.5 * (2 ** attempt))
    raise last


def fetch_json(url, **kw):
    raw = fetch(url, **kw)
    try:
        return json.loads(raw)
    except ValueError:
        raise NetError("response was not valid JSON")
