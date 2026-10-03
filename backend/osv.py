"""OSV (https://osv.dev) client. Two calls:
  1. /v1/querybatch  - ask about MANY package@version pairs in one request (fast)
  2. /v1/vulns/{id}  - get the full advisory (summary, severity, affected ranges, references)

Important rule: a failed lookup is NOT "no vulnerabilities". query_batch() returns for every package
either (list_of_ids, None) or (None, "error text"). The scan then becomes 'partial'/'failed'.
"""
import os
from concurrent.futures import ThreadPoolExecutor

from net import NetError, fetch_json

BASE = os.environ.get("OSV_API_BASE_URL", "https://api.osv.dev").rstrip("/")


class OSVClient:
    def __init__(self, base=None, batch_size=500, retries=3):
        self.base, self.batch_size, self.retries = (base or BASE).rstrip("/"), batch_size, retries

    def query_batch(self, packages):
        """packages = [(name, version), ...]  ->  [(ids or None, error or None), ...] same order."""
        results = [(None, "not queried")] * len(packages)
        for start in range(0, len(packages), self.batch_size):
            chunk = packages[start:start + self.batch_size]
            body = {"queries": [{"package": {"name": n, "ecosystem": "npm"}, "version": v} for n, v in chunk]}
            try:
                data = fetch_json(f"{self.base}/v1/querybatch", method="POST", body=body, retries=self.retries)
                items = data.get("results")
                if not isinstance(items, list) or len(items) != len(chunk):
                    raise NetError("OSV sent a malformed response")
            except NetError as e:
                for i in range(len(chunk)):
                    results[start + i] = (None, str(e))
                continue
            for i, item in enumerate(items):
                try:
                    ids = [v["id"] for v in (item or {}).get("vulns", []) if "id" in v]
                    token = (item or {}).get("next_page_token")
                    name, version = chunk[i]
                    while token:  # long result lists come in pages
                        page = fetch_json(f"{self.base}/v1/query", method="POST", retries=self.retries, body={
                            "package": {"name": name, "ecosystem": "npm"}, "version": version, "page_token": token})
                        ids += [v["id"] for v in page.get("vulns", []) if "id" in v]
                        token = page.get("next_page_token")
                    results[start + i] = (list(dict.fromkeys(ids)), None)
                except NetError as e:
                    results[start + i] = (None, str(e))
        return results

    def get_vulnerabilities(self, ids):
        """Fetch each advisory once, in parallel. Returns (found: {id: record}, failed: {id: error})."""
        found, failed = {}, {}

        def one(osv_id):
            try:
                found[osv_id] = fetch_json(f"{self.base}/v1/vulns/{osv_id}", retries=self.retries)
            except NetError as e:
                failed[osv_id] = str(e)

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(one, ids))
        return found, failed
