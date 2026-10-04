"""The scan pipeline. Read it top to bottom - each numbered step is one stage:

 1. parse     package.json + lockfile -> list of dependencies          (parser.py)
 2. lookup    ask OSV about every package@version in one batch          (osv.py)
 3. details   fetch each distinct advisory once                        (osv.py)
 4. findings  severity + fixed version + risk per vulnerability        (analysis.py)
 5. summary   counts, Risk Index, scan status                          (analysis.py)
 6. save      everything is written to SQLite in ONE transaction
"""
import json
import logging
import time
from datetime import datetime, timezone

import analysis
from db import get_conn, query
from errors import AppError
from osv import OSVClient
from npm_parser import analyze_inputs

log = logging.getLogger("devguard")
SEVERITIES = ["critical", "high", "medium", "low", "unknown"]
_CACHE = {}  # osv_id -> (fetched_at, record); advisories are reused between scans for 24 h
CACHE_SECONDS = 24 * 3600


def now():
    return datetime.now(timezone.utc).isoformat()


def normalize_record(raw):
    """Turn a raw OSV advisory into the few fields DevGuard needs."""
    severity, score, vector = analysis.normalize_severity(raw)
    affected = [{"package": a.get("package"), "ranges": a.get("ranges")} for a in raw.get("affected") or []
                if isinstance(a, dict) and (a.get("package") or {}).get("ecosystem", "npm") == "npm"]
    refs = [{"type": r.get("type"), "url": r.get("url")} for r in raw.get("references") or []
            if isinstance(r, dict) and r.get("url")][:20]
    return {"summary": (raw.get("summary") or "")[:1000], "details": (raw.get("details") or "")[:20000],
            "severity": severity, "cvss": score, "cvss_vector": vector, "aliases": raw.get("aliases") or [],
            "refs": refs, "affected": affected, "published": raw.get("published"), "modified": raw.get("modified")}


def affected_ranges(affected, name):
    out = []
    for entry in affected:
        if (entry.get("package") or {}).get("name") != name:
            continue
        for start, fixed in analysis._intervals(entry):
            out.append(f"from {start or '0'} until {fixed} (fixed in {fixed})")
    return out


def run_scan(project_id, osv=None):
    """Scan one project and return the new scan id. `osv` can be swapped for a fake in tests."""
    osv = osv or OSVClient()
    project = query("SELECT * FROM projects WHERE id = ?", (project_id,), one=True)
    if project is None:
        raise AppError(404, "project_not_found", "Project not found.")

    # 1. parse (bad input is the user's problem -> clear 422 message)
    try:
        parsed = analyze_inputs(project["manifest_text"] or "", project["lock_text"])
    except ValueError as e:
        raise AppError(422, "invalid_project_files", str(e),
                       "Check that the files are valid package.json / package-lock.json (npm 7+).")
    if not parsed.dependencies:
        raise AppError(422, "no_dependencies", "No analyzable dependencies were found.",
                       "Make sure package.json lists dependencies and the lockfile matches it.")

    conn = get_conn()
    try:
        scan_id = conn.execute(
            "INSERT INTO scans (project_id, status, mode, created_at, warnings) VALUES (?, 'running', ?, ?, ?)",
            (project_id, parsed.resolution_mode, now(), json.dumps(parsed.warnings))).lastrowid
        deps = []
        for d in parsed.dependencies:
            dep_id = conn.execute(
                "INSERT INTO dependencies (scan_id, name, version, dep_type, env, depth, path) VALUES (?,?,?,?,?,?,?)",
                (scan_id, d.name, d.version, d.dependency_type, d.environment, d.depth,
                 json.dumps(d.dependency_path))).lastrowid
            deps.append({"id": dep_id, "name": d.name, "version": d.version,
                         "type": d.dependency_type, "env": d.environment})

        # 2. lookup: one batched request instead of one per package
        errors, ids_by_dep, failed = [], {}, 0
        for dep, (ids, err) in zip(deps, osv.query_batch([(d["name"], d["version"]) for d in deps])):
            if err is not None:
                failed += 1
                errors.append(f"{dep['name']}@{dep['version']}: {err}")
                conn.execute("UPDATE dependencies SET lookup_ok = 0 WHERE id = ?", (dep["id"],))
            else:
                ids_by_dep[dep["id"]] = ids

        # 3. details: each advisory is fetched once (and cached)
        needed = sorted({i for ids in ids_by_dep.values() for i in ids})
        fresh = time.time() - CACHE_SECONDS
        to_fetch = [i for i in needed if i not in _CACHE or _CACHE[i][0] < fresh]
        if to_fetch:
            found, bad = osv.get_vulnerabilities(to_fetch)
            for osv_id, raw in found.items():
                _CACHE[osv_id] = (time.time(), normalize_record(raw))
            for osv_id, err in bad.items():
                errors.append(f"Details for {osv_id} could not be fetched: {err}")

        # 4. findings
        counts = {s: 0 for s in SEVERITIES}
        raw_total, fixable, vulnerable = 0.0, 0, set()
        for dep in deps:
            for osv_id in ids_by_dep.get(dep["id"], []):
                entry = _CACHE.get(osv_id)
                if entry is None:  # details failed: already listed in errors, scan becomes 'partial'
                    conn.execute("UPDATE dependencies SET lookup_ok = 0 WHERE id = ?", (dep["id"],))
                    continue
                rec = entry[1]
                fixed = analysis.fixed_version_for(rec["affected"], dep["name"], dep["version"])
                risk = analysis.finding_score(rec["severity"], dep["env"], dep["type"])
                conn.execute(
                    """INSERT INTO findings (scan_id, dependency_id, osv_id, summary, details, severity, cvss,
                       cvss_vector, fixed_version, affected_ranges, risk, refs, aliases, published, modified)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (scan_id, dep["id"], osv_id, rec["summary"], rec["details"], rec["severity"], rec["cvss"],
                     rec["cvss_vector"], fixed, json.dumps(affected_ranges(rec["affected"], dep["name"])), risk,
                     json.dumps(rec["refs"]), json.dumps(rec["aliases"]), rec["published"], rec["modified"]))
                counts[rec["severity"] if rec["severity"] in counts else "unknown"] += 1
                raw_total += risk
                fixable += 1 if fixed else 0
                vulnerable.add(dep["id"])

        # 5. summary + status. 'failed'/'partial' are never confused with "no vulnerabilities".
        total = sum(counts.values())
        index = analysis.risk_index(raw_total)
        direct = sum(1 for d in deps if d["type"] == "direct")
        status = "failed" if failed == len(deps) else "partial" if errors else "completed"

        # 6. save
        conn.execute(
            """UPDATE scans SET status=?, total_dependencies=?, direct_count=?, transitive_count=?,
               vulnerable_dependencies=?, total_findings=?, critical_count=?, high_count=?, medium_count=?,
               low_count=?, unknown_count=?, fixable_findings=?, lookups_failed=?, risk_index=?, risk_level=?,
               errors=? WHERE id=?""",
            (status, len(deps), direct, len(deps) - direct, len(vulnerable), total, counts["critical"],
             counts["high"], counts["medium"], counts["low"], counts["unknown"], fixable, failed, index,
             analysis.risk_level(index, total), json.dumps(errors[:50]), scan_id))
        conn.commit()
        return scan_id
    except Exception:  # keep a 'failed' scan row so the problem is visible, then report it
        log.exception("scan failed for project %s", project_id)  # full details only in the server log
        conn.rollback()
        conn.execute("INSERT INTO scans (project_id, status, mode, created_at, errors) VALUES (?, 'failed', ?, ?, ?)",
                     (project_id, parsed.resolution_mode, now(), json.dumps(["Internal error while scanning. Please try again."])))
        conn.commit()
        raise AppError(500, "scan_failed", "The scan failed unexpectedly. Please try again.")
    finally:
        conn.close()
