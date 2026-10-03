"""All the SELECT queries the dashboard needs. The analytics are plain SQL (GROUP BY / JOIN)."""
import json

import analysis
from db import query
from errors import AppError

RANK = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "unknown"}


def _scan(row):
    if row:
        row["warnings"] = json.loads(row.get("warnings") or "[]")
        row["errors"] = json.loads(row.get("errors") or "[]")
        n = row["total_dependencies"] or 0
        row["density"] = round(row["total_findings"] / n, 3) if n else 0
    return row


def list_projects():
    projects = query("SELECT id, name, source_type, repo_url, created_at FROM projects ORDER BY id DESC")
    for p in projects:
        p["latest_scan"] = _scan(query("SELECT * FROM scans WHERE project_id=? ORDER BY id DESC LIMIT 1", (p["id"],), one=True))
        p["scan_count"] = query("SELECT COUNT(*) AS n FROM scans WHERE project_id=?", (p["id"],), one=True)["n"]
    return projects


def get_project(project_id):
    p = query("SELECT id, name, source_type, repo_url, branch, created_at FROM projects WHERE id=?", (project_id,), one=True)
    if p is None:
        raise AppError(404, "project_not_found", "Project not found.")
    return p


def list_scans(project_id):
    return [_scan(s) for s in query("SELECT * FROM scans WHERE project_id=? ORDER BY id DESC", (project_id,))]


def get_scan(scan_id):
    s = _scan(query("SELECT * FROM scans WHERE id=?", (scan_id,), one=True))
    if s is None:
        raise AppError(404, "scan_not_found", "Scan not found.")
    return s


def previous_scan_id(scan):
    row = query("SELECT id FROM scans WHERE project_id=? AND id<? AND status IN ('completed','partial') ORDER BY id DESC LIMIT 1",
                (scan["project_id"], scan["id"]), one=True)
    return row["id"] if row else None


def findings(scan_id):
    return query("""SELECT f.id, f.osv_id, f.summary, f.severity, f.cvss, f.fixed_version, f.risk,
                           d.name AS package, d.version, d.dep_type, d.env, d.depth
                    FROM findings f JOIN dependencies d ON d.id = f.dependency_id
                    WHERE f.scan_id = ? ORDER BY f.risk DESC, d.name""", (scan_id,))


def finding_detail(finding_id):
    f = query("""SELECT f.*, d.name AS package, d.version, d.dep_type, d.env, d.depth, d.path
                 FROM findings f JOIN dependencies d ON d.id = f.dependency_id WHERE f.id = ?""", (finding_id,), one=True)
    if f is None:
        raise AppError(404, "finding_not_found", "Finding not found.")
    for k in ("path", "refs", "aliases", "affected_ranges"):
        f[k] = json.loads(f.get(k) or "[]")
    return f


def dependencies(scan_id):
    rows = query("""SELECT d.id, d.name, d.version, d.dep_type, d.env, d.depth, d.path, d.lookup_ok,
                           COUNT(f.id) AS vuln_count,
                           MAX(CASE f.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2
                                               WHEN 'low' THEN 1 WHEN 'unknown' THEN 0 ELSE -1 END) AS worst,
                           COALESCE(ROUND(SUM(f.risk), 1), 0) AS risk
                    FROM dependencies d LEFT JOIN findings f ON f.dependency_id = d.id
                    WHERE d.scan_id = ? GROUP BY d.id ORDER BY vuln_count DESC, risk DESC, d.name""", (scan_id,))
    for r in rows:
        r["path"] = json.loads(r["path"] or "[]")
        r["worst_severity"] = RANK.get(r.pop("worst"), None) if r["vuln_count"] else None
    return rows


def _split(scan_id, column):
    """Total vs vulnerable packages grouped by dep_type or env (SQL GROUP BY)."""
    return query(f"""SELECT d.{column} AS label, COUNT(*) AS total,
                            SUM(CASE WHEN EXISTS (SELECT 1 FROM findings f WHERE f.dependency_id = d.id)
                                     THEN 1 ELSE 0 END) AS vulnerable
                     FROM dependencies d WHERE d.scan_id = ? GROUP BY d.{column}""", (scan_id,))


def top_packages(scan_id, limit=8):
    return query("""SELECT d.name, d.version, d.dep_type, d.env, COUNT(f.id) AS findings,
                           ROUND(SUM(f.risk), 1) AS risk, SUM(f.severity = 'critical') AS critical,
                           SUM(f.severity = 'high') AS high
                    FROM dependencies d JOIN findings f ON f.dependency_id = d.id
                    WHERE d.scan_id = ? GROUP BY d.id ORDER BY SUM(f.risk) DESC LIMIT ?""", (scan_id, limit))


def snapshot(scan_id):
    """A scan as plain data, in the shape analysis.compare_snapshots() expects."""
    scan = get_scan(scan_id)
    deps = query("SELECT name, version FROM dependencies WHERE scan_id=?", (scan_id,))
    finds = query("""SELECT d.name AS package, d.version, f.osv_id, f.severity FROM findings f
                     JOIN dependencies d ON d.id = f.dependency_id WHERE f.scan_id = ?""", (scan_id,))
    return {"scan": scan, "deps": deps, "findings": finds}


def compare(new_id, old_id):
    new, old = snapshot(new_id), snapshot(old_id)
    if new["scan"]["project_id"] != old["scan"]["project_id"]:
        raise AppError(422, "different_projects", "Those scans belong to different projects.")
    result = analysis.compare_snapshots(old, new)
    result["comparable"] = old["scan"]["status"] == "completed" and new["scan"]["status"] == "completed"
    if not result["comparable"]:
        result["note"] = "One of these scans is partial or failed, so differences may reflect missing lookups."
    return result


def summary(project_id):
    """Everything the Overview tab shows, computed from SQL."""
    project = get_project(project_id)
    latest = _scan(query("SELECT * FROM scans WHERE project_id=? ORDER BY id DESC LIMIT 1", (project_id,), one=True))
    if latest is None:
        return {"project": project, "scan": None}
    usable = query("SELECT id, created_at, risk_index, total_findings, critical_count, high_count FROM scans "
                   "WHERE project_id=? AND status IN ('completed','partial') ORDER BY id", (project_id,))
    prev_id = previous_scan_id(latest) if latest["status"] != "failed" else None
    return {"project": project, "scan": latest, "trend": usable,
            "exposure": _split(latest["id"], "dep_type"), "environment": _split(latest["id"], "env"),
            "top_packages": top_packages(latest["id"]),
            "changes": compare(latest["id"], prev_id) if prev_id else None}


def findings_csv(scan_id):
    """The findings as CSV text (for Excel / Google Sheets)."""
    import csv
    import io

    def safe(v):  # stop spreadsheet programs from treating text like "=1+1" or "@scope/pkg" as a formula
        v = "" if v is None else str(v)
        return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v

    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["package", "version", "advisory", "severity", "cvss", "fixed_in", "type", "environment", "summary"])
    for f in findings(scan_id):
        w.writerow([safe(x) for x in (f["package"], f["version"], f["osv_id"], f["severity"], f["cvss"],
                                      f["fixed_version"], f["dep_type"], f["env"], f["summary"])])
    return out.getvalue()
