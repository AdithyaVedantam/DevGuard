"""All the analysis maths in one file: version comparison, CVSS scoring, severity, fix versions,
the DevGuard Risk Index, and scan-to-scan comparison. No database, no network.
"""
from __future__ import annotations


# ======================================================================
# semver
# ======================================================================
"""Minimal SemVer 2.0 comparison (enough for OSV `fixed` events and lockfile versions)."""

import re

_RE = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.\-]+))?(?:\+[0-9A-Za-z.\-]+)?$")


def parse(version: str):
    m = _RE.match(version.strip())
    if not m:
        return None
    core = (int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0))
    pre = m.group(4)
    if pre is None:
        return core, None
    ids = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))
    return core, ids


def compare(a: str, b: str) -> int:
    """-1 if a<b, 0 if equal, 1 if a>b. Unparseable versions fall back to string comparison."""
    pa, pb = parse(a), parse(b)
    if pa is None or pb is None:
        return (a > b) - (a < b)
    if pa[0] != pb[0]:
        return -1 if pa[0] < pb[0] else 1
    ia, ib = pa[1], pb[1]
    if ia == ib:
        return 0
    if ia is None:  # a release outranks any prerelease of the same core
        return 1
    if ib is None:
        return -1
    return -1 if ia < ib else 1

# ======================================================================
# cvss
# ======================================================================
"""CVSS v3.x base-score calculator (FIRST specification) and severity normalisation.

OSV advisories carry a CVSS vector (`severity[].score`) and/or a GitHub label
(`database_specific.severity`). normalize_severity() order of preference:
  1. a CVSS v3.x vector  -> computed score -> band (9.0+ critical, 7.0+ high, 4.0+ medium, >0 low)
  2. a structured ecosystem label (CRITICAL/HIGH/MODERATE/MEDIUM/LOW)
  3. "unknown"  (never silently "low")
"""

import math
from typing import Any

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_LABELS = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector: str) -> float | None:
    """CVSS v3.0/3.1 base score for a vector string, or None if it can't be parsed."""
    if not vector.startswith("CVSS:3"):
        return None
    try:
        m = dict(p.split(":", 1) for p in vector.split("/")[1:])
        changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}
        iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        expl = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr[m["PR"]] * _UI[m["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    raw = 1.08 * (impact + expl) if changed else impact + expl
    return _roundup(min(raw, 10.0))


def band(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"


def normalize_severity(vuln: dict[str, Any]) -> tuple[str, float | None, str | None]:
    """-> (severity label, cvss score or None, cvss vector or None)."""
    for entry in vuln.get("severity") or []:
        vec = entry.get("score") if isinstance(entry, dict) else None
        if isinstance(vec, str):
            score = cvss3_score(vec)
            if score is not None and score > 0:
                return band(score), score, vec
    label = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(label, str) and label.upper() in _LABELS:
        return _LABELS[label.upper()], None, None
    return "unknown", None, None

# ======================================================================
# fixes
# ======================================================================
"""Find the version that fixes a vulnerability for one package, from OSV `affected` data."""

from functools import cmp_to_key
from typing import Any



def _intervals(entry: dict[str, Any]) -> list[tuple[str | None, str]]:
    """[(introduced or None=from the start, fixed)] - open-ended ranges (no fix) are skipped."""
    out: list[tuple[str | None, str]] = []
    for rng in entry.get("ranges") or []:
        if rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
            continue
        start: str | None = None
        for ev in rng.get("events") or []:
            if "introduced" in ev:
                start = None if ev["introduced"] == "0" else ev["introduced"]
            elif "fixed" in ev:
                out.append((start, ev["fixed"]))
                start = None
    return out


def fixed_version_for(affected: list[dict[str, Any]], name: str, version: str) -> str | None:
    """Smallest `fixed` version that fixes `version` of npm package `name`; None if unknown."""
    candidates: list[str] = []
    for entry in affected or []:
        pkg = entry.get("package") or {}
        if pkg.get("name") != name or pkg.get("ecosystem", "npm") != "npm":
            continue
        intervals = _intervals(entry)
        containing = [f for s, f in intervals if (s is None or compare(version, s) >= 0) and compare(version, f) < 0]
        candidates.extend(containing)
        if not containing:  # fallback: any fix newer than the installed version
            candidates.extend(f for _, f in intervals if compare(f, version) > 0)
    return min(candidates, key=cmp_to_key(compare)) if candidates else None

# ======================================================================
# risk
# ======================================================================
"""DevGuard Risk Index - a transparent 0-100 score. A DevGuard analytical heuristic, NOT an
industry-standard security score.

    finding_score = severity_weight x environment_factor x exposure_factor
    raw           = sum of finding scores in the scan
    risk_index    = round(100 x (1 - e^(-raw / K)))        K = 40

severity_weight   critical 10 | high 6 | medium 3 | low 1 | unknown 2
environment       production 1.0 | development 0.4   (dev-only code rarely ships)
exposure          direct 1.0 | transitive 0.8        (you control direct dependencies)
saturating curve  first findings move the score a lot, it never exceeds 100, and zero findings is
                  exactly 0. One critical production direct finding = 22; ten of them = 92.
"""

import math

SEVERITY_WEIGHT = {"critical": 10.0, "high": 6.0, "medium": 3.0, "low": 1.0, "unknown": 2.0}
ENV_FACTOR = {"production": 1.0, "development": 0.4}
EXPOSURE_FACTOR = {"direct": 1.0, "transitive": 0.8}
SATURATION_K = 40.0


def finding_score(severity: str, environment: str, dependency_type: str) -> float:
    return (SEVERITY_WEIGHT.get(severity, SEVERITY_WEIGHT["unknown"])
            * ENV_FACTOR.get(environment, 1.0)
            * EXPOSURE_FACTOR.get(dependency_type, 0.8))


def risk_index(raw_score: float) -> int:
    if raw_score <= 0:
        return 0
    return round(100 * (1 - math.exp(-raw_score / SATURATION_K)))


def risk_level(index: int, findings: int) -> str:
    if findings == 0:
        return "none"
    if index >= 75:
        return "critical"
    if index >= 50:
        return "high"
    if index >= 25:
        return "medium"
    return "low"

# ======================================================================
# comparison
# ======================================================================
"""Pure scan-to-scan comparison. Works on plain dicts so it needs no database to test.

A finding is identified by (package name, OSV id): upgrading lodash 4.17.15 -> 4.17.21 makes
(lodash, GHSA-...) disappear = FIXED; a (name, id) pair that is new = INTRODUCED.
"""

from typing import Any

METRICS = ["risk_index", "total_findings", "critical_count", "high_count", "medium_count",
           "low_count", "unknown_count", "vulnerable_dependencies", "total_dependencies"]


def _delta(old: float, new: float) -> dict[str, Any]:
    d = new - old
    return {"old": old, "new": new, "delta": d, "direction": "down" if d < 0 else "up" if d > 0 else "same"}


def _versions(deps: list[dict[str, str]]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for d in deps:
        out.setdefault(d["name"], set()).add(d["version"])
    return out


def compare_snapshots(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """old/new = {"scan": {metric: value, "id": n}, "deps": [{name, version}], "findings": [{package,
    version, osv_id, severity}]}"""
    old_f = {(f["package"], f["osv_id"]): f for f in old["findings"]}
    new_f = {(f["package"], f["osv_id"]): f for f in new["findings"]}
    old_v, new_v = _versions(old["deps"]), _versions(new["deps"])

    fixed, introduced = [], []
    for key, f in sorted(old_f.items()):
        if key not in new_f:
            now = sorted(new_v.get(f["package"], []))
            fixed.append({**f, "resolution": f"upgraded to {', '.join(now)}" if now else "package removed"})
    for key, f in sorted(new_f.items()):
        if key not in old_f:
            introduced.append(f)

    updated, added, removed = [], [], []
    for name in sorted(set(old_v) | set(new_v)):
        if name in old_v and name in new_v:
            gone, came = old_v[name] - new_v[name], new_v[name] - old_v[name]
            if gone or came:
                updated.append({"name": name, "from": ", ".join(sorted(gone)) or "-", "to": ", ".join(sorted(came)) or "-"})
        elif name in new_v:
            added.append({"name": name, "version": ", ".join(sorted(new_v[name]))})
        else:
            removed.append({"name": name, "version": ", ".join(sorted(old_v[name]))})

    metrics = {m: _delta(old["scan"].get(m, 0), new["scan"].get(m, 0)) for m in METRICS}
    old_total = len(old_f)
    return {
        "from_scan": old["scan"].get("id"),
        "to_scan": new["scan"].get("id"),
        "metrics": metrics,
        "fixed": fixed,
        "introduced": introduced,
        "package_changes": {"updated": updated, "added": added, "removed": removed},
        "remediation_rate": round(len(fixed) / old_total, 3) if old_total else None,
        "net_change": len(new_f) - len(old_f),
        "summary": {"resolved": len(fixed), "introduced": len(introduced), "updated": len(updated),
                    "added": len(added), "removed": len(removed)},
    }
