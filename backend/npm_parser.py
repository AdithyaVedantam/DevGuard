"""Read package.json + package-lock.json as DATA (never executed) and build the dependency list.

Why the lockfile? package.json has ranges (^4.17.0); the lockfile has the exact versions npm installed,
which is what a vulnerability database needs. We walk the lockfile like Node does to find which
packages are direct vs transitive, their depth, and the path that pulled them in.
"""
from __future__ import annotations

"""Parse package.json. The file is treated purely as DATA: read with the json module, never
executed, installed or evaluated."""

import json
from dataclasses import dataclass, field


class ManifestError(ValueError):
    """package.json is unreadable or structurally invalid."""


@dataclass
class Manifest:
    name: str
    version: str | None
    dependencies: dict[str, str] = field(default_factory=dict)
    dev_dependencies: dict[str, str] = field(default_factory=dict)
    optional_dependencies: dict[str, str] = field(default_factory=dict)
    peer_dependencies: dict[str, str] = field(default_factory=dict)  # recorded, not resolved


def _dep_map(raw: object, field_name: str) -> dict[str, str]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ManifestError(f"'{field_name}' in package.json must be an object")
    return {str(k): v for k, v in raw.items() if isinstance(v, str)}  # malformed entries are skipped


def parse_package_json(text: str) -> Manifest:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ManifestError(f"package.json is not valid JSON: {exc.msg} (line {exc.lineno})") from exc
    if not isinstance(data, dict):
        raise ManifestError("package.json must contain a JSON object at the top level")
    name, version = data.get("name"), data.get("version")
    return Manifest(
        name=name.strip() if isinstance(name, str) and name.strip() else "unnamed-project",
        version=version if isinstance(version, str) else None,
        dependencies=_dep_map(data.get("dependencies"), "dependencies"),
        dev_dependencies=_dep_map(data.get("devDependencies"), "devDependencies"),
        optional_dependencies=_dep_map(data.get("optionalDependencies"), "optionalDependencies"),
        peer_dependencies=_dep_map(data.get("peerDependencies"), "peerDependencies"),
    )

"""Turn package-lock.json (lockfileVersion 2/3 `packages` map) into normalized dependency records.

Why the lockfile? package.json holds *ranges* ("^4.17.0"); the lockfile records the *exact resolved
versions* npm installed - what a vulnerability database needs.

Algorithm (no npm resolver needed - the lockfile already encodes the resolved tree):
  1. Every key like "node_modules/a/node_modules/b" is one installed package instance.
  2. Each instance lists names it depends on; we resolve a name like Node does: the package's own
     node_modules first, then walking up parent node_modules folders to the root.
  3. Breadth-first search from the root's declared dependencies gives shortest depth + path.
  4. Production vs development: reachable from dependencies/optionalDependencies => production.
"""

import json
import re
from collections import deque
from dataclasses import dataclass, field


ROOT = ""


class LockfileError(ValueError):
    """package-lock.json is unreadable or in an unsupported format."""


@dataclass
class ParsedDependency:
    name: str
    version: str
    ecosystem: str = "npm"
    dependency_type: str = "transitive"  # direct | transitive
    environment: str = "production"  # production | development
    depth: int | None = None
    dependency_path: list[str] = field(default_factory=list)


@dataclass
class ParseResult:
    root_name: str
    dependencies: list[ParsedDependency]
    warnings: list[str]
    resolution_mode: str  # "lockfile" | "manifest-ranges"


def _resolve(packages: dict, from_key: str, name: str) -> str | None:
    """Node-style module resolution inside the lockfile's `packages` map."""
    base = from_key
    while True:
        candidate = f"{base}/node_modules/{name}" if base else f"node_modules/{name}"
        if candidate in packages:
            return candidate
        if not base:
            return None
        idx = base.rfind("/node_modules/")
        base = base[:idx] if idx != -1 else ""


def _name_of(key: str, entry: dict) -> str:
    real = entry.get("name")  # present for npm aliases: the REAL package name is what OSV needs
    if isinstance(real, str) and real:
        return real
    return key.rsplit("node_modules/", 1)[1]


def _edges(packages: dict, key: str) -> list[str]:
    entry = packages[key]
    names: list[str] = []
    for field_name in ("dependencies", "optionalDependencies", "peerDependencies"):
        deps = entry.get(field_name)
        if isinstance(deps, dict):
            names.extend(deps.keys())
    out = []
    for n in names:
        target = _resolve(packages, key, n)
        if target is not None:
            out.append(target)
    return out


def parse_lockfile(manifest: Manifest, lock_text: str) -> ParseResult:
    try:
        lock = json.loads(lock_text)
    except json.JSONDecodeError as exc:
        raise LockfileError(f"package-lock.json is not valid JSON: {exc.msg} (line {exc.lineno})") from exc
    if not isinstance(lock, dict):
        raise LockfileError("package-lock.json must contain a JSON object at the top level")
    packages = lock.get("packages")
    if not isinstance(packages, dict):
        raise LockfileError(
            "This lockfile has no 'packages' map (lockfileVersion 1 is not supported). "
            "Regenerate it with npm 7+ (`npm install --package-lock-only`)."
        )

    warnings: list[str] = []
    root_entry = packages.get(ROOT) if isinstance(packages.get(ROOT), dict) else {}
    root_name = manifest.name if manifest.name != "unnamed-project" else (root_entry.get("name") or "unnamed-project")

    roots: dict[str, str] = {}
    for n in manifest.dev_dependencies:
        roots[n] = "development"
    for n in list(manifest.dependencies) + list(manifest.optional_dependencies):
        roots[n] = "production"  # production wins if a name is in both groups

    direct_env: dict[str, str] = {}
    for name, env in roots.items():
        key = _resolve(packages, ROOT, name)
        if key is None:
            warnings.append(f"'{name}' is declared in package.json but missing from the lockfile (lockfile out of date?)")
            continue
        if direct_env.get(key) != "production":
            direct_env[key] = env

    # BFS for shortest depth/path. Production roots first so ties prefer production paths.
    parent: dict[str, str | None] = {}
    depth: dict[str, int] = {}
    queue: deque[str] = deque()
    for key in sorted(direct_env, key=lambda k: (direct_env[k] != "production", k)):
        parent[key], depth[key] = None, 1
        queue.append(key)
    while queue:
        cur = queue.popleft()
        for nxt in _edges(packages, cur):
            if nxt not in depth:
                parent[nxt], depth[nxt] = cur, depth[cur] + 1
                queue.append(nxt)

    # Reachable from production roots => production; everything else is development-only.
    prod_reach: set[str] = {k for k, e in direct_env.items() if e == "production"}
    queue = deque(prod_reach)
    while queue:
        cur = queue.popleft()
        for nxt in _edges(packages, cur):
            if nxt not in prod_reach:
                prod_reach.add(nxt)
                queue.append(nxt)

    def path_for(key: str) -> list[str]:
        chain: list[str] = []
        cur: str | None = key
        while cur is not None:
            chain.append(_name_of(cur, packages[cur]))
            cur = parent[cur]
        return [root_name] + list(reversed(chain))

    merged: dict[tuple[str, str], ParsedDependency] = {}
    for key, entry in packages.items():
        if key == ROOT or not isinstance(entry, dict):
            continue
        if entry.get("link") or "node_modules/" not in key:
            continue  # workspace links / non-installed entries
        version = entry.get("version")
        if not isinstance(version, str) or not version:
            warnings.append(f"Skipped '{key}': no version recorded in lockfile")
            continue
        name = _name_of(key, entry)
        if key in depth:
            dep = ParsedDependency(
                name=name, version=version,
                dependency_type="direct" if key in direct_env else "transitive",
                environment="production" if key in prod_reach else "development",
                depth=depth[key], dependency_path=path_for(key),
            )
        else:  # in the lockfile but unreachable from the root (extraneous)
            dep = ParsedDependency(
                name=name, version=version,
                environment="development" if (entry.get("dev") or entry.get("devOptional")) else "production",
                depth=None, dependency_path=[name],
            )
        existing = merged.get((name, version))
        if existing is None:
            merged[(name, version)] = dep
            continue
        # Same name+version installed in several places: keep ONE record, best attributes win.
        if dep.dependency_type == "direct":
            existing.dependency_type = "direct"
        if dep.environment == "production":
            existing.environment = "production"
        if dep.depth is not None and (existing.depth is None or dep.depth < existing.depth):
            existing.depth, existing.dependency_path = dep.depth, dep.dependency_path

    deps = sorted(merged.values(), key=lambda d: (d.depth if d.depth is not None else 10_000, d.name, d.version))
    return ParseResult(root_name, deps, warnings, "lockfile")


_SEMVER = re.compile(r"(\d+)\.(\d+)\.(\d+)(?:-[0-9A-Za-z.\-]+)?")
_NON_REGISTRY = ("git", "http", "file:", "link:", "workspace:", "npm:", "github:", "/", ".")


def parse_manifest_only(manifest: Manifest) -> ParseResult:
    """Best-effort mode without a lockfile: a range is approximated by its first concrete x.y.z.
    Transitive dependencies cannot be known, so only direct ones are analyzed."""
    warnings = [
        "No package-lock.json supplied: versions were inferred from package.json ranges and "
        "transitive dependencies are NOT analyzed. Provide a lockfile for accurate results."
    ]
    deps: list[ParsedDependency] = []
    groups = [(manifest.dependencies, "production"), (manifest.optional_dependencies, "production"),
              (manifest.dev_dependencies, "development")]
    seen: set[str] = set()
    for group, env in groups:
        for name, spec in group.items():
            if name in seen:
                continue
            spec_s = spec.strip()
            match = None if spec_s.startswith(_NON_REGISTRY) else _SEMVER.search(spec_s)
            if not match:
                warnings.append(f"Skipped '{name}@{spec}': cannot infer a concrete version")
                continue
            seen.add(name)
            deps.append(ParsedDependency(name=name, version=match.group(0), dependency_type="direct",
                                         environment=env, depth=1, dependency_path=[manifest.name, name]))
    return ParseResult(manifest.name, deps, warnings, "manifest-ranges")


def analyze_inputs(package_json_text: str, lock_text: str | None) -> ParseResult:
    """Single entry point used by the API: lockfile if present, otherwise manifest-only fallback."""
    manifest = parse_package_json(package_json_text)
    if lock_text and lock_text.strip():
        return parse_lockfile(manifest, lock_text)
    return parse_manifest_only(manifest)
