"""Find every npm project inside a repository or an uploaded folder (monorepos, backend/ + frontend/).

Both entry points (GitHub import and folder upload) produce the same plain "items":

    {"path": "backend", "manifest": "<package.json text>", "lock": "<package-lock.json text>" | None}

where `path` is the folder relative to the repository / upload root ("" = the root itself).
Everything here only reads text. Nothing is written to disk, cloned, installed or executed.
"""
import json
import posixpath
import re

MANIFEST, LOCKFILE = "package.json", "package-lock.json"
IGNORED_DIRS = {"node_modules", ".git", "bower_components"}  # never real projects
MAX_PROJECTS = 10  # one scan = one OSV round trip, so a single import is capped
MAX_UPLOAD_FILES = 60


def clean_path(raw):
    """Normalise a relative path to 'a/b/c.json'. Raises ValueError for anything suspicious.
    The path is only ever used as a label and for grouping - it never touches the file system."""
    p = str(raw or "").replace("\\", "/").strip()
    parts = [seg for seg in p.split("/") if seg not in ("", ".")]
    if any(seg == ".." for seg in parts) or len(p) > 400:
        raise ValueError("invalid path")
    return "/".join(parts)


def is_ignored(path):
    return any(seg in IGNORED_DIRS for seg in path.split("/"))


def depth_of(path):
    return len(path.split("/")) if path else 0


def sort_items(items):
    return sorted(items, key=lambda i: (depth_of(i["path"]), i["path"]))


def _workspace_patterns(manifest_text):
    """The `workspaces` globs of a package.json (list form or {"packages": [...]}), as regexes."""
    try:
        data = json.loads(manifest_text)
    except ValueError:
        return []
    ws = data.get("workspaces") if isinstance(data, dict) else None
    if isinstance(ws, dict):
        ws = ws.get("packages")
    out = []
    for pattern in ws if isinstance(ws, list) else []:
        if not isinstance(pattern, str) or pattern.startswith("!"):
            continue
        parts = [seg for seg in pattern.strip().strip("/").split("/") if seg not in ("", ".")]
        rx = "/".join(".+" if seg == "**" else re.escape(seg).replace(r"\*", "[^/]*").replace(r"\?", "[^/]") for seg in parts)
        out.append(re.compile(rf"^{rx}$"))
    return out


def _is_workspace_member(ancestor_manifest, relative_path):
    return any(rx.match(relative_path) for rx in _workspace_patterns(ancestor_manifest))


def apply_limits(items):
    """Drop npm-workspace members (their root lockfile already covers them) and enforce MAX_PROJECTS.
    Returns (kept, skipped) where skipped = [{"path": ..., "reason": ...}]."""
    items = sort_items(items)
    by_path = {i["path"]: i for i in items}
    kept, skipped = [], []
    for item in items:
        covered_by = None
        if not item["lock"]:  # a member with its own lockfile is a separate project
            parent = posixpath.dirname(item["path"])
            while True:
                anc = by_path.get(parent) if item["path"] else None
                rel = item["path"][len(parent) + 1:] if parent else item["path"]
                if anc is not None and anc["lock"] and _is_workspace_member(anc["manifest"], rel):
                    covered_by = parent
                    break
                if not parent:
                    break
                parent = posixpath.dirname(parent)
        if covered_by is not None:
            skipped.append({"path": item["path"], "reason": f"npm workspace member - already covered by the lockfile in '{covered_by or '.'}'"})
        else:
            kept.append(item)
    for item in kept[MAX_PROJECTS:]:
        skipped.append({"path": item["path"], "reason": f"limit of {MAX_PROJECTS} projects per import reached"})
    return kept[:MAX_PROJECTS], skipped


def group_uploaded(entries):
    """entries = [(relative_path, text), ...] from a folder upload.
    Pairs each package.json with the package-lock.json in the SAME folder.
    Returns (items, skipped, root_label). The first path segment (the folder the user picked) is stripped when
    every file shares it, so project names read 'backend', not 'my-folder/backend'."""
    files = {}
    skipped = []
    for raw_path, text in entries:
        try:
            path = clean_path(raw_path)
        except ValueError:
            skipped.append({"path": str(raw_path)[:80], "reason": "unsafe path ignored"})
            continue
        name = posixpath.basename(path)
        if name not in (MANIFEST, LOCKFILE):
            continue  # silently ignore anything else (a folder pick can contain thousands of files)
        if is_ignored(path):
            continue
        files[path] = text

    tops = {p.split("/")[0] for p in files if "/" in p}
    strip_top = len(tops) == 1 and all("/" in p for p in files)
    root_label = next(iter(tops)) if strip_top else ""

    def rel_dir(p):
        d = posixpath.dirname(p)
        if strip_top:
            d = d.split("/", 1)[1] if "/" in d else ""
        return d

    manifests, locks = {}, {}
    for p, text in files.items():
        (manifests if posixpath.basename(p) == MANIFEST else locks)[rel_dir(p)] = text
    for d in locks:
        if d not in manifests:
            skipped.append({"path": posixpath.join(d, LOCKFILE) if d else LOCKFILE, "reason": "package-lock.json without a package.json in the same folder"})
    items = [{"path": d, "manifest": text, "lock": locks.get(d)} for d, text in manifests.items()]
    return items, skipped, root_label
