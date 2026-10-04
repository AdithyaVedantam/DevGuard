"""Download package.json / package-lock.json files from a PUBLIC GitHub repo. Nothing is cloned or run.

A repository can hold several npm projects (backend/ + frontend/, a monorepo, ...). DevGuard lists the
repository's file tree once (one GitHub API call), finds every package.json, and downloads each one
together with the package-lock.json that sits next to it.

Accepted URLs:
    https://github.com/owner/repo                      every npm project in the repo
    https://github.com/owner/repo/tree/main/backend    only the projects under backend/
"""
import os
import posixpath
import re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote, urlsplit

import discovery
from errors import AppError
from net import NetError, fetch, fetch_json

MAX_BYTES = 5 * 1024 * 1024
_URL = re.compile(r"^https?://(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:/(.*))?/?$")


def parse_github_url(url):
    """-> {"owner", "repo", "ref" (branch or None), "subpath" ("" = whole repo)}"""
    parts = urlsplit(str(url).strip())  # drops ?query and #fragment
    m = _URL.match(f"{parts.scheme}://{parts.netloc}{parts.path}")
    if not m:
        raise AppError(422, "invalid_github_url", "That does not look like a GitHub repository URL.",
                       "Use the form https://github.com/owner/repository")
    rest = [seg for seg in (m.group(3) or "").split("/") if seg]
    ref, subpath = None, ""
    if len(rest) >= 2 and rest[0] in ("tree", "blob"):
        ref = rest[1]
        try:
            subpath = discovery.clean_path("/".join(rest[2:]))
        except ValueError:
            raise AppError(422, "invalid_github_url", "That GitHub URL contains an invalid path.")
        if rest[0] == "blob" or posixpath.basename(subpath) in (discovery.MANIFEST, discovery.LOCKFILE):
            subpath = posixpath.dirname(subpath)  # a link to the file itself -> use its folder
    return {"owner": m.group(1), "repo": m.group(2), "ref": ref, "subpath": subpath}


def parse_url(url):
    """Kept for backward compatibility: (owner, repo)."""
    p = parse_github_url(url)
    return p["owner"], p["repo"]


def repo_url_for(owner, repo, branch, path):
    base = f"https://github.com/{owner}/{repo}"
    return f"{base}/tree/{branch}/{path}" if path else base


def _get_text(owner, repo, branch, filename):
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/{quote(branch, safe='/')}/{quote(filename, safe='/')}"
    try:
        return fetch(url, timeout=20, retries=2, max_bytes=MAX_BYTES).decode("utf-8")
    except NetError as e:
        if e.status == 404:
            return None
        raise AppError(502, "github_error", f"Could not download {filename} from GitHub ({e}).",
                       "Try again, or upload the files manually.")
    except UnicodeDecodeError:
        raise AppError(422, "not_text", f"{filename} is not a text file.")


def _list_tree(owner, repo, branch, headers):
    """-> (set of every file path in the branch, truncated?) or None when the listing is unavailable
    (rate limit / API down). Raises nothing for 404 - returns the string 'no-branch'."""
    try:
        data = fetch_json(f"https://api.github.com/repos/{owner}/{repo}/git/trees/{quote(branch, safe='')}?recursive=1",
                          headers=headers, timeout=20)
    except NetError as e:
        return "no-branch" if e.status == 404 else None
    tree = data.get("tree") if isinstance(data, dict) else None
    if not isinstance(tree, list):
        return None
    return {e["path"] for e in tree if isinstance(e, dict) and e.get("type") == "blob" and isinstance(e.get("path"), str)}, bool(data.get("truncated"))


def _in_scope(directory, subpath, exact):
    if exact:
        return directory == subpath
    return not subpath or directory == subpath or directory.startswith(subpath + "/")


def fetch_repo_projects(url, exact=False):
    """Find and download every npm project in a public repo.

    exact=True returns only the project whose folder IS the one in the URL (used by 'Run New Scan').
    Returns {"owner", "repo", "branch", "items": [...], "skipped": [...], "warnings": [...]}."""
    target = parse_github_url(url)
    owner, repo, subpath = target["owner"], target["repo"], target["subpath"]
    headers = {"Accept": "application/vnd.github+json"}
    if os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"

    branches = [target["ref"]] if target["ref"] else ["main", "master"]
    try:  # ask GitHub which branch is the default one
        meta = fetch_json(f"https://api.github.com/repos/{owner}/{repo}", headers=headers, timeout=15)
        if not target["ref"]:
            branches = [meta.get("default_branch") or "main"]
    except NetError as e:
        if e.status == 404:
            raise AppError(404, "repo_not_found", f"Repository {owner}/{repo} was not found (or it is private).",
                           "DevGuard supports public repositories only. You can upload the files instead.")
        # rate-limited or offline API: fall back to guessing main/master (raw downloads are not rate limited)

    warnings = []
    for branch in branches:
        listing = _list_tree(owner, repo, branch, headers)
        if listing == "no-branch":
            continue
        if listing is None:  # tree API unavailable: look at the target folder only (old behaviour)
            dirs, all_files = [subpath], None
            warnings.append("GitHub's file listing was unavailable, so only the requested folder was checked "
                            "(set GITHUB_TOKEN on the server to avoid the rate limit).")
        else:
            all_files, truncated = listing
            if truncated:
                warnings.append("This repository is very large, so GitHub returned a partial file list; some projects may be missing.")
            dirs = sorted({posixpath.dirname(p) for p in all_files
                           if posixpath.basename(p) == discovery.MANIFEST and not discovery.is_ignored(p)
                           and _in_scope(posixpath.dirname(p), subpath, exact)},
                          key=lambda d: (discovery.depth_of(d), d))
        if not dirs:
            continue

        def load(directory):
            lock_path = posixpath.join(directory, discovery.LOCKFILE)
            manifest_path = posixpath.join(directory, discovery.MANIFEST)
            manifest = _get_text(owner, repo, branch, manifest_path)
            if manifest is None:
                return None
            has_lock = True if all_files is None else lock_path in all_files
            lock = _get_text(owner, repo, branch, lock_path) if has_lock else None
            return {"path": directory, "manifest": manifest, "lock": lock}

        with ThreadPoolExecutor(max_workers=6) as pool:
            loaded = [i for i in pool.map(load, dirs[:discovery.MAX_PROJECTS * 3]) if i]
        if not loaded:
            continue
        items, skipped = discovery.apply_limits(loaded)
        for extra in dirs[discovery.MAX_PROJECTS * 3:]:
            skipped.append({"path": extra, "reason": f"limit of {discovery.MAX_PROJECTS} projects per import reached"})
        if len(items) == 1 and not items[0]["lock"]:
            where = f" in '{items[0]['path']}'" if items[0]["path"] else " in the repository root"
            raise AppError(422, "lockfile_missing", f"package-lock.json was not found{where}.",
                           "DevGuard needs a resolved npm lockfile for accurate results. "
                           "Run `npm install` in that folder, commit package-lock.json, or upload the files manually.")
        return {"owner": owner, "repo": repo, "branch": branch, "items": items, "skipped": skipped, "warnings": warnings}

    where = f"under '{subpath}' in" if subpath else "anywhere in"
    raise AppError(422, "package_json_missing", f"No package.json was found {where} {owner}/{repo}.",
                   "DevGuard analyzes npm projects. If your code is in a folder, paste the folder's GitHub URL "
                   "(https://github.com/owner/repo/tree/main/folder) or upload the files.")


def fetch_repo_files(url):
    """Backward-compatible single-project helper: the first project found."""
    found = fetch_repo_projects(url)
    first = found["items"][0]
    return {"owner": found["owner"], "repo": found["repo"], "branch": found["branch"],
            "package_json": first["manifest"], "package_lock": first["lock"]}
