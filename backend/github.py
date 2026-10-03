"""Download package.json and package-lock.json from a PUBLIC GitHub repo. Nothing is cloned or run."""
import os
import re

from errors import AppError
from net import NetError, fetch, fetch_json

MAX_BYTES = 5 * 1024 * 1024
_URL = re.compile(r"^https?://(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:/.*)?/?$")


def parse_url(url):
    m = _URL.match(url.strip())
    if not m:
        raise AppError(422, "invalid_github_url", "That does not look like a GitHub repository URL.",
                       "Use the form https://github.com/owner/repository")
    return m.group(1), m.group(2)


def _get_text(owner, repo, branch, filename):
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{filename}"
    try:
        return fetch(url, timeout=20, retries=2, max_bytes=MAX_BYTES).decode("utf-8")
    except NetError as e:
        if e.status == 404:
            return None
        raise AppError(502, "github_error", f"Could not download {filename} from GitHub ({e}).",
                       "Try again, or upload the files manually.")
    except UnicodeDecodeError:
        raise AppError(422, "not_text", f"{filename} is not a text file.")


def fetch_repo_files(url):
    owner, repo = parse_url(url)
    headers = {"Accept": "application/vnd.github+json"}
    if os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    branches = ["main", "master"]
    try:  # ask GitHub which branch is the default one
        meta = fetch_json(f"https://api.github.com/repos/{owner}/{repo}", headers=headers, timeout=15)
        branches = [meta.get("default_branch") or "main"]
    except NetError as e:
        if e.status == 404:
            raise AppError(404, "repo_not_found", f"Repository {owner}/{repo} was not found (or it is private).",
                           "DevGuard supports public repositories only. You can upload the files instead.")
        # rate-limited or offline API: fall back to guessing main/master (raw downloads are not rate limited)
    for branch in branches:
        pkg = _get_text(owner, repo, branch, "package.json")
        if pkg is None:
            continue
        lock = _get_text(owner, repo, branch, "package-lock.json")
        if lock is None:
            raise AppError(422, "lockfile_missing", "package-lock.json was not found in the repository root.",
                           "DevGuard needs a resolved npm lockfile for accurate results. "
                           "You can also upload package.json and package-lock.json manually.")
        return {"owner": owner, "repo": repo, "branch": branch, "package_json": pkg, "package_lock": lock}
    raise AppError(422, "package_json_missing", f"package.json was not found at the root of {owner}/{repo}.",
                   "DevGuard analyzes npm projects whose package.json is at the repository root.")
