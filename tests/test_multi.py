"""Tests for multi-project import (backend/ + frontend/, monorepos, folder upload).
Run with:  python3 -m unittest discover -s tests -v      (no extra installs; the endpoint test is skipped
if fastapi's TestClient dependency `httpx` is missing)."""
import io
import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

import test_devguard as base  # sets DEVGUARD_DB, sys.path and provides FakeOSV

import db
import discovery
import github
import main
import queries
import scanner
from errors import AppError

SAMPLES = base.SAMPLES
BEFORE = ((SAMPLES / "before" / "package.json").read_text(), (SAMPLES / "before" / "package-lock.json").read_text())
AFTER = ((SAMPLES / "after" / "package.json").read_text(), (SAMPLES / "after" / "package-lock.json").read_text())


def reset_db():
    if os.path.exists(db.db_path()):
        os.remove(db.db_path())
    db.init_db()
    scanner._CACHE.clear()


# ------------------------------------------------------------------ discovery
class DiscoveryTests(unittest.TestCase):
    def test_clean_path(self):
        self.assertEqual(discovery.clean_path("./a\\b//c.json"), "a/b/c.json")
        with self.assertRaises(ValueError):
            discovery.clean_path("a/../../etc/passwd")

    def test_group_folder_upload_pairs_by_folder(self):
        entries = [
            ("proj/backend/package.json", "B"), ("proj/backend/package-lock.json", "BL"),
            ("proj/frontend/package.json", "F"), ("proj/frontend/package-lock.json", "FL"),
            ("proj/frontend/node_modules/x/package.json", "IGNORED"),
            ("proj/frontend/src/index.js", "IGNORED"), ("proj/README.md", "IGNORED"),
        ]
        items, skipped, root = discovery.group_uploaded(entries)
        self.assertEqual(root, "proj")
        self.assertEqual({i["path"]: (i["manifest"], i["lock"]) for i in items},
                         {"backend": ("B", "BL"), "frontend": ("F", "FL")})
        self.assertEqual(skipped, [])

    def test_group_root_project_and_loose_lock(self):
        items, skipped, root = discovery.group_uploaded(
            [("app/package.json", "R"), ("app/package-lock.json", "RL"), ("app/old/package-lock.json", "X")])
        self.assertEqual([(i["path"], i["lock"]) for i in items], [("", "RL")])
        self.assertEqual(len(skipped), 1)
        self.assertIn("without a package.json", skipped[0]["reason"])

    def test_group_two_loose_files_without_folder(self):
        items, _, root = discovery.group_uploaded([("package.json", "P"), ("package-lock.json", "L")])
        self.assertEqual((root, [(i["path"], i["lock"]) for i in items]), ("", [("", "L")]))

    def test_unsafe_path_is_skipped_not_used(self):
        items, skipped, _ = discovery.group_uploaded([("../../evil/package.json", "X"), ("ok/package.json", "O")])
        self.assertEqual([i["manifest"] for i in items], ["O"])
        self.assertEqual(len(skipped), 1)

    def test_workspace_members_are_covered_by_the_root_lockfile(self):
        root = {"path": "", "manifest": json.dumps({"name": "mono", "workspaces": ["packages/*"]}), "lock": "L"}
        member = {"path": "packages/a", "manifest": "{}", "lock": None}
        own_lock = {"path": "packages/b", "manifest": "{}", "lock": "BL"}
        unrelated = {"path": "tools", "manifest": "{}", "lock": None}
        kept, skipped = discovery.apply_limits([member, own_lock, unrelated, root])
        self.assertEqual([i["path"] for i in kept], ["", "tools", "packages/b"])
        self.assertEqual([s["path"] for s in skipped], ["packages/a"])

    def test_project_cap(self):
        items = [{"path": f"p{i:02d}", "manifest": "{}", "lock": "L"} for i in range(discovery.MAX_PROJECTS + 3)]
        kept, skipped = discovery.apply_limits(items)
        self.assertEqual((len(kept), len(skipped)), (discovery.MAX_PROJECTS, 3))


# ------------------------------------------------------------------ github
TREE = {"truncated": False, "tree": [
    {"path": p, "type": "blob"} for p in (
        "README.md", "backend/package.json", "backend/package-lock.json", "backend/src/app.js",
        "frontend/package.json", "frontend/package-lock.json",
        "frontend/node_modules/left-pad/package.json", "docs/package.json")] + [{"path": "backend", "type": "tree"}]}
FILES = {"backend/package.json": "BP", "backend/package-lock.json": "BL", "frontend/package.json": "FP",
         "frontend/package-lock.json": "FL", "docs/package.json": "DP"}


def fake_json(tree=TREE):
    def fetch_json(url, **kw):
        if "/git/trees/" in url:
            if tree is None:
                raise github.NetError("HTTP 403", 403)
            return tree
        return {"default_branch": "main"}
    return fetch_json


def fake_text(owner, repo, branch, filename):
    return FILES.get(filename)


class GitHubDiscoveryTests(unittest.TestCase):
    def run_fetch(self, url, tree=TREE, **kw):
        with mock.patch.object(github, "fetch_json", fake_json(tree)), mock.patch.object(github, "_get_text", fake_text):
            return github.fetch_repo_projects(url, **kw)

    def test_url_parsing(self):
        p = github.parse_github_url("https://github.com/a/b/tree/dev/packages/api?tab=x#y")
        self.assertEqual((p["owner"], p["repo"], p["ref"], p["subpath"]), ("a", "b", "dev", "packages/api"))
        p = github.parse_github_url("https://github.com/a/b/blob/main/backend/package.json")
        self.assertEqual((p["ref"], p["subpath"]), ("main", "backend"))
        p = github.parse_github_url("https://github.com/a/b.git")
        self.assertEqual((p["repo"], p["ref"], p["subpath"]), ("b", None, ""))
        with self.assertRaises(AppError):
            github.parse_github_url("https://github.com/a/b/tree/main/../../x")

    def test_finds_every_project_and_ignores_node_modules(self):
        r = self.run_fetch("https://github.com/o/r")
        got = {i["path"]: (i["manifest"], i["lock"]) for i in r["items"]}
        self.assertEqual(got, {"backend": ("BP", "BL"), "frontend": ("FP", "FL"), "docs": ("DP", None)})
        self.assertEqual([i["path"] for i in r["items"]], ["backend", "docs", "frontend"])  # shallow first, then A-Z

    def test_folder_url_limits_scope(self):
        r = self.run_fetch("https://github.com/o/r/tree/main/backend")
        self.assertEqual([i["path"] for i in r["items"]], ["backend"])

    def test_exact_mode_for_rescans(self):
        r = self.run_fetch("https://github.com/o/r/tree/main/frontend", exact=True)
        self.assertEqual([i["path"] for i in r["items"]], ["frontend"])
        with self.assertRaises(AppError) as cm:  # root has no package.json in this repo
            self.run_fetch("https://github.com/o/r", exact=True)
        self.assertEqual(cm.exception.code, "package_json_missing")

    def test_tree_unavailable_falls_back_to_root_only(self):
        files = dict(FILES, **{"package.json": "RP", "package-lock.json": "RL"})
        with mock.patch.object(github, "fetch_json", fake_json(None)), \
                mock.patch.object(github, "_get_text", lambda o, r, b, f: files.get(f)):
            r = github.fetch_repo_projects("https://github.com/o/r")
        self.assertEqual([i["path"] for i in r["items"]], [""])
        self.assertTrue(r["warnings"])

    def test_single_project_without_lockfile_keeps_the_clear_error(self):
        tree = {"truncated": False, "tree": [{"path": "api/package.json", "type": "blob"}]}
        with mock.patch.dict(FILES, {"api/package.json": "AP"}), self.assertRaises(AppError) as cm:
            self.run_fetch("https://github.com/o/r", tree=tree)
        self.assertEqual(cm.exception.code, "lockfile_missing")
        self.assertIn("api", cm.exception.message)

    def test_no_package_json_anywhere(self):
        tree = {"truncated": False, "tree": [{"path": "main.py", "type": "blob"}]}
        with self.assertRaises(AppError) as cm:
            self.run_fetch("https://github.com/o/r", tree=tree)
        self.assertEqual(cm.exception.code, "package_json_missing")


# ------------------------------------------------------------------ import + scan
class ImportManyTests(unittest.TestCase):
    def setUp(self):
        reset_db()
        patcher = mock.patch.object(scanner, "OSVClient", lambda: base.FakeOSV())
        patcher.start()
        self.addCleanup(patcher.stop)

    def items(self):
        return [{"path": "backend", "manifest": BEFORE[0], "lock": BEFORE[1]},
                {"path": "frontend", "manifest": AFTER[0], "lock": AFTER[1]}]

    def test_every_folder_becomes_its_own_project_with_its_own_scan(self):
        r = main.import_many(self.items(), "github", lambda i: f"o/r/{i['path']}",
                             lambda i: f"https://github.com/o/r/tree/main/{i['path']}", "main")
        self.assertEqual([p["name"] for p in r["projects"]], ["o/r/backend", "o/r/frontend"])
        self.assertEqual(len({p["project_id"] for p in r["projects"]}), 2)
        self.assertEqual(r["project_id"], r["projects"][0]["project_id"])  # legacy field still present
        backend = queries.get_scan(r["projects"][0]["scan_id"])
        self.assertEqual(backend["total_findings"], r["projects"][0]["total_findings"])
        self.assertGreater(r["projects"][0]["total_findings"], r["projects"][1]["total_findings"])
        proj = queries.get_project(r["projects"][1]["project_id"])
        self.assertEqual(proj["repo_url"] if "repo_url" in proj else None, "https://github.com/o/r/tree/main/frontend")

    def test_one_broken_project_does_not_stop_the_others(self):
        items = self.items() + [{"path": "broken", "manifest": "{nope", "lock": None}]
        r = main.import_many(items, "upload", lambda i: i["path"])
        self.assertEqual([("project_id" in p) for p in r["projects"]], [True, True, False])
        self.assertEqual(r["projects"][2]["error"]["code"], "invalid_project_files")

    def test_single_project_failure_raises_the_precise_error(self):
        with self.assertRaises(AppError) as cm:
            main.import_many([{"path": "", "manifest": "{nope", "lock": None}], "upload", lambda i: None)
        self.assertEqual(cm.exception.code, "invalid_project_files")

    def test_all_failed_raises(self):
        with self.assertRaises(AppError) as cm:
            main.import_many([{"path": "a", "manifest": "{", "lock": None}, {"path": "b", "manifest": "{", "lock": None}],
                             "upload", lambda i: i["path"])
        self.assertEqual(cm.exception.code, "nothing_scanned")

    def test_reimport_updates_the_same_project_so_history_grows(self):
        for _ in range(2):
            r = main.import_many(self.items(), "upload", lambda i: f"mine/{i['path']}")
        self.assertEqual(len(queries.list_projects()), 2)
        self.assertEqual(queries.list_projects()[0]["scan_count"], 2)

    def test_rescan_of_a_github_subfolder_refetches_only_that_folder(self):
        r = main.import_many(self.items()[:1], "github", lambda i: "o/r/backend",
                             lambda i: "https://github.com/o/r/tree/main/backend", "main")
        pid = r["project_id"]
        seen = {}

        def fake_fetch(url, exact=False):
            seen.update(url=url, exact=exact)
            return {"branch": "main", "items": [{"path": "backend", "manifest": AFTER[0], "lock": AFTER[1]}]}
        with mock.patch.object(github, "fetch_repo_projects", fake_fetch):
            out = main.rescan(pid)
        self.assertEqual(seen, {"url": "https://github.com/o/r/tree/main/backend", "exact": True})
        self.assertNotEqual(out["scan_id"], r["scan_id"])
        self.assertEqual(db.query("SELECT manifest_text FROM projects WHERE id=?", (pid,), one=True)["manifest_text"], AFTER[0])


try:
    from fastapi.testclient import TestClient
except Exception:  # httpx not installed
    TestClient = None


@unittest.skipIf(TestClient is None, "needs `pip install httpx` for FastAPI's TestClient")
class UploadEndpointTests(unittest.TestCase):
    def setUp(self):
        reset_db()
        patcher = mock.patch.object(scanner, "OSVClient", lambda: base.FakeOSV())
        patcher.start()
        self.addCleanup(patcher.stop)
        self.client = TestClient(main.app)

    def post(self, files):
        multipart = [("files", (Path(p).name, io.BytesIO(t.encode()), "application/json")) for p, t in files]
        return self.client.post("/api/import/files", files=multipart, data={"paths": [p for p, _ in files]})

    def test_folder_with_backend_and_frontend(self):
        res = self.post([("shop/backend/package.json", BEFORE[0]), ("shop/backend/package-lock.json", BEFORE[1]),
                         ("shop/frontend/package.json", AFTER[0]), ("shop/frontend/package-lock.json", AFTER[1]),
                         ("shop/frontend/node_modules/x/package.json", "{}")])
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual([p["name"] for p in res.json()["projects"]], ["shop/backend", "shop/frontend"])

    def test_single_root_project_keeps_its_package_json_name(self):
        res = self.post([("only/package.json", BEFORE[0]), ("only/package-lock.json", BEFORE[1])])
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(res.json()["projects"][0]["name"], json.loads(BEFORE[0]).get("name", "unnamed-project"))

    def test_no_package_json_is_a_clean_422(self):
        res = self.post([("x/index.js", "console.log(1)")])
        self.assertEqual(res.status_code, 422)
        self.assertEqual(res.json()["error"]["code"], "package_json_missing")

    def test_mismatched_paths_rejected(self):
        res = self.client.post("/api/import/files", files=[("files", ("package.json", b"{}", "application/json"))],
                               data={"paths": ["a/package.json", "b/package.json"]})
        self.assertEqual(res.status_code, 422)


if __name__ == "__main__":
    unittest.main()
