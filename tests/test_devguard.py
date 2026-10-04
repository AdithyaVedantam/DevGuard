"""Run with:  python3 -m unittest discover -s tests -v      (no extra installs needed)"""
import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))
_tmp = tempfile.mkdtemp()
os.environ["DEVGUARD_DB"] = os.path.join(_tmp, "test.db")
os.environ.pop("LLM_API_KEY", None)

import analysis  # noqa: E402
import db  # noqa: E402
import github  # noqa: E402
import llm  # noqa: E402
import queries  # noqa: E402
import scanner  # noqa: E402
from errors import AppError  # noqa: E402
from npm_parser import LockfileError, ManifestError, analyze_inputs, parse_lockfile, parse_package_json  # noqa: E402
from osv import OSVClient  # noqa: E402

SAMPLES = ROOT / "backend" / "samples"


# ---------------------------------------------------------------- parser
PKG = json.dumps({"name": "app", "dependencies": {"a": "^1.0.0"}, "devDependencies": {"d": "^1.0.0"}})
LOCK = json.dumps({"lockfileVersion": 3, "packages": {
    "": {"name": "app"},
    "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "^1"}},
    "node_modules/b": {"version": "2.0.0", "dependencies": {"c": "^1"}},
    "node_modules/c": {"version": "3.0.0"},
    "node_modules/d": {"version": "1.5.0", "dev": True, "dependencies": {"c": "^1"}},
    "node_modules/d/node_modules/c": {"version": "9.9.9", "dev": True}}})


class ParserTests(unittest.TestCase):
    def deps(self):
        return {(d.name, d.version): d for d in analyze_inputs(PKG, LOCK).dependencies}

    def test_direct_vs_transitive(self):
        d = self.deps()
        self.assertEqual(d[("a", "1.0.0")].dependency_type, "direct")
        self.assertEqual(d[("b", "2.0.0")].dependency_type, "transitive")

    def test_depth_and_path(self):
        c = self.deps()[("c", "3.0.0")]
        self.assertEqual(c.depth, 3)
        self.assertEqual(c.dependency_path, ["app", "a", "b", "c"])

    def test_dev_vs_prod_and_nested_resolution(self):
        d = self.deps()
        self.assertEqual(d[("d", "1.5.0")].environment, "development")
        self.assertEqual(d[("c", "9.9.9")].environment, "development")
        self.assertEqual(d[("c", "3.0.0")].environment, "production")

    def test_malformed_input(self):
        for bad in ("{nope", "[]", '"x"'):
            with self.assertRaises(ManifestError):
                parse_package_json(bad)
        with self.assertRaises(LockfileError):
            parse_lockfile(parse_package_json(PKG), "{broken")
        with self.assertRaises(LockfileError):
            parse_lockfile(parse_package_json(PKG), json.dumps({"lockfileVersion": 1, "dependencies": {}}))

    def test_no_lockfile_is_best_effort(self):
        r = analyze_inputs(json.dumps({"name": "x", "dependencies": {"lodash": "^4.17.15", "w": "git+https://x"}}), None)
        self.assertEqual(r.resolution_mode, "manifest-ranges")
        self.assertEqual([d.name for d in r.dependencies], ["lodash"])
        self.assertTrue(r.warnings)

    def test_missing_fields_safe(self):
        self.assertEqual(parse_package_json("{}").name, "unnamed-project")


# ---------------------------------------------------------------- analysis
def vec(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"):
    return f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"


class AnalysisTests(unittest.TestCase):
    def test_cvss_known_values(self):
        self.assertEqual(analysis.cvss3_score(vec()), 9.8)
        self.assertEqual(analysis.cvss3_score(vec(s="C")), 10.0)
        self.assertEqual(analysis.cvss3_score(vec(i="N", a="N")), 7.5)

    def test_severity_bands_and_unknown(self):
        sev = lambda v: analysis.normalize_severity({"severity": [{"type": "CVSS_V3", "score": v}]})[0]  # noqa: E731
        self.assertEqual(sev(vec()), "critical")
        self.assertEqual(sev(vec(i="N", a="N")), "high")
        self.assertEqual(sev(vec(ui="R", c="L", i="L", a="N")), "medium")
        self.assertEqual(sev(vec(ac="H", pr="H", ui="R", c="L", i="N", a="N")), "low")
        self.assertEqual(analysis.normalize_severity({})[0], "unknown")
        self.assertEqual(analysis.normalize_severity({"database_specific": {"severity": "MODERATE"}})[0], "medium")

    def test_risk(self):
        self.assertEqual(analysis.risk_index(0), 0)
        f = analysis.finding_score
        self.assertGreater(f("critical", "production", "direct"), f("low", "production", "direct"))
        self.assertGreater(f("high", "production", "direct"), f("high", "development", "direct"))
        self.assertEqual(analysis.risk_index(10), 22)
        self.assertLessEqual(analysis.risk_index(10 ** 6), 100)

    def test_fixed_version(self):
        aff = [{"package": {"name": "x", "ecosystem": "npm"}, "ranges": [
            {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.6"}]},
            {"type": "SEMVER", "events": [{"introduced": "1.3.0"}, {"fixed": "1.3.4"}]}]}]
        self.assertEqual(analysis.fixed_version_for(aff, "x", "1.2.5"), "1.2.6")
        self.assertEqual(analysis.fixed_version_for(aff, "x", "1.3.1"), "1.3.4")
        self.assertIsNone(analysis.fixed_version_for(aff, "y", "1.0.0"))

    def test_compare(self):
        def snap(i, risk, finds, deps):
            return {"scan": {"id": i, "risk_index": risk}, "deps": [{"name": n, "version": v} for n, v in deps],
                    "findings": [{"package": p, "version": v, "osv_id": o, "severity": "high"} for p, v, o in finds]}
        old = snap(1, 74, [("lodash", "4.17.20", "G1"), ("axios", "1.6.2", "G2")], [("lodash", "4.17.20"), ("axios", "1.6.2")])
        new = snap(2, 68, [("axios", "1.6.2", "G2"), ("x", "2.0.0", "G9")], [("lodash", "4.17.21"), ("axios", "1.6.2"), ("x", "2.0.0")])
        c = analysis.compare_snapshots(old, new)
        self.assertEqual([f["osv_id"] for f in c["fixed"]], ["G1"])
        self.assertEqual([f["osv_id"] for f in c["introduced"]], ["G9"])
        self.assertEqual(c["metrics"]["risk_index"]["delta"], -6)
        self.assertEqual(c["remediation_rate"], 0.5)
        self.assertEqual(c["package_changes"]["updated"], [{"name": "lodash", "from": "4.17.20", "to": "4.17.21"}])


# ---------------------------------------------------------------- OSV client against a REAL local HTTP server
class MockOSV(BaseHTTPRequestHandler):
    mode = "ok"
    posts = []

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        raw = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        MockOSV.posts.append((self.path, body))
        if MockOSV.mode == "down":
            return self._send(503, {})
        if MockOSV.mode == "malformed":
            return self._send(200, {"results": []})
        if self.path == "/v1/querybatch":
            res = []
            for q in body["queries"]:
                if q["package"]["name"] == "paged":
                    res.append({"vulns": [{"id": "P-1"}], "next_page_token": "t"})
                elif q["package"]["name"] == "lodash":
                    res.append({"vulns": [{"id": "A-1"}, {"id": "A-2"}]})
                else:
                    res.append({})
            return self._send(200, {"results": res})
        if self.path == "/v1/query":
            return self._send(200, {"vulns": [{"id": "P-2"}]})
        self._send(404, {})

    def do_GET(self):
        if self.path.endswith("BAD"):
            return self._send(404, {})
        self._send(200, {"id": self.path.rsplit("/", 1)[1], "summary": "s"})


class OSVTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), MockOSV)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.client = OSVClient(base=f"http://127.0.0.1:{cls.server.server_port}", retries=1)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        MockOSV.mode, MockOSV.posts = "ok", []

    def test_batch_ids_and_clean(self):
        self.assertEqual(self.client.query_batch([("lodash", "4.17.15"), ("clean", "1.0.0")]),
                         [(["A-1", "A-2"], None), ([], None)])

    def test_outage_is_error_not_clean(self):
        MockOSV.mode = "down"
        res = self.client.query_batch([("a", "1"), ("b", "1")])
        self.assertTrue(all(ids is None and err for ids, err in res))

    def test_malformed_response_is_error(self):
        MockOSV.mode = "malformed"
        res = self.client.query_batch([("a", "1")])
        self.assertIsNone(res[0][0])
        self.assertIn("malformed", res[0][1])

    def test_pagination(self):
        self.assertEqual(self.client.query_batch([("paged", "1")]), [(["P-1", "P-2"], None)])

    def test_chunking(self):
        small = OSVClient(base=self.client.base, batch_size=2, retries=1)
        small.query_batch([("p", str(i)) for i in range(5)])
        self.assertEqual([len(b["queries"]) for p, b in MockOSV.posts if p == "/v1/querybatch"], [2, 2, 1])

    def test_details_with_errors_separated(self):
        ok, bad = self.client.get_vulnerabilities(["OK1", "BAD"])
        self.assertIn("OK1", ok)
        self.assertIn("BAD", bad)


# ---------------------------------------------------------------- full pipeline with a fake OSV
H = vec(i="N", a="N", ac="L")  # 7.5 high placeholder; overwritten below
CRIT = vec(a="N")  # 9.1 critical


def rec(osv_id, pkg, fixed, severity=None, label=None):
    r = {"id": osv_id, "summary": f"{osv_id} summary", "details": "details", "aliases": [],
         "references": [{"type": "WEB", "url": "https://example.test/a"}],
         "affected": [{"package": {"name": pkg, "ecosystem": "npm"},
                       "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}]}
    if severity:
        r["severity"] = [{"type": "CVSS_V3", "score": severity}]
    if label:
        r["database_specific"] = {"severity": label}
    return r


RECORDS = {"T-1": rec("T-1", "lodash", "4.17.21", vec(i="N", a="N")), "T-2": rec("T-2", "minimist", "1.2.6", CRIT),
           "T-3": rec("T-3", "minimatch", "3.0.5", label="MODERATE")}
VULN = {("lodash", "4.17.15"): ["T-1"], ("minimist", "1.2.0"): ["T-2"], ("minimist", "0.0.8"): ["T-2"],
        ("minimist", "1.2.5"): ["T-2"], ("minimatch", "3.0.4"): ["T-3"]}


class FakeOSV:
    def __init__(self, fail_for=()):
        self.fail_for, self.detail_requests = set(fail_for), []

    def query_batch(self, packages):
        return [(None, "simulated outage") if n in self.fail_for else (list(VULN.get((n, v), [])), None)
                for n, v in packages]

    def get_vulnerabilities(self, ids):
        self.detail_requests += list(ids)
        return {i: RECORDS[i] for i in ids}, {}


def make_project(variant, name="devguard-demo"):
    pkg = (SAMPLES / variant / "package.json").read_text()
    lock = (SAMPLES / variant / "package-lock.json").read_text()
    row = db.query("SELECT id FROM projects WHERE name=?", (name,), one=True)
    if row:
        db.execute("UPDATE projects SET manifest_text=?, lock_text=? WHERE id=?", (pkg, lock, row["id"]))
        return row["id"]
    return db.execute("INSERT INTO projects (name, source_type, manifest_text, lock_text, created_at) VALUES (?,?,?,?,?)",
                      (name, "demo", pkg, lock, scanner.now()))


class PipelineTests(unittest.TestCase):
    def setUp(self):
        if os.path.exists(db.db_path()):
            os.remove(db.db_path())
        db.init_db()
        scanner._CACHE.clear()

    def test_scan_counts_and_storage(self):
        osv = FakeOSV()
        pid = make_project("before")
        sid = scanner.run_scan(pid, osv)
        s = queries.get_scan(sid)
        self.assertEqual(s["status"], "completed")
        self.assertEqual((s["total_dependencies"], s["direct_count"]), (8, 4))
        self.assertEqual(s["total_findings"], 4)
        self.assertEqual((s["critical_count"], s["high_count"], s["medium_count"]), (2, 1, 1))
        self.assertTrue(0 < s["risk_index"] <= 100)
        self.assertEqual(sorted(osv.detail_requests), ["T-1", "T-2", "T-3"])  # each advisory fetched once
        fs = queries.findings(sid)
        self.assertEqual(len(fs), 4)
        crit = [f for f in fs if f["severity"] == "critical"]
        self.assertTrue(all(f["fixed_version"] == "1.2.6" for f in crit))
        detail = queries.finding_detail(fs[0]["id"])
        self.assertEqual(detail["path"][0], "devguard-demo")
        self.assertTrue(detail["refs"] and detail["affected_ranges"])
        deps = queries.dependencies(sid)
        self.assertEqual(len([d for d in deps if d["vuln_count"]]), 4)

    def test_second_scan_comparison_and_summary(self):
        pid = make_project("before")
        s1 = scanner.run_scan(pid, FakeOSV())
        make_project("after")
        s2 = scanner.run_scan(pid, FakeOSV())
        c = queries.compare(s2, s1)
        self.assertEqual((c["summary"]["resolved"], c["summary"]["introduced"]), (2, 0))
        self.assertLess(c["metrics"]["risk_index"]["delta"], 0)
        sm = queries.summary(pid)
        self.assertEqual(len(sm["trend"]), 2)
        self.assertEqual(sm["changes"]["summary"]["resolved"], 2)
        labels = {r["label"]: (r["total"], r["vulnerable"]) for r in sm["exposure"]}
        self.assertEqual(labels["direct"][0], 4)
        self.assertTrue(sm["top_packages"])

    def test_outage_is_partial_then_failed(self):
        pid = make_project("before")
        s = queries.get_scan(scanner.run_scan(pid, FakeOSV(fail_for={"lodash"})))
        self.assertEqual(s["status"], "partial")
        self.assertTrue(s["errors"])
        self.assertEqual(s["total_findings"], 3)
        every = {"lodash", "minimist", "mkdirp", "minimatch", "brace-expansion", "balanced-match", "concat-map"}
        self.assertEqual(queries.get_scan(scanner.run_scan(pid, FakeOSV(fail_for=every)))["status"], "failed")

    def test_bad_files_raise_clean_error(self):
        pid = db.execute("INSERT INTO projects (name, source_type, manifest_text, created_at) VALUES ('x','upload','{nope',?)", (scanner.now(),))
        with self.assertRaises(AppError) as cm:
            scanner.run_scan(pid, FakeOSV())
        self.assertEqual(cm.exception.code, "invalid_project_files")

    def test_delete_cascades(self):
        pid = make_project("before")
        scanner.run_scan(pid, FakeOSV())
        db.execute("DELETE FROM projects WHERE id=?", (pid,))
        for t in ("scans", "dependencies", "findings"):
            self.assertEqual(db.query(f"SELECT COUNT(*) AS n FROM {t}", one=True)["n"], 0)


# ---------------------------------------------------------------- AI + GitHub
class AITests(unittest.TestCase):
    ENV = ("LLM_API_KEY", "LLM_MODEL", "LLM_FALLBACK_MODELS", "ALT_API_KEY", "ALT_BASE_URL", "ALT_MODELS")

    def setUp(self):
        if os.path.exists(db.db_path()):
            os.remove(db.db_path())
        db.init_db()
        scanner._CACHE.clear()
        self.orig = llm.fetch_json
        for k in self.ENV:
            os.environ.pop(k, None)
        self.sid = scanner.run_scan(make_project("before"), FakeOSV())

    def tearDown(self):
        llm.fetch_json = self.orig
        for k in self.ENV:
            os.environ.pop(k, None)

    def test_without_key_uses_rules_and_hides_config_hints(self):
        r = llm.explain(self.sid)
        self.assertEqual(r["source"], "rules")
        self.assertIn("4 known vulnerabilities", r["text"])
        self.assertNotIn("LLM_API_KEY", json.dumps(r))
        with self.assertRaises(AppError) as cm:
            llm.ask(self.sid, "what first?")
        self.assertEqual(cm.exception.code, "ai_disabled")
        self.assertNotIn("LLM", cm.exception.message + (cm.exception.hint or ""))

    def test_context_contains_only_calculated_facts(self):
        ctx = llm.build_context(self.sid)
        self.assertEqual(ctx["vulnerabilities"], 4)
        self.assertIn(ctx["top_findings"][0]["advisory"], ("T-1", "T-2", "T-3"))

    def test_gemini_model_fallback_order(self):
        os.environ.update(LLM_API_KEY="k", LLM_MODEL="m1", LLM_FALLBACK_MODELS="m2,m3")
        tried = []

        def fake(url, **kw):
            model = url.split("/models/")[1].split(":")[0]
            tried.append(model)
            if model != "m3":
                raise llm.NetError("HTTP 404", 404)
            return {"candidates": [{"content": {"parts": [{"text": "ok from m3"}]}}]}
        llm.fetch_json = fake
        self.assertEqual(llm.explain(self.sid), {"text": "ok from m3", "source": "ai"})
        self.assertEqual(tried, ["m1", "m2", "m3"])

    def test_alt_provider_used_when_gemini_fails(self):
        os.environ.update(LLM_API_KEY="k", LLM_MODEL="g1", LLM_FALLBACK_MODELS="g2", ALT_API_KEY="a",
                          ALT_BASE_URL="https://alt.test/v1", ALT_MODELS="alt-1")

        def fake(url, **kw):
            if "generativelanguage" in url:
                raise llm.NetError("HTTP 429", 429)
            self.assertTrue(url.endswith("/chat/completions"))
            return {"choices": [{"message": {"content": "from alt"}}]}
        llm.fetch_json = fake
        self.assertEqual(llm.ask(self.sid, "what first?")["text"], "from alt")

    def test_all_models_fail_is_quiet_and_generic(self):
        os.environ.update(LLM_API_KEY="k")

        def boom(*a, **k):
            raise llm.NetError("HTTP 403 secret-detail", 403)
        llm.fetch_json = boom
        self.assertEqual(llm.explain(self.sid)["source"], "rules")
        with self.assertRaises(AppError) as cm:
            llm.ask(self.sid, "what first?")
        self.assertEqual(cm.exception.code, "ai_unavailable")
        self.assertNotIn("secret-detail", cm.exception.message)


class SafetyTests(unittest.TestCase):
    def test_rate_limit_only_in_public_mode(self):
        import ratelimit
        os.environ.pop("DEVGUARD_PUBLIC", None)
        for _ in range(5):
            ratelimit.check("1.1.1.1", "t", 1)  # unlimited locally
        os.environ["DEVGUARD_PUBLIC"] = "1"
        try:
            ratelimit.check("2.2.2.2", "t", 2)
            ratelimit.check("2.2.2.2", "t", 2)
            with self.assertRaises(AppError) as cm:
                ratelimit.check("2.2.2.2", "t", 2)
            self.assertEqual(cm.exception.status, 429)
        finally:
            os.environ.pop("DEVGUARD_PUBLIC", None)

    def test_scan_failure_hides_internal_details(self):
        if os.path.exists(db.db_path()):
            os.remove(db.db_path())
        db.init_db()
        scanner._CACHE.clear()
        pid = make_project("before")
        original = scanner.analysis.risk_index
        scanner.analysis.risk_index = lambda x: 1 / 0
        try:
            with self.assertRaises(AppError) as cm:
                scanner.run_scan(pid, FakeOSV())
        finally:
            scanner.analysis.risk_index = original
        self.assertNotIn("division", cm.exception.message + str(cm.exception.hint))
        failed = db.query("SELECT errors FROM scans WHERE status='failed'", one=True)
        self.assertNotIn("ZeroDivision", failed["errors"])


class ExportTests(unittest.TestCase):
    def test_csv_is_safe_and_complete(self):
        if os.path.exists(db.db_path()):
            os.remove(db.db_path())
        db.init_db()
        scanner._CACHE.clear()
        sid = scanner.run_scan(make_project("before"), FakeOSV())
        text = queries.findings_csv(sid)
        self.assertEqual(len(text.strip().splitlines()), 5)  # header + 4 findings
        self.assertIn("T-2", text)
        self.assertEqual(queries.findings_csv.__name__, "findings_csv")


class GitHubTests(unittest.TestCase):
    def test_url_parsing(self):
        self.assertEqual(github.parse_url("https://github.com/expressjs/express"), ("expressjs", "express"))
        self.assertEqual(github.parse_url("https://github.com/a/b.git"), ("a", "b"))
        self.assertEqual(github.parse_url("https://github.com/a/b/tree/main/x"), ("a", "b"))
        for bad in ("https://example.com/a/b", "not a url", "https://github.com/onlyowner"):
            with self.assertRaises(AppError):
                github.parse_url(bad)


if __name__ == "__main__":
    unittest.main()
