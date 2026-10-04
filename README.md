# DevGuard — Dependency Security Analytics

DevGuard reads a Node.js project's `package.json` + `package-lock.json`, checks every installed package version against the **OSV vulnerability database**, and shows what is vulnerable, how risky the project is, and **whether it is getting safer over time**. An optional **AI assistant (Gemini)** explains scan results in plain English.

Uploaded code is **never executed** — files are only read as JSON data.

**Stack:** Python · FastAPI · SQLite (plain SQL) · plain HTML/JavaScript + Tailwind + Chart.js · OSV API · GitHub · Google Gemini

---

## 1. Run it (5 minutes)

Needs **Python 3.9+** (`python3 --version`). Open the `devguard` folder in VS Code, open the terminal (**Terminal → New Terminal**), then:

**Mac / Linux**
```bash
./start.sh
```
**Windows (PowerShell)**
```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
cd backend
uvicorn main:app --reload --port 8000
```
Open **http://localhost:8000**. That's it — the database file (`devguard.db`) creates itself. Frontend and backend are one server, nothing else to start.

## 2. Try it
1. Click **1 · Load demo (older versions)** → real packages (lodash, minimist, …) are scanned against live OSV.
2. Explore the tabs: Overview, Vulnerabilities (click a row for details + dependency path), Dependencies, History.
3. Go back and click **2 · Re-scan after upgrades** → open **History → Compare** to see what was fixed, what remains, and the Risk Index change.
4. Try a real repo, e.g. paste any public GitHub repo that has a `package-lock.json` at its root.

## 3. Turn on the AI (optional)
```bash
cp .env.example .env        # then open .env in VS Code and paste your Gemini key after LLM_API_KEY=
```
Restart the server. The **AI Assistant** tab then answers "what should I fix first?" using only your scan's data. Without a key the app still works and shows an automated summary instead (users are never told about keys or config).

**Resilience:** models are tried in order — your `LLM_MODEL`, then `LLM_FALLBACK_MODELS`, then an optional second provider (`ALT_*`, any OpenAI-compatible API such as xAI Grok, Groq or OpenRouter), then DevGuard's own rule-based summary. A retired model, a rate limit or an outage never breaks the page.

**AI design rule (good interview point):** the AI never decides what is vulnerable — OSV data and our own code do. The AI only *explains* numbers that were already calculated, it is told to use only the data it's given, and treats advisory text as data, not instructions.

**Security notes:** error details, model names and keys go to the server log only. With `DEVGUARD_PUBLIC=1` (set on the hosted site) the API docs are hidden, delete is disabled, and scans/AI calls are rate-limited per IP.

## 4. How it works
```
GitHub URL / upload  ->  package.json + lockfile  ->  parse into a dependency list
   -> OSV batch query (one request for many packages)  ->  fetch each advisory once
   -> severity (CVSS) + fixed version + risk  ->  save in SQLite  ->  SQL queries  ->  dashboard
```

| File | What it does |
|---|---|
| `backend/main.py` | The web server and all URLs (`/api/...`) |
| `backend/npm_parser.py` | Reads the lockfile: direct vs transitive, prod vs dev, depth, dependency path |
| `backend/osv.py` | Talks to OSV (batch query + advisory details). Failed lookup ≠ "no vulnerabilities" |
| `backend/analysis.py` | CVSS score calculator, severity, fixed-version finder, **Risk Index**, scan comparison |
| `backend/scanner.py` | The scan pipeline, step by step |
| `backend/queries.py` | The SQL (`GROUP BY` / `JOIN`) behind every number on the dashboard |
| `backend/db.py` | SQLite tables, written as plain SQL |
| `backend/llm.py` | All AI code (Gemini + fallback models + optional second provider) |
| `backend/ratelimit.py` | Per-IP limits on the public site |
| `backend/github.py` | Downloads the two files from a public repo |
| `frontend/app.js` | The whole UI |

**Risk Index** (a DevGuard heuristic, *not* an industry standard) — in `analysis.py`:
`finding score = severity weight (critical 10, high 6, medium 3, low 1, unknown 2) × environment (prod 1.0, dev 0.4) × exposure (direct 1.0, transitive 0.8)`; the sum is squashed to 0–100 with `100 × (1 − e^(−sum/40))`.

**Scan status:** `completed`, `partial` (some lookups failed) or `failed`. A partial scan is clearly flagged so "0 vulnerabilities" is never mistaken for "safe".

## 5. Tests
```bash
python3 -m unittest discover -s tests -v
```
31 tests, no extra installs, no internet needed (OSV is mocked with a local test server).

## 6. Troubleshooting
| Problem | Fix |
|---|---|
| `CERTIFICATE_VERIFY_FAILED` on Mac | `pip install --upgrade certifi` (inside the venv) |
| Port 8000 already in use | change `--port 8000` to `--port 8001` and open that port |
| "Cannot reach the DevGuard server" | the server isn't running — start it again |
| GitHub import: lockfile missing | the repo has no `package-lock.json`; upload the two files instead |
| Scan shows **partial** | OSV was unreachable for some packages; press Run New Scan |
| AI says "not configured" | add `LLM_API_KEY` to `.env`, restart the server |

## 7. Limitations (be upfront about these)
npm projects only (lockfile v2/v3, files at the repo root) · public GitHub repos only · no login (single-user) · only *known* vulnerabilities from OSV · no source-code analysis · risk score is a project-specific heuristic.

## 8. Resume / interview
- *Built a dependency security analytics tool (Python, FastAPI, SQLite) that parses npm lockfiles into direct/transitive dependency graphs, batch-queries the OSV vulnerability database, and computes severity (own CVSS v3 calculator), a transparent risk index, and scan-to-scan remediation trends.*
- *Integrated Gemini to explain scan results using only calculated data, with a deterministic fallback; wrote 31 automated tests including a mock OSV server.*
- **Pitch:** "A user imports a project from GitHub or uploads package files. Python parses the lockfile to find every package and how it got there, batch-queries OSV, and stores each scan in SQLite. SQL aggregates give severity, exposure and trends, and comparing scans shows what was fixed or introduced. An LLM explains the results but never decides what's vulnerable."
- **Why SQL / SQLite?** Scans, dependencies and findings are related tables; trends are aggregations. SQLite = zero setup for a prototype.
- **Why batch?** One request for hundreds of packages instead of one each.
- **OSV down?** Marked partial/failed, never shown as "no vulnerabilities".

## 9. Ideas to extend later
Post a scan summary to Slack/Discord via webhook · scheduled re-scans · GitHub Action that runs a scan on every push · Python/`requirements.txt` support · swap SQLite for PostgreSQL.

## 10. Live demo & deployment
Live: _paste your https://….onrender.com link here_ (free tier: first load takes about a minute, and data resets when the service restarts — click **Load demo** first).

Deploy on Render (Python web service): Build `pip install -r requirements.txt`, Start `cd backend && uvicorn main:app --host 0.0.0.0 --port $PORT --proxy-headers --forwarded-allow-ips='*'`, and set `DEVGUARD_PUBLIC=1`, `PYTHON_VERSION`, and optionally `LLM_API_KEY`, `LLM_MODEL`, `LLM_FALLBACK_MODELS`, `GITHUB_TOKEN`. A ready-made `render.yaml` is included.

## 11. Reading CVSS in the UI
Severity comes from the CVSS v3 score OSV provides (our own implementation of the FIRST formula). The Vulnerabilities table shows the numeric score; "—" means OSV gave only a label (for example advisories that carry only a newer CVSS v4 vector, which DevGuard does not score).
