// DevGuard frontend: plain JavaScript, no framework, no build step.
// Pages are drawn by setting innerHTML. EVERY dynamic value goes through esc() so package names or
// advisory text can never inject HTML.

const app = document.getElementById("app");
let charts = [];
let CONFIG = { ai: false, public: false }; // filled from /api/health at startup
const SEV = { critical: "#ff4d5e", high: "#ff8a3d", medium: "#f5c542", low: "#4cc38a", unknown: "#7d8798" };
Chart.defaults.color = "#94a3b8";
Chart.defaults.borderColor = "#1e293b";

// ---------- helpers ----------
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const safeUrl = (u) => (/^https?:\/\//i.test(u) ? u : "#");
const $ = (sel) => document.querySelector(sel);
const badge = (s) => { const c = SEV[s] || SEV.unknown; return `<span class="rounded px-2 py-0.5 text-[11px] font-semibold uppercase" style="color:${c};background:${c}22;border:1px solid ${c}66">${esc(s || "unknown")}</span>`; };
const riskColor = (l) => ({ critical: "#ff4d5e", high: "#ff8a3d", medium: "#f5c542", low: "#4cc38a", none: "#4cc38a" }[l] || "#94a3b8");
const when = (iso) => { const d = new Date(iso); return isNaN(d) ? "" : d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }); };
const stat = (label, value, sub = "", color = "") => `<div class="card"><div class="text-xs uppercase tracking-wide text-slate-400">${label}</div><div class="mt-1 text-3xl font-semibold" ${color ? `style="color:${color}"` : ""}>${esc(value)}</div>${sub ? `<div class="mt-1 text-xs text-slate-500">${sub}</div>` : ""}</div>`;
const section = (title, body, sub = "") => `<section class="card"><h2 class="text-sm font-semibold text-slate-100">${title}</h2>${sub ? `<p class="mb-3 text-xs text-slate-500">${sub}</p>` : '<div class="mb-3"></div>'}${body}</section>`;
const errBox = (e) => `<div class="rounded-xl border border-red-500/40 bg-red-500/10 p-4 text-sm"><b class="text-red-400">Something went wrong</b><div class="mt-1">${esc(e.message)}</div>${e.hint ? `<div class="mt-1 text-slate-400">${esc(e.hint)}</div>` : ""}</div>`;
const spinner = (msg) => `<div class="flex items-center gap-3 text-sm text-slate-400"><span class="h-4 w-4 animate-spin rounded-full border-2 border-slate-600 border-t-teal-400"></span>${esc(msg)}</div>`;
const empty = (title, body, action = "") => `<div class="card flex flex-col items-center py-12 text-center"><div class="text-base font-semibold">${esc(title)}</div><p class="mt-1 max-w-md text-sm text-slate-400">${esc(body)}</p><div class="mt-4">${action}</div></div>`;
const brand = `<a href="#/" class="flex items-center gap-2 text-lg font-semibold text-white"><span class="flex h-7 w-7 items-center justify-center rounded-md bg-teal-400 text-slate-950">🛡</span>DevGuard</a>`;

async function api(path, opts) {
  let res;
  try { res = await fetch(path, opts); } catch { throw Object.assign(new Error("Cannot reach the DevGuard server."), { hint: "Please try again in a moment." }); }
  const body = await res.json().catch(() => null);
  if (!res.ok) { const e = body && body.error; throw Object.assign(new Error(e ? e.message : `Request failed (${res.status})`), { hint: e && e.hint }); }
  return body;
}
const post = (path, body) => api(path, body === undefined ? { method: "POST" } : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
const killCharts = () => { charts.forEach((c) => c.destroy()); charts = []; };
const addChart = (id, cfg) => { const el = document.getElementById(id); if (el) charts.push(new Chart(el, cfg)); };

// ---------- router ----------
window.addEventListener("hashchange", route);
function route() {
  killCharts();
  const m = location.hash.match(/^#\/project\/(\d+)(?:\/(\w+))?/);
  m ? projectPage(Number(m[1]), m[2] || "overview") : homePage();
}

// ---------- home ----------
async function homePage() {
  app.innerHTML = `
  <header class="flex items-center justify-between py-5">${brand}<span class="pill">OSV-powered · uploaded code is never executed</span></header>
  <section class="py-12 text-center">
    <h1 class="text-4xl font-semibold tracking-tight text-white md:text-5xl">Know what is vulnerable.<br>Know why it matters.<br><span class="text-teal-400">Track whether you are getting safer.</span></h1>
    <p class="mx-auto mt-5 max-w-2xl text-slate-400">DevGuard reads your npm dependency tree, checks every resolved version against the OSV vulnerability database, and shows risk metrics and trends over time.</p>
  </section>
  <div id="busy" class="mb-4"></div><div id="error" class="mb-4"></div>
  <div class="grid gap-5 md:grid-cols-2">
    <div class="card"><h2 class="font-semibold text-white">Analyze a public GitHub repository</h2>
      <p class="mt-1 text-xs text-slate-500">Reads package.json and package-lock.json from the repo root. Nothing is cloned or run.</p>
      <input id="ghUrl" class="input mt-4" placeholder="https://github.com/user/repository">
      <button id="ghBtn" class="btn btn-primary mt-3 w-full">Analyze Repository</button></div>
    <div class="card"><h2 class="font-semibold text-white">Upload project files</h2>
      <p class="mt-1 text-xs text-slate-500">DevGuard only analyzes dependency metadata. Uploaded code is never executed.</p>
      <label class="mt-4 block text-xs text-slate-400">package.json (required)<input id="fPkg" type="file" accept=".json" class="input mt-1"></label>
      <label class="mt-3 block text-xs text-slate-400">package-lock.json (recommended)<input id="fLock" type="file" accept=".json" class="input mt-1"></label>
      <button id="upBtn" class="btn btn-primary mt-3 w-full">Upload &amp; Analyze</button></div>
  </div>
  <div class="card mt-5 flex flex-wrap items-center justify-between gap-3">
    <div><div class="font-semibold text-white">Try the demo project <span class="pill border-teal-400/40 text-teal-300">demo data</span></div>
      <p class="mt-1 text-xs text-slate-500">Real npm package versions. Findings come live from OSV. Load v1, then v2 (upgraded) to see a real scan comparison.</p></div>
    <div class="flex gap-2"><button class="btn btn-ghost" data-demo="before">1 · Load demo (older versions)</button><button class="btn btn-ghost" data-demo="after">2 · Re-scan after upgrades</button></div>
  </div>
  <h2 class="mb-3 mt-10 text-sm font-semibold uppercase tracking-wide text-slate-400">Your projects</h2>
  <div id="projects">${spinner("Loading projects…")}</div>
  <footer class="mt-14 text-center text-xs text-slate-500">Vulnerability data from OSV. DevGuard detects known vulnerabilities only. The Risk Index is a DevGuard heuristic, not an industry standard.</footer>`;

  const run = async (msg, fn) => {
    $("#error").innerHTML = ""; $("#busy").innerHTML = `<div class="card">${spinner(msg)}<p class="mt-2 text-xs text-slate-500">This usually takes a few seconds.</p></div>`;
    document.querySelectorAll("button").forEach((b) => (b.disabled = true));
    try { const r = await fn(); location.hash = `#/project/${r.project_id}`; }
    catch (e) { $("#busy").innerHTML = ""; $("#error").innerHTML = errBox(e); document.querySelectorAll("button").forEach((b) => (b.disabled = false)); }
  };
  $("#ghBtn").onclick = () => { const url = $("#ghUrl").value.trim(); if (url) run("Downloading files from GitHub and querying OSV…", () => post("/api/import/github", { url })); };
  $("#ghUrl").onkeydown = (e) => { if (e.key === "Enter") $("#ghBtn").click(); };
  $("#upBtn").onclick = () => {
    const pkg = $("#fPkg").files[0], lock = $("#fLock").files[0];
    if (!pkg) { $("#error").innerHTML = errBox({ message: "Please choose a package.json file." }); return; }
    const fd = new FormData(); fd.append("package_json", pkg); if (lock) fd.append("package_lock", lock);
    run("Parsing dependencies and querying OSV…", () => api("/api/import/upload", { method: "POST", body: fd }));
  };
  document.querySelectorAll("[data-demo]").forEach((b) => (b.onclick = () => run("Scanning demo project against OSV…", () => post(`/api/demo/${b.dataset.demo}`))));

  try {
    const { projects } = await api("/api/projects");
    $("#projects").innerHTML = projects.length ? `<div class="grid gap-3 md:grid-cols-2">${projects.map((p) => {
      const s = p.latest_scan;
      return `<a href="#/project/${p.id}" class="card block transition hover:border-teal-400/50"><div class="flex items-center justify-between"><b class="text-white">${esc(p.name)}</b><span class="pill">${esc(p.source_type)}</span></div>
        <div class="mt-2 flex flex-wrap items-center gap-4 text-xs text-slate-400">${s ? `<span>Risk <b class="text-slate-100">${s.risk_index}</b></span><span>${s.total_findings} vulns</span>${s.critical_count ? badge("critical") : ""}${s.status !== "completed" ? `<span class="pill text-orange-300">${esc(s.status)}</span>` : ""}<span class="ml-auto">${when(s.created_at)} · ${p.scan_count} scans</span>` : "No scans yet"}</div></a>`;
    }).join("")}</div>` : empty("No projects yet.", "Analyze a public GitHub repository or upload your package files to get started.");
  } catch (e) { $("#projects").innerHTML = errBox(e); }
}

// ---------- project page ----------
const TABS = [["overview", "Overview"], ["vulns", "Vulnerabilities"], ["deps", "Dependencies"], ["history", "History"], ["ai", "AI Assistant"]];

async function projectPage(id, tab) {
  app.innerHTML = `<header class="flex items-center justify-between py-5">${brand}</header>${spinner("Loading project…")}`;
  let data;
  try { data = await api(`/api/projects/${id}/summary`); }
  catch (e) { app.innerHTML = `<header class="py-5">${brand}</header>${errBox(e)}`; return; }
  const p = data.project, s = data.scan;
  app.innerHTML = `
  <header class="flex items-center justify-between py-5">${brand}<button id="scanBtn" class="btn btn-primary">Run New Scan</button></header>
  <div class="mb-4"><div class="flex flex-wrap items-center gap-3"><h1 class="text-2xl font-semibold text-white">${esc(p.name)}</h1><span class="pill ${p.source_type === "demo" ? "border-teal-400/40 text-teal-300" : ""}">${p.source_type === "demo" ? "demo data" : esc(p.source_type)}</span></div>
    <div class="mt-1 text-xs text-slate-500">${p.repo_url ? `<a class="text-teal-400 hover:underline" target="_blank" rel="noopener noreferrer" href="${esc(safeUrl(p.repo_url))}">${esc(p.repo_url.replace("https://", ""))}</a> · ` : ""}${s ? `Last scanned ${when(s.created_at)}` : "Not scanned yet"} <a href="#/" class="ml-3 text-slate-400 hover:text-white">← all projects</a>
    ${CONFIG.public ? "" : '<button id="delBtn" class="ml-3 text-slate-600 hover:text-red-400">delete</button>'}</div></div>
  <nav class="mb-5 flex gap-1 overflow-x-auto border-b border-slate-800">${TABS.map(([k, l]) => `<a href="#/project/${id}/${k}" class="whitespace-nowrap border-b-2 px-4 py-2 text-sm ${k === tab ? "border-teal-400 text-white" : "border-transparent text-slate-400 hover:text-slate-200"}">${l}</a>`).join("")}</nav>
  <div id="notice" class="mb-4"></div><div id="tab"></div>`;

  $("#scanBtn").onclick = async () => {
    $("#scanBtn").disabled = true; $("#notice").innerHTML = `<div class="card">${spinner("Scanning… reading files, querying OSV, calculating risk, saving")}</div>`;
    try { await post(`/api/projects/${id}/scan`); route(); } catch (e) { $("#notice").innerHTML = errBox(e); $("#scanBtn").disabled = false; }
  };
  if ($("#delBtn")) $("#delBtn").onclick = async () => { if (confirm(`Delete "${p.name}" and all its scans?`)) { await api(`/api/projects/${id}`, { method: "DELETE" }); location.hash = "#/"; } };

  const tabEl = $("#tab");
  if (!s) { tabEl.innerHTML = empty("No scans yet", "Run the first scan to see dependencies, vulnerabilities and risk metrics."); return; }
  statusBanner(s);
  ({ overview: () => overview(tabEl, data), vulns: () => vulnsTab(tabEl, s), deps: () => depsTab(tabEl, s), history: () => historyTab(tabEl, id), ai: () => aiTab(tabEl, s) }[tab] || (() => overview(tabEl, data)))();
}

function statusBanner(s) {
  const list = (a) => `<ul class="mt-2 list-disc pl-5 text-xs text-slate-400">${a.slice(0, 5).map((x) => `<li>${esc(x)}</li>`).join("")}${a.length > 5 ? `<li>…and ${a.length - 5} more</li>` : ""}</ul>`;
  let html = "";
  if (s.status === "failed") html += `<div class="mb-3 rounded-xl border border-red-500/40 bg-red-500/10 p-4 text-sm"><b class="text-red-400">This scan failed.</b> Nothing can be concluded about vulnerabilities. Press "Run New Scan" to retry.${list(s.errors)}</div>`;
  if (s.status === "partial") html += `<div class="mb-3 rounded-xl border border-orange-400/40 bg-orange-400/10 p-4 text-sm"><b class="text-orange-300">Partial scan.</b> Some OSV lookups failed, so "0 vulnerabilities" does <b>not</b> mean safe. Retry the scan.${list(s.errors)}</div>`;
  if (s.mode === "manifest-ranges") html += `<div class="mb-3 rounded-xl border border-slate-700 bg-slate-900 p-4 text-sm text-slate-300"><b>Best-effort mode:</b> no lockfile was provided, so versions were guessed from package.json ranges and transitive dependencies were not analyzed.</div>`;
  else if (s.warnings.length) html += `<div class="mb-3 rounded-xl border border-slate-700 bg-slate-900 p-4 text-sm text-slate-300"><b>Parser warnings</b>${list(s.warnings)}</div>`;
  $("#notice").insertAdjacentHTML("beforeend", html);
}

// ---------- overview ----------
function changesHtml(c) {
  const d = (label, m) => `<div class="rounded-lg border border-slate-800 bg-slate-950 p-3"><div class="text-xs text-slate-400">${label}</div><div class="mt-1 text-lg font-semibold">${m.old} → ${m.new}</div><div class="text-xs ${m.delta < 0 ? "text-green-400" : m.delta > 0 ? "text-red-400" : "text-slate-500"}">${m.delta === 0 ? "no change" : (m.delta < 0 ? "↓ " : "↑ ") + Math.abs(m.delta)}</div></div>`;
  const row = (f, extra) => `<li class="flex flex-wrap items-center gap-2">${badge(f.severity)}<span class="font-mono">${esc(f.package)} ${esc(f.version)}</span><span class="text-slate-500">${esc(f.osv_id)}${extra ? " · " + esc(extra) : ""}</span></li>`;
  const pc = c.package_changes, sm = c.summary;
  return `${c.note ? `<div class="mb-3 rounded-lg border border-orange-400/40 bg-orange-400/10 p-3 text-xs text-orange-300">${esc(c.note)}</div>` : ""}
  <div class="grid grid-cols-2 gap-3 md:grid-cols-4">${d("Risk Index", c.metrics.risk_index)}${d("Critical", c.metrics.critical_count)}${d("High", c.metrics.high_count)}${d("Vulnerable packages", c.metrics.vulnerable_dependencies)}</div>
  <ul class="mt-4 space-y-1 text-sm"><li class="text-green-400">✓ ${sm.resolved} vulnerabilit${sm.resolved === 1 ? "y" : "ies"} resolved${c.remediation_rate !== null ? ` (remediation rate ${Math.round(c.remediation_rate * 100)}%)` : ""}</li>
    <li class="${sm.introduced ? "text-red-400" : "text-slate-400"}">+ ${sm.introduced} introduced</li><li class="text-slate-300">↻ ${sm.updated} packages updated · ${sm.added} added · ${sm.removed} removed</li></ul>
  ${c.fixed.length ? `<div class="mt-3 text-xs font-semibold uppercase text-green-400">Fixed</div><ul class="mt-1 space-y-1 text-sm">${c.fixed.map((f) => row(f, f.resolution)).join("")}</ul>` : ""}
  ${c.introduced.length ? `<div class="mt-3 text-xs font-semibold uppercase text-red-400">New</div><ul class="mt-1 space-y-1 text-sm">${c.introduced.map((f) => row(f)).join("")}</ul>` : ""}
  ${pc.updated.length ? `<details class="mt-3 text-sm"><summary class="cursor-pointer text-slate-400">Package changes</summary><ul class="mt-2 font-mono text-xs text-slate-300">${pc.updated.map((p) => `<li>↻ ${esc(p.name)} ${esc(p.from)} → ${esc(p.to)}</li>`).join("")}${pc.added.map((p) => `<li>+ ${esc(p.name)} ${esc(p.version)}</li>`).join("")}${pc.removed.map((p) => `<li>− ${esc(p.name)} ${esc(p.version)}</li>`).join("")}</ul></details>` : ""}`;
}

function splitTable(rows) {
  return `<table class="w-full"><thead><tr><th class="th"></th><th class="th">Packages</th><th class="th">Vulnerable</th></tr></thead><tbody class="divide-y divide-slate-800">${rows.map((r) => `<tr><td class="td">${esc(r.label)}</td><td class="td">${r.total}</td><td class="td ${r.vulnerable ? "text-orange-300" : "text-slate-500"}">${r.vulnerable}</td></tr>`).join("")}</tbody></table>`;
}

function overview(el, data) {
  const s = data.scan;
  if (s.status === "failed") { el.innerHTML = ""; return; }
  el.innerHTML = `<div class="space-y-5">
  <div class="grid grid-cols-2 gap-3 md:grid-cols-4">
    ${stat("Risk Index", s.risk_index, `${esc(s.risk_level)} · DevGuard heuristic`, riskColor(s.risk_level))}
    ${stat("Dependencies", s.total_dependencies, `${s.direct_count} direct · ${s.transitive_count} transitive`)}
    ${stat("Vulnerabilities", s.total_findings, `in ${s.vulnerable_dependencies} packages`)}
    ${stat("Density", s.density, "vulnerabilities ÷ dependencies")}</div>
  <div class="grid grid-cols-2 gap-3 md:grid-cols-5">
    ${stat("Critical", s.critical_count, "", s.critical_count ? SEV.critical : "")}${stat("High", s.high_count, "", s.high_count ? SEV.high : "")}
    ${stat("Medium", s.medium_count)}${stat("Low", s.low_count, s.unknown_count ? `+ ${s.unknown_count} unknown severity` : "")}${stat("Highest CVSS", data.max_cvss == null ? "—" : Number(data.max_cvss).toFixed(1), "worst advisory score (0–10)")}</div>
  <div class="grid gap-5 md:grid-cols-3">
    <div class="md:col-span-2">${section("Risk trend", data.trend.length < 2 ? `<p class="py-10 text-center text-sm text-slate-500">Run another scan to see a trend. One scan is one data point.</p>` : `<canvas id="cTrend" height="130"></canvas>`, "Risk Index per scan (lower is better)")}</div>
    ${section("Severity", `<canvas id="cSev" height="220"></canvas>`, "Findings in the latest scan")}</div>
  <div class="grid gap-5 md:grid-cols-2">${section("Direct vs transitive", splitTable(data.exposure))}${section("Production vs development", splitTable(data.environment))}</div>
  ${section("Highest-risk packages", data.top_packages.length ? `<div class="overflow-x-auto"><table class="w-full"><thead><tr><th class="th">Package</th><th class="th">Type</th><th class="th">Env</th><th class="th">Vulns</th><th class="th">Worst</th><th class="th">Max CVSS</th><th class="th">Risk</th></tr></thead><tbody class="divide-y divide-slate-800">${data.top_packages.map((p) => `<tr><td class="td font-mono">${esc(p.name)}@${esc(p.version)}</td><td class="td text-slate-400">${esc(p.dep_type)}</td><td class="td text-slate-400">${esc(p.env)}</td><td class="td">${p.findings}</td><td class="td">${badge(p.critical ? "critical" : p.high ? "high" : "medium")}</td><td class="td">${p.max_cvss == null ? "—" : Number(p.max_cvss).toFixed(1)}</td><td class="td">${p.risk}</td></tr>`).join("")}</tbody></table></div>` : `<p class="text-sm text-slate-500">No vulnerable packages found${s.status === "partial" ? " (partial scan: not proof of safety)" : ""}.</p>`, "Ranked by summed finding risk")}
  ${section("What changed since the last scan?", data.changes ? changesHtml(data.changes) : `<p class="text-sm text-slate-500">This is the first scan. Run another after changing your dependencies to see a comparison.</p>`)}
  ${section("How is this calculated?", `<div class="space-y-2 text-sm text-slate-400">
    <p><b class="text-slate-200">Risk Index</b>: a DevGuard heuristic, not an industry standard. Each finding = severity weight (critical 10, high 6, medium 3, low 1, unknown 2) × environment (production 1.0, development 0.4) × exposure (direct 1.0, transitive 0.8). The sum is squashed to 0–100 with 100·(1 − e^(−sum/40)).</p>
    <p><b class="text-slate-200">Severity</b>: from the CVSS v3 vector when OSV has one, else the advisory's own label, else <i>unknown</i> (never silently "low").</p>
    <p><b class="text-slate-200">Density</b> = vulnerabilities ÷ dependencies. <b class="text-slate-200">Remediation rate</b> (A→B) = resolved ÷ vulnerabilities in A.</p></div>`)}</div>`;

  if (data.trend.length >= 2) addChart("cTrend", { type: "line", data: { labels: data.trend.map((t) => "#" + t.id),
    datasets: [{ label: "Risk Index", data: data.trend.map((t) => t.risk_index), borderColor: "#2dd4bf", tension: 0.3 }, { label: "Vulnerabilities", data: data.trend.map((t) => t.total_findings), borderColor: "#ff8a3d", tension: 0.3 }] }, options: { plugins: { legend: { position: "bottom" } } } });
  const names = ["critical", "high", "medium", "low", "unknown"], vals = [s.critical_count, s.high_count, s.medium_count, s.low_count, s.unknown_count];
  addChart("cSev", { type: "bar", data: { labels: names, datasets: [{ data: vals, backgroundColor: names.map((n) => SEV[n]) }] }, options: { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } } });
}

// ---------- vulnerabilities ----------
async function vulnsTab(el, s) {
  el.innerHTML = spinner("Loading vulnerabilities…");
  let rows; try { rows = (await api(`/api/scans/${s.id}/findings`)).findings; } catch (e) { el.innerHTML = errBox(e); return; }
  el.innerHTML = `<div class="mb-3 flex flex-wrap gap-2"><input id="q" class="input max-w-xs" placeholder="Search package or advisory id…">
    <select id="fSev" class="input w-auto"><option value="">Any severity</option>${["critical", "high", "medium", "low", "unknown"].map((x) => `<option>${x}</option>`).join("")}</select>
    <select id="fType" class="input w-auto"><option value="">Direct &amp; transitive</option><option>direct</option><option>transitive</option></select>
    <select id="fEnv" class="input w-auto"><option value="">Prod &amp; dev</option><option>production</option><option>development</option></select>
    <select id="fFix" class="input w-auto"><option value="">Fix: any</option><option value="yes">Fix available</option><option value="no">No fix known</option></select>
    <a class="btn btn-ghost" href="/api/scans/${s.id}/export.csv">Export CSV</a></div>
    <div id="vTable"></div><p id="vCount" class="mt-2 text-xs text-slate-500"></p>`;
  const draw = () => {
    const q = $("#q").value.toLowerCase(), sev = $("#fSev").value, ty = $("#fType").value, env = $("#fEnv").value, fix = $("#fFix").value;
    const list = rows.filter((r) => (!q || r.package.toLowerCase().includes(q) || r.osv_id.toLowerCase().includes(q)) && (!sev || r.severity === sev) && (!ty || r.dep_type === ty) && (!env || r.env === env) && (!fix || (fix === "yes") === !!r.fixed_version));
    $("#vCount").textContent = `${list.length} result(s). Click a row for details and the dependency path.`;
    $("#vTable").innerHTML = list.length ? `<div class="card overflow-x-auto p-0"><table class="w-full"><thead class="border-b border-slate-800"><tr><th class="th">Package</th><th class="th">Version</th><th class="th">Severity</th><th class="th">CVSS</th><th class="th">Advisory</th><th class="th">Type</th><th class="th">Env</th><th class="th">Fixed in</th></tr></thead><tbody class="divide-y divide-slate-800">${list.map((r) => `<tr class="cursor-pointer hover:bg-slate-800/60" data-id="${r.id}"><td class="td font-mono">${esc(r.package)}</td><td class="td font-mono text-slate-400">${esc(r.version)}</td><td class="td">${badge(r.severity)}</td><td class="td tabular-nums" title="${r.cvss === null ? "OSV provided only a severity label for this advisory" : "CVSS v3 base score"}">${r.cvss === null ? "—" : Number(r.cvss).toFixed(1)}</td><td class="td"><div class="font-mono text-xs text-teal-300">${esc(r.osv_id)}</div><div class="max-w-xs truncate text-xs text-slate-500">${esc(r.summary)}</div></td><td class="td text-slate-400">${esc(r.dep_type)}</td><td class="td text-slate-400">${r.env === "production" ? "prod" : "dev"}</td><td class="td font-mono">${r.fixed_version ? esc(r.fixed_version) : "—"}</td></tr>`).join("")}</tbody></table></div>`
      : empty("No vulnerabilities match.", rows.length ? "Try clearing a filter." : "None found. If the scan was partial or failed, that is not proof of safety.");
    document.querySelectorAll("#vTable tr[data-id]").forEach((tr) => (tr.onclick = () => toggleDetail(tr, 8)));
  };
  ["q", "fSev", "fType", "fEnv", "fFix"].forEach((id) => ($("#" + id).oninput = draw));
  draw();
}

async function toggleDetail(tr, cols) {
  const next = tr.nextElementSibling;
  if (next && next.dataset.detail) { next.remove(); return; }
  const row = document.createElement("tr"); row.dataset.detail = "1";
  row.innerHTML = `<td colspan="${cols}" class="bg-slate-950 px-5 py-4">${spinner("Loading…")}</td>`; tr.after(row);
  try {
    const f = await api(`/api/findings/${tr.dataset.id}`);
    row.firstElementChild.innerHTML = `<div class="grid gap-4 text-sm md:grid-cols-2">
      <div><div class="flex flex-wrap items-center gap-2">${badge(f.severity)}${f.cvss !== null ? `<span class="pill">CVSS ${f.cvss}</span>` : ""}<b class="font-mono text-white">${esc(f.osv_id)}</b></div>
        ${f.aliases.length ? `<div class="mt-1 text-xs text-slate-500">Also: ${f.aliases.map(esc).join(", ")}</div>` : ""}
        <p class="mt-2 text-slate-300">${esc(f.summary || "No summary provided by OSV.")}</p>
        <dl class="mt-3 grid grid-cols-2 gap-2 text-xs"><div><dt class="text-slate-500">Installed</dt><dd class="font-mono">${esc(f.package)}@${esc(f.version)}</dd></div><div><dt class="text-slate-500">Fixed in</dt><dd class="font-mono">${esc(f.fixed_version || "none known in OSV data")}</dd></div>
          <div><dt class="text-slate-500">Dependency</dt><dd>${esc(f.dep_type)} · ${esc(f.env)}${f.depth ? " · depth " + f.depth : ""}</dd></div><div><dt class="text-slate-500">Published</dt><dd>${esc((f.published || "—").slice(0, 10))}</dd></div>${f.cvss_vector ? `<div class="col-span-2"><dt class="text-slate-500">CVSS vector</dt><dd class="break-all font-mono">${esc(f.cvss_vector)}</dd></div>` : ""}</dl>
        ${f.affected_ranges.length ? `<div class="mt-3 text-xs text-slate-500">Affected ranges (OSV): <span class="font-mono text-slate-300">${f.affected_ranges.map(esc).join("; ")}</span></div>` : ""}</div>
      <div><div class="text-xs font-semibold uppercase text-slate-400">Dependency path</div><ol class="mt-2 space-y-1 font-mono text-xs">${f.path.map((p, i) => `<li style="padding-left:${i * 12}px" class="${i === f.path.length - 1 ? "text-orange-300" : "text-slate-300"}">${i ? "↳ " : "● "}${esc(p)}</li>`).join("")}</ol>
        ${f.refs.length ? `<div class="mt-4 text-xs font-semibold uppercase text-slate-400">References</div><ul class="mt-1 space-y-1 text-xs">${f.refs.slice(0, 6).map((r) => `<li><a class="break-all text-teal-300 hover:underline" target="_blank" rel="noopener noreferrer" href="${esc(safeUrl(r.url))}">${esc(r.url)}</a></li>`).join("")}</ul>` : ""}</div></div>
      ${f.details ? `<details class="mt-3"><summary class="cursor-pointer text-xs text-slate-400">Full advisory text</summary><p class="mt-2 whitespace-pre-wrap text-xs text-slate-300">${esc(f.details)}</p></details>` : ""}`;
  } catch (e) { row.firstElementChild.innerHTML = errBox(e); }
}

// ---------- dependencies ----------
async function depsTab(el, s) {
  el.innerHTML = spinner("Loading dependencies…");
  let rows; try { rows = (await api(`/api/scans/${s.id}/dependencies`)).dependencies; } catch (e) { el.innerHTML = errBox(e); return; }
  el.innerHTML = `<div class="mb-3 flex flex-wrap gap-2"><input id="q" class="input max-w-xs" placeholder="Search packages…">
    <select id="fType" class="input w-auto"><option value="">Direct &amp; transitive</option><option>direct</option><option>transitive</option></select>
    <select id="fEnv" class="input w-auto"><option value="">Prod &amp; dev</option><option>production</option><option>development</option></select>
    <select id="fVul" class="input w-auto"><option value="">All packages</option><option value="yes">Vulnerable only</option><option value="no">No known vulns</option></select>
    <select id="fSort" class="input w-auto"><option value="vuln">Sort: most vulnerable</option><option value="depth">Sort: deepest</option><option value="name">Sort: name</option></select></div>
    <div id="dTable"></div><p id="dCount" class="mt-2 text-xs text-slate-500"></p>`;
  const draw = () => {
    const q = $("#q").value.toLowerCase(), ty = $("#fType").value, env = $("#fEnv").value, vu = $("#fVul").value, so = $("#fSort").value;
    const list = rows.filter((r) => (!q || r.name.toLowerCase().includes(q)) && (!ty || r.dep_type === ty) && (!env || r.env === env) && (!vu || (vu === "yes") === r.vuln_count > 0));
    if (so === "depth") list.sort((a, b) => (b.depth || 0) - (a.depth || 0)); else if (so === "name") list.sort((a, b) => a.name.localeCompare(b.name));
    const direct = list.filter((r) => r.dep_type === "direct").length;
    $("#dCount").textContent = `${list.length} dependencies · ${direct} direct · ${list.length - direct} transitive. Click a row to see its path.`;
    $("#dTable").innerHTML = list.length ? `<div class="card overflow-x-auto p-0"><table class="w-full"><thead class="border-b border-slate-800"><tr><th class="th">Package</th><th class="th">Version</th><th class="th">Type</th><th class="th">Env</th><th class="th">Depth</th><th class="th">Vulns</th><th class="th">Worst</th><th class="th">Risk</th></tr></thead><tbody class="divide-y divide-slate-800">${list.map((r) => `<tr class="cursor-pointer hover:bg-slate-800/60" data-path="${esc(r.path.join("  →  "))}"><td class="td font-mono">${esc(r.name)}${r.lookup_ok ? "" : ' <span class="pill text-orange-300">lookup failed</span>'}</td><td class="td font-mono text-slate-400">${esc(r.version)}</td><td class="td text-slate-400">${esc(r.dep_type)}</td><td class="td text-slate-400">${r.env === "production" ? "prod" : "dev"}</td><td class="td">${r.depth ?? "—"}</td><td class="td">${r.vuln_count}</td><td class="td">${r.worst_severity ? badge(r.worst_severity) : "—"}</td><td class="td">${r.risk}</td></tr>`).join("")}</tbody></table></div>` : empty("No dependencies match.", "Try clearing a filter.");
    document.querySelectorAll("#dTable tr[data-path]").forEach((tr) => (tr.onclick = () => {
      const n = tr.nextElementSibling; if (n && n.dataset.detail) return n.remove();
      const row = document.createElement("tr"); row.dataset.detail = "1"; row.innerHTML = `<td colspan="8" class="bg-slate-950 px-5 py-3 font-mono text-xs text-slate-300">${esc(tr.dataset.path)}</td>`; tr.after(row);
    }));
  };
  ["q", "fType", "fEnv", "fVul", "fSort"].forEach((id) => ($("#" + id).oninput = draw));
  draw();
}

// ---------- history ----------
async function historyTab(el, projectId) {
  el.innerHTML = spinner("Loading history…");
  let scans; try { scans = (await api(`/api/projects/${projectId}/scans`)).scans; } catch (e) { el.innerHTML = errBox(e); return; }
  el.innerHTML = `${section("Scan history", `<div class="overflow-x-auto"><table class="w-full"><thead><tr><th class="th">Scan</th><th class="th">When</th><th class="th">Status</th><th class="th">Risk</th><th class="th">Vulns</th><th class="th">C / H / M / L</th><th class="th">Deps</th><th class="th"></th></tr></thead><tbody class="divide-y divide-slate-800">${scans.map((s, i) => {
    const older = scans.slice(i + 1).find((o) => o.status !== "failed"); const bad = s.status === "failed";
    return `<tr><td class="td font-mono">#${s.id}</td><td class="td text-slate-400">${when(s.created_at)}</td><td class="td"><span class="pill ${s.status === "completed" ? "text-teal-300" : "text-orange-300"}">${esc(s.status)}</span></td><td class="td">${bad ? "—" : s.risk_index}</td><td class="td">${bad ? "—" : s.total_findings}</td><td class="td font-mono text-xs text-slate-400">${s.critical_count} / ${s.high_count} / ${s.medium_count} / ${s.low_count}</td><td class="td">${s.total_dependencies}</td><td class="td text-right">${older && !bad ? `<button class="text-xs text-teal-300 hover:underline" data-cmp="${s.id}:${older.id}">Compare with #${older.id}</button>` : ""}</td></tr>`;
  }).join("")}</tbody></table></div>`, "Newest first. Every scan is stored as a snapshot.")}<div id="cmp" class="mt-5"></div>`;
  document.querySelectorAll("[data-cmp]").forEach((b) => (b.onclick = async () => {
    const [n, o] = b.dataset.cmp.split(":"); $("#cmp").innerHTML = spinner("Comparing…");
    try { $("#cmp").innerHTML = section(`What changed: scan #${o} → #${n}`, changesHtml(await api(`/api/scans/${n}/compare/${o}`))); } catch (e) { $("#cmp").innerHTML = errBox(e); }
  }));
}

// ---------- AI ----------
function aiTab(el, s) {
  const chat = CONFIG.ai
    ? section("Ask about this scan", `<div class="flex gap-2"><input id="askIn" class="input" maxlength="500" placeholder="e.g. What should I fix first? Is the critical one in production?"><button id="askBtn" class="btn btn-primary">Ask</button></div><div id="askOut" class="mt-4"></div>`, "Answers use only this scan's data.")
    : section("Ask about this scan", `<p class="text-sm text-slate-500">The AI chat is not enabled on this server.</p>`);
  el.innerHTML = `<div class="space-y-5">${section(CONFIG.ai ? "Explain this scan" : "Scan summary", `<button id="exBtn" class="btn btn-primary">${CONFIG.ai ? "Explain this scan" : "Summarize this scan"}</button><div id="exOut" class="mt-4"></div>`, CONFIG.ai ? "The AI only explains numbers DevGuard already calculated. It never decides what is vulnerable." : "A plain-language summary of the numbers DevGuard calculated.")}${chat}</div>`;
  const out = (target, r) => (target.innerHTML = `<div class="rounded-lg border border-slate-800 bg-slate-950 p-4 text-sm leading-relaxed text-slate-200" style="white-space:pre-wrap">${esc(r.text)}</div><div class="mt-2 text-xs text-slate-500">${r.source === "ai" ? "Generated by AI from your scan data. AI can make mistakes." : "Automated summary based on DevGuard's calculated results."}</div>`);
  $("#exBtn").onclick = async () => { $("#exOut").innerHTML = spinner("Thinking…"); try { out($("#exOut"), await post(`/api/scans/${s.id}/explain`)); } catch (e) { $("#exOut").innerHTML = errBox(e); } };
  if (CONFIG.ai) {
    const ask = async () => { const q = $("#askIn").value.trim(); if (!q) return; $("#askOut").innerHTML = spinner("Thinking…"); try { out($("#askOut"), await post(`/api/scans/${s.id}/ask`, { question: q })); } catch (e) { $("#askOut").innerHTML = errBox(e); } };
    $("#askBtn").onclick = ask; $("#askIn").onkeydown = (e) => { if (e.key === "Enter") ask(); };
  }
}

(async () => { try { CONFIG = await api("/api/health"); } catch { /* keep defaults */ } route(); })(); // start: kept at the end so every constant above is defined
