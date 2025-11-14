// frontend/script.js — full client with Guest mode
// IMPORTANT: update API_BASE if your backend URL is different.
const API_BASE = (location.hostname.includes("localhost") ? "http://localhost:5000" : "https://byte-bloom-cloud-scanner.onrender.com");

// Local mock paths (served by Vercel when mock/ is next to index.html)
const LOCAL_MOCK = "/mock/sample_scan.json";
const ISSUES_MOCK = "/mock/report_issues.json";
// GitHub raw fallback (optional)
const GITHUB_RAW_BASE = "https://raw.githubusercontent.com/bharathakn49-dev/byte-bloom-cloud-scanner/main/frontend/mock";

const $ = (id) => document.getElementById(id);
const tbody = document.querySelector("#results tbody");
const statusEl = $("status");
const spinner = $("spinner");

// Auth & guest state
let token = localStorage.getItem("bb_token") || "";
let currentUser = localStorage.getItem("bb_user") || "";
let isGuest = false;
let guestHistory = JSON.parse(localStorage.getItem("bb_guest_history") || "[]");

// ------------------ UI helpers ------------------
function showSpinner(on = true) { if (!spinner) return; spinner.style.display = on ? "block" : "none"; }
function setStatus(text, tone = "info") {
  if (!statusEl) return;
  statusEl.textContent = text;
  statusEl.style.color = tone === "error" ? "var(--danger)" : (tone === "ok" ? "var(--success)" : "var(--muted)");
}
function escapeHtml(s) { return String(s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }
function clearResults() { if (tbody) tbody.innerHTML = ""; }
function addRow(type, name, detail) {
  if (!tbody) return;
  const tr = document.createElement("tr");
  tr.innerHTML = `<td><span class="badge">${escapeHtml(type)}</span></td>
                  <td><strong>${escapeHtml(name)}</strong></td>
                  <td><div style="font-size:13px;color:var(--muted)">${escapeHtml(detail)}</div></td>`;
  tbody.appendChild(tr);
}
function toggleButtons(disabled) {
  ["btnTest","btnScan","btnMock","exportCsv","btnRegister","btnLogin","btnGuest"].forEach(id => {
    const el = $(id);
    if (el) el.disabled = disabled;
  });
}

// ------------------ Network helpers ------------------
async function fetchWithTimeout(url, opts = {}, timeout = 25000) {
  const ac = new AbortController();
  const id = setTimeout(() => ac.abort(), timeout);
  try {
    const res = await fetch(url, { ...opts, signal: ac.signal });
    clearTimeout(id);
    return res;
  } catch (e) {
    clearTimeout(id);
    throw e;
  }
}
async function postJSON(path, body, timeout=25000) {
  const url = API_BASE + path;
  const headers = { "Content-Type": "application/json", ...authHeaders() };
  const res = await fetchWithTimeout(url, { method: "POST", headers, body: JSON.stringify(body) }, timeout);
  const text = await res.text();
  try { return JSON.parse(text); } catch(e) { throw new Error(`Invalid JSON (${res.status}): ${text}`); }
}
async function getJSON(path, timeout=20000) {
  const url = API_BASE + path;
  const headers = { ...authHeaders() };
  const res = await fetchWithTimeout(url, { headers }, timeout);
  const text = await res.text();
  try { return JSON.parse(text); } catch(e) { throw new Error(`Invalid JSON (${res.status}): ${text}`); }
}
function authHeaders() { return token ? { "Authorization": "Bearer " + token } : {}; }

// ------------------ Auth functions ------------------
async function onRegister() {
  const username = $("username").value && $("username").value.trim();
  const pass = $("password").value;
  if (!username || !pass) { alert("Enter username & password"); return; }
  setStatus("Registering..."); showSpinner(true); toggleButtons(true);
  try {
    const res = await postJSON("/auth/register", { username, password: pass }, 20000);
    if (res.ok) {
      token = res.token; currentUser = res.username;
      localStorage.setItem("bb_token", token); localStorage.setItem("bb_user", currentUser);
      isGuest = false;
      setAuthUI();
      setStatus("Registered & logged in", "ok");
    } else {
      setStatus("Register failed", "error");
      alert("Register failed: " + JSON.stringify(res));
    }
  } catch (e) {
    setStatus("Register error: " + e.message, "error");
    alert("Register error: " + e.message);
  } finally { showSpinner(false); toggleButtons(false); }
}

async function onLogin() {
  const username = $("username").value && $("username").value.trim();
  const pass = $("password").value;
  if (!username || !pass) { alert("Enter username & password"); return; }
  setStatus("Logging in..."); showSpinner(true); toggleButtons(true);
  try {
    const res = await postJSON("/auth/login", { username, password: pass }, 15000);
    if (res.ok) {
      token = res.token; currentUser = res.username;
      localStorage.setItem("bb_token", token); localStorage.setItem("bb_user", currentUser);
      isGuest = false;
      setAuthUI();
      setStatus("Logged in", "ok");
    } else {
      setStatus("Login failed", "error"); alert("Login failed: " + JSON.stringify(res));
    }
  } catch (e) {
    setStatus("Login error: " + e.message, "error"); alert("Login error: " + e.message);
  } finally { showSpinner(false); toggleButtons(false); }
}

function onGuestLogin() {
  isGuest = true;
  token = "";
  currentUser = "guest";
  localStorage.setItem("bb_user", "guest");
  localStorage.setItem("bb_token", "");
  setAuthUI();
  setStatus("Logged in as Guest (local-only history)", "ok");
}

function onLogout() {
  token = ""; currentUser = ""; isGuest = false;
  localStorage.removeItem("bb_token"); localStorage.removeItem("bb_user");
  setAuthUI();
  setStatus("Logged out", "info");
}

function setAuthUI() {
  const loggedWrap = $("loggedInInfo");
  const who = $("whoami");
  const logout = $("btnLogout");
  const loginBtn = $("btnLogin");
  const regBtn = $("btnRegister");
  const guestBtn = $("btnGuest");

  if (isGuest) {
    if (loggedWrap) { loggedWrap.style.display = "block"; who.textContent = "Guest (local)"; }
    if (logout) logout.style.display = "inline-block";
    if (loginBtn) loginBtn.style.display = "inline-block";
    if (regBtn) regBtn.style.display = "inline-block";
    if (guestBtn) guestBtn.style.display = "none";
    return;
  }

  if (token) {
    if (loggedWrap) { loggedWrap.style.display = "block"; who.textContent = currentUser || "user"; }
    if (logout) logout.style.display = "inline-block";
    if (loginBtn) loginBtn.style.display = "none";
    if (regBtn) regBtn.style.display = "none";
    if (guestBtn) guestBtn.style.display = "none";
  } else {
    if (loggedWrap) loggedWrap.style.display = "none";
    if (logout) logout.style.display = "none";
    if (loginBtn) loginBtn.style.display = "inline-block";
    if (regBtn) regBtn.style.display = "inline-block";
    if (guestBtn) guestBtn.style.display = "inline-block";
  }
}

// ------------------ Scan & keys ------------------
async function onTestKeys() {
  const ak = $("access_key").value.trim();
  const sk = $("secret_key").value.trim();
  const region = $("region").value.trim() || "us-east-1";
  if (!ak || !sk) { alert("Enter access key and secret (or use mock)"); return; }
  setStatus("Testing keys..."); showSpinner(true); toggleButtons(true);
  try {
    const res = await fetchWithTimeout(API_BASE + "/keys/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ access_key: ak, secret_key: sk, region })
    }, 20000);
    const j = await res.json();
    if (j.ok) { setStatus("Key test OK", "ok"); alert("Key test summary:\n" + JSON.stringify(j.summary || {}, null, 2)); }
    else { setStatus("Key test failed", "error"); alert("Key test failed: " + JSON.stringify(j)); }
  } catch (e) {
    setStatus("Key test error: " + (e.name === "AbortError" ? "timeout" : e.message), "error");
    alert("Key test error: " + e);
  } finally { showSpinner(false); toggleButtons(false); }
}

async function onRunScan() {
  const ak = $("access_key").value.trim();
  const sk = $("secret_key").value.trim();
  const region = $("region").value.trim() || "us-east-1";

  if (!ak || !sk) {
    if (!isGuest && !confirm("No keys entered. Continue as Guest (local-only) and load mock instead?")) return;
    if (!isGuest) onGuestLogin();
    await loadMock();
    return;
  }

  // If not logged-in and not guest, warn (scans will be saved only for logged-in users)
  if (!token && !isGuest) {
    if (!confirm("You are not logged in. Scans will not be saved to your account. Continue as Guest?")) return;
    onGuestLogin();
    await loadMock();
    return;
  }

  setStatus("Running scan..."); showSpinner(true); toggleButtons(true);
  try {
    const res = await fetchWithTimeout(API_BASE + "/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify({ access_key: ak, secret_key: sk, region })
    }, 40000);
    const j = await res.json();
    if (!j.ok) {
      setStatus("Scan failed: " + (j.error || ""), "error");
      alert("Scan failed: " + JSON.stringify(j));
    } else {
      const report = j.report || {};
      renderReport(report);
      setStatus("Scan complete" + (isGuest ? " (guest local)" : " and saved"), "ok");

      // Save guest history locally
      if (isGuest) {
        guestHistory.unshift({
          timestamp: new Date().toISOString(),
          region,
          summary: report.summary || {},
          report
        });
        localStorage.setItem("bb_guest_history", JSON.stringify(guestHistory));
      }
    }
  } catch (e) {
    setStatus("Scan error: " + (e.name === "AbortError" ? "timeout" : e.message), "error");
    alert("Scan error: " + e);
  } finally {
    showSpinner(false); toggleButtons(false);
  }
}

// ------------------ Render report ------------------
function renderReport(report) {
  clearResults();
  if (!report) { setStatus("Empty report", "error"); return; }
  // issues-style
  if (report.issues && Array.isArray(report.issues)) {
    report.issues.forEach(issue => addRow((issue.resource || "misc").split(":")[0].toUpperCase(), issue.title || issue.id, (issue.severity || "") + " — " + JSON.stringify(issue.details || {})));
    return;
  }
  // simple-style
  (report.s3_results || []).forEach(s => addRow("S3", s.bucket || "", s.public ? "Public" : "Not public"));
  (report.sg_results || []).forEach(sg => addRow("SecurityGroup", sg.security_group || "", sg.open_to_world ? `Port ${sg.port}` : "OK"));
  (report.cloudtrail_results || []).forEach(ct => addRow("CloudTrail", ct.trail || "log_groups", JSON.stringify(ct)));
}

// ------------------ Mock loader ------------------
async function loadMock() {
  setStatus("Loading mock data..."); showSpinner(true); toggleButtons(true);
  try {
    // try issues mock, then simple, then github fallbacks
    let r = await fetchWithTimeout(ISSUES_MOCK, {}, 8000).catch(()=>null);
    if (r && r.ok) { renderReport(await r.json()); setStatus("Mock (issues) loaded", "ok"); return; }
    r = await fetchWithTimeout(LOCAL_MOCK, {}, 8000).catch(()=>null);
    if (r && r.ok) { renderReport(await r.json()); setStatus("Mock loaded", "ok"); return; }
    r = await fetchWithTimeout(GITHUB_RAW_BASE + "/report_issues.json", {}, 10000).catch(()=>null);
    if (r && r.ok) { renderReport(await r.json()); setStatus("Mock loaded (github)", "ok"); return; }
    r = await fetchWithTimeout(GITHUB_RAW_BASE + "/sample_scan.json", {}, 10000).catch(()=>null);
    if (r && r.ok) { renderReport(await r.json()); setStatus("Mock loaded (github simple)", "ok"); return; }
    throw new Error("No mock available");
  } catch (e) {
    setStatus("Mock load error: " + e.message, "error"); alert("Mock load error: " + e.message);
  } finally { showSpinner(false); toggleButtons(false); }
}

// ------------------ History (server & guest) ------------------
async function fetchHistory() {
  if (isGuest) return showGuestHistory();
  if (!token) { alert("Login to view history"); return; }
  setStatus("Loading history..."); showSpinner(true);
  try {
    const j = await getJSON("/history");
    if (!j.ok) { setStatus("History fetch error", "error"); alert("History error: " + JSON.stringify(j)); return; }
    renderHistoryList(j.scans || []);
    setStatus("History loaded", "ok");
  } catch (e) {
    setStatus("History fetch error: " + e.message, "error"); alert("History fetch error: " + e);
  } finally { showSpinner(false); }
}

function renderHistoryList(scans) {
  const wrap = $("historyList");
  wrap.innerHTML = "";
  scans.forEach(s => {
    const d = document.createElement("div");
    d.style.padding = "8px";
    d.style.borderBottom = "1px dashed rgba(255,255,255,0.03)";
    d.innerHTML = `<div style="font-weight:700">${s.timestamp} (${s.region})</div><div style="color:var(--muted)">${escapeHtml(JSON.stringify(s.summary))}</div><div style="margin-top:6px"><button data-id="${s.id}" class="btn secondary">View</button></div>`;
    wrap.appendChild(d);
  });
  wrap.querySelectorAll("button[data-id]").forEach(b => {
    b.onclick = async (ev) => {
      const id = ev.currentTarget.getAttribute("data-id");
      await viewScan(id);
    };
  });
  $("historyWrap").style.display = "block";
}

function showGuestHistory() {
  const wrap = $("historyList");
  wrap.innerHTML = "";
  guestHistory.forEach((h, i) => {
    const d = document.createElement("div");
    d.style.padding = "8px";
    d.style.borderBottom = "1px dashed rgba(255,255,255,0.03)";
    d.innerHTML = `<div style="font-weight:700">${h.timestamp} (${h.region})</div><div style="color:var(--muted)">${escapeHtml(JSON.stringify(h.summary))}</div><div style="margin-top:6px"><button data-id="${i}" class="btn secondary">View</button></div>`;
    wrap.appendChild(d);
  });
  wrap.querySelectorAll("button[data-id]").forEach(b => {
    b.onclick = (ev) => {
      const i = Number(ev.currentTarget.getAttribute("data-id"));
      renderReport(guestHistory[i].report);
      setStatus("Loaded guest scan", "ok");
    };
  });
  $("historyWrap").style.display = "block";
}

// Load a saved scan (server)
async function viewScan(id) {
  setStatus("Loading saved scan..."); showSpinner(true);
  try {
    const j = await getJSON(`/history/${id}`);
    if (!j.ok) { setStatus("Failed to load scan", "error"); alert("Error: " + JSON.stringify(j)); return; }
    renderReport(j.scan.report || {});
    setStatus("Loaded saved scan", "ok");
  } catch (e) {
    setStatus("Error loading saved scan: " + e.message, "error"); alert("Error loading saved scan: " + e);
  } finally { showSpinner(false); }
}

// ------------------ Remediation dry-run ------------------
async function showRemediation(issueId) {
  if (!confirm("Open remediation dry-run for: " + issueId + " ?")) return;
  setStatus("Fetching remediation plan...");
  showSpinner(true);
  try {
    const ak = $("access_key").value.trim();
    const sk = $("secret_key").value.trim();
    const region = $("region").value.trim() || "us-east-1";
    const res = await postJSON("/remediate", { access_key: ak, secret_key: sk, region, issue_id: issueId, confirm: false }, 20000);
    if (res.ok) alert("Dry-run plan:\n\n" + JSON.stringify(res.remediation || res, null, 2));
    else alert("Remediation error: " + JSON.stringify(res));
    setStatus("Remediation plan retrieved", "ok");
  } catch (e) {
    setStatus("Remediation error: " + e.message, "error"); alert("Remediation error: " + e.message);
  } finally { showSpinner(false); }
}

// ------------------ CSV export ------------------
function exportCSV() {
  const rows = [["Type","Name","Detail"]];
  document.querySelectorAll("#results tbody tr").forEach(tr => {
    const cells = Array.from(tr.querySelectorAll("td")).map(td => td.textContent.replace(/"/g,'""'));
    rows.push(cells);
  });
  if (rows.length === 1) { setStatus("No rows to export", "error"); return; }
  const csv = rows.map(r => `"${r.join('","')}"`).join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `bytebloom_report_${new Date().toISOString().slice(0,19).replace(/[:T]/g,'-')}.csv`;
  a.click();
  setStatus("CSV exported", "ok");
}

// ------------------ Init & wire up ------------------
document.addEventListener("DOMContentLoaded", () => {
  // Auth buttons
  if ($("btnRegister")) $("btnRegister").addEventListener("click", onRegister);
  if ($("btnLogin")) $("btnLogin").addEventListener("click", onLogin);
  if ($("btnGuest")) $("btnGuest").addEventListener("click", onGuestLogin);
  if ($("btnLogout")) $("btnLogout").addEventListener("click", onLogout);

  // Scan buttons
  if ($("btnTest")) $("btnTest").addEventListener("click", onTestKeys);
  if ($("btnScan")) $("btnScan").addEventListener("click", onRunScan);
  if ($("btnMock")) $("btnMock").addEventListener("click", loadMock);
  if ($("exportCsv")) $("exportCsv").addEventListener("click", exportCSV);

  // History
  if ($("btnShowHistory")) $("btnShowHistory").addEventListener("click", fetchHistory);

  // Load persisted guest data if any
  guestHistory = JSON.parse(localStorage.getItem("bb_guest_history") || "[]");
  if (localStorage.getItem("bb_token")) {
    token = localStorage.getItem("bb_token");
    currentUser = localStorage.getItem("bb_user") || "";
    isGuest = (currentUser === "guest");
  } else {
    isGuest = false;
  }
  setAuthUI();
});




