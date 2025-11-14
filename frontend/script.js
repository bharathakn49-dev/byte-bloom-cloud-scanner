// frontend/script.js
// Full client logic: auth, scan, history, mock, export
const API_BASE = (location.hostname.includes("localhost") ? "http://localhost:5000" : "https://byte-bloom-cloud-scanner.onrender.com");
const LOCAL_MOCK = "/mock/sample_scan.json";
const ISSUES_MOCK = "/mock/report_issues.json";
const GITHUB_RAW_BASE = "https://raw.githubusercontent.com/bharathakn49-dev/byte-bloom-cloud-scanner/main/frontend/mock";

const $ = id => document.getElementById(id);
const tbody = document.querySelector("#results tbody");
const statusEl = $("status");
const spinner = $("spinner");

let token = localStorage.getItem("bb_token") || "";
let currentUser = localStorage.getItem("bb_user") || "";

function showSpinner(on=true){ if(!spinner) return; spinner.style.display = on ? "block" : "none"; }
function setStatus(txt, tone="info"){ if(!statusEl) return; statusEl.textContent = txt; statusEl.style.color = tone === "error" ? "var(--danger)" : (tone === "ok" ? "var(--success)" : "var(--muted)"); }
function authHeaders(){ return token ? {"Authorization": "Bearer " + token} : {}; }

function escapeHtml(s){ return String(s || "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"); }
function clearResults(){ if(tbody) tbody.innerHTML = ""; }
function addRow(type, name, detail){ if(!tbody) return; const tr = document.createElement("tr"); tr.innerHTML = `<td><span class="badge">${escapeHtml(type)}</span></td><td><strong>${escapeHtml(name)}</strong></td><td><div style="font-size:13px;color:var(--muted)">${escapeHtml(detail)}</div></td>`; tbody.appendChild(tr); }

async function fetchWithTimeout(url, opts={}, timeout=25000){ const ac = new AbortController(); const id = setTimeout(()=>ac.abort(), timeout); try{ const res = await fetch(url, {...opts, signal: ac.signal}); clearTimeout(id); return res; } catch(e){ clearTimeout(id); throw e; } }

function toggleButtons(disabled){ ["btnTest","btnScan","btnMock","exportCsv","btnRegister","btnLogin"].forEach(id=>{ const el=document.getElementById(id); if(el) el.disabled = disabled; }); }

async function postJSON(path, body, timeout=25000){ const url = API_BASE + path; const headers = {"Content-Type": "application/json", ...authHeaders()}; const res = await fetchWithTimeout(url, {method:"POST", headers, body: JSON.stringify(body)}, timeout); const txt = await res.text(); try { return JSON.parse(txt); } catch(e){ throw new Error(`Invalid JSON (${res.status}): ${txt}`); } }

async function getJSON(path, timeout=20000){ const url = API_BASE + path; const headers = {...authHeaders()}; const res = await fetchWithTimeout(url, {headers}, timeout); const txt = await res.text(); try { return JSON.parse(txt); } catch(e){ throw new Error(`Invalid JSON (${res.status}): ${txt}`); } }

// ---------- AUTH ----------
async function onRegister(){
  const username = $("username").value || $("username").value;
  const pass = $("password").value;
  if(!username || !pass){ alert("Enter username & password"); return; }
  setStatus("Registering...");
  showSpinner(true); toggleButtons(true);
  try {
    const res = await postJSON("/auth/register", {username, password: pass}, 20000);
    if(res.ok){ token = res.token; currentUser = res.username; localStorage.setItem("bb_token", token); localStorage.setItem("bb_user", currentUser); setAuthUI(); setStatus("Registered & logged in", "ok"); }
    else { setStatus("Register failed: " + (res.error||""), "error"); alert("Register error: "+JSON.stringify(res)); }
  } catch(e){ setStatus("Register error: " + e.message, "error"); alert("Register error: " + e.message); }
  finally{ showSpinner(false); toggleButtons(false); }
}

async function onLogin(){
  const username = $("username").value;
  const pass = $("password").value;
  if(!username || !pass){ alert("Enter username & password"); return; }
  setStatus("Logging in...");
  showSpinner(true); toggleButtons(true);
  try {
    const res = await postJSON("/auth/login", {username, password: pass}, 15000);
    if(res.ok){ token = res.token; currentUser = res.username; localStorage.setItem("bb_token", token); localStorage.setItem("bb_user", currentUser); setAuthUI(); setStatus("Logged in", "ok"); }
    else { setStatus("Login failed", "error"); alert("Login error: " + JSON.stringify(res)); }
  } catch(e){ setStatus("Login error: " + e.message, "error"); alert("Login error: " + e.message); }
  finally{ showSpinner(false); toggleButtons(false); }
}

function onLogout(){
  token = ""; currentUser = ""; localStorage.removeItem("bb_token"); localStorage.removeItem("bb_user"); setAuthUI(); setStatus("Logged out", "info");
}

function setAuthUI(){
  const loggedWrap = $("loggedInInfo");
  const who = $("whoami");
  const logout = $("btnLogout");
  const loginBtn = $("btnLogin");
  const regBtn = $("btnRegister");
  if(token){
    if(loggedWrap){ loggedWrap.style.display = "block"; who.textContent = currentUser || "user"; }
    if(logout){ logout.style.display = "inline-block"; logout.onclick = onLogout; }
    if(loginBtn) loginBtn.style.display = "none";
    if(regBtn) regBtn.style.display = "none";
  } else {
    if(loggedWrap) loggedWrap.style.display = "none";
    if(logout) logout.style.display = "none";
    if(loginBtn) loginBtn.style.display = "inline-block";
    if(regBtn) regBtn.style.display = "inline-block";
  }
}

// ---------- SCAN ----------
async function onTestKeys(){
  const ak = $("access_key").value.trim();
  const sk = $("secret_key").value.trim();
  const region = $("region").value.trim() || "us-east-1";
  if(!ak || !sk){ alert("Please enter keys or use mock data"); return; }
  setStatus("Testing keys...");
  showSpinner(true); toggleButtons(true);
  try {
    const res = await fetchWithTimeout(API_BASE + "/keys/test", {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({access_key: ak, secret_key: sk, region})}, 20000);
    const j = await res.json();
    if(j.ok){ setStatus("Key test OK", "ok"); alert("Key test summary:\n" + JSON.stringify(j.summary || {}, null,2)); }
    else { setStatus("Key test failed", "error"); alert("Key test failed: " + JSON.stringify(j)); }
  } catch(e){ setStatus("Key test error: " + e.message, "error"); alert("Key test error: " + e); }
  finally { showSpinner(false); toggleButtons(false); }
}

async function onRunScan(){
  if(!token){ if(!confirm("You are not logged in. Scans will not be saved. Continue using mock data or enter keys?")) { return; } }
  const ak = $("access_key").value.trim();
  const sk = $("secret_key").value.trim();
  const region = $("region").value.trim() || "us-east-1";
  if(!ak || !sk){ if(confirm("No keys — load mock instead?")) { await loadMock(); } return; }
  setStatus("Running scan...");
  showSpinner(true); toggleButtons(true);
  try {
    const res = await fetchWithTimeout(API_BASE + "/scan", { method:"POST", headers: {"Content-Type":"application/json", ...authHeaders()}, body: JSON.stringify({access_key: ak, secret_key: sk, region}) }, 40000);
    const j = await res.json();
    if(!j.ok){ setStatus("Scan failed: " + (j.error||""), "error"); alert("Scan failed: " + JSON.stringify(j)); }
    else {
      const report = j.report || {};
      renderReport(report);
      setStatus("Scan complete and saved", "ok");
    }
  } catch(e){ setStatus("Scan error: " + (e.name==="AbortError" ? "timeout" : e.message), "error"); alert("Scan error: " + e); }
  finally{ showSpinner(false); toggleButtons(false); }
}

function renderReport(report){
  clearResults();
  if(report.issues){
    report.issues.forEach(issue => addRow((issue.resource||"").split(":")[0] || "misc", issue.title || issue.id, (issue.severity || "") + " — " + JSON.stringify(issue.details || {})));
  } else {
    (report.s3_results||[]).forEach(s => addRow("S3", s.bucket || "", s.public ? "Public" : "Not public"));
    (report.sg_results||[]).forEach(sg => addRow("SecurityGroup", sg.security_group || "", sg.open_to_world ? `Port ${sg.port}` : "OK"));
    (report.cloudtrail_results||[]).forEach(ct => addRow("CloudTrail", ct.trail || "log_groups", JSON.stringify(ct)));
  }
}

// ---------- MOCK ----------
async function loadMock(){
  setStatus("Loading mock data...");
  showSpinner(true); toggleButtons(true);
  try {
    let r = await fetchWithTimeout(ISSUES_MOCK, {}, 8000).catch(()=>null);
    if(r && r.ok){ renderReport(await r.json()); setStatus("Mock (issues) loaded", "ok"); return; }
    r = await fetchWithTimeout(LOCAL_MOCK, {}, 8000).catch(()=>null);
    if(r && r.ok){ renderReport(await r.json()); setStatus("Mock loaded", "ok"); return; }
    r = await fetchWithTimeout(GITHUB_RAW_BASE + "/report_issues.json", {}, 10000).catch(()=>null);
    if(r && r.ok){ renderReport(await r.json()); setStatus("Mock loaded (github)", "ok"); return; }
    throw new Error("No mock available");
  } catch(e){ setStatus("Mock error: " + e.message, "error"); alert("Mock error: " + e.message); }
  finally{ showSpinner(false); toggleButtons(false); }
}

// ---------- HISTORY ----------
async function fetchHistory(){
  if(!token){ alert("Login to view history"); return; }
  setStatus("Loading history...");
  showSpinner(true);
  try{
    const j = await getJSON("/history");
    if(!j.ok){ setStatus("History fetch error", "error"); alert("History error: " + JSON.stringify(j)); return; }
    const wrap = $("historyList"); wrap.innerHTML = "";
    (j.scans || []).forEach(s => {
      const d = document.createElement("div");
      d.style.padding = "8px"; d.style.borderBottom = "1px dashed rgba(255,255,255,0.03)";
      d.innerHTML = `<div style="font-weight:700">${s.timestamp} (${s.region})</div><div style="color:var(--muted)">${JSON.stringify(s.summary)}</div><div style="margin-top:6px"><button data-id="${s.id}" class="btn secondary">View</button></div>`;
      wrap.appendChild(d);
    });
    wrap.querySelectorAll("button[data-id]").forEach(b=>{
      b.onclick = async (ev) => {
        const id = ev.currentTarget.getAttribute("data-id");
        await viewScan(id);
      };
    });
    $("historyWrap").style.display = "block";
    setStatus("H


