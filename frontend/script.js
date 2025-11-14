// frontend/script.js
// Full client logic: auth, scan, history, mock, export

// ✅ YOUR BACKEND URL (REPLACED)
const API_BASE = "https://byte-bloom-cloud-scanner.onrender.com";

const LOCAL_MOCK = "/mock/sample_scan.json";
const ISSUES_MOCK = "/mock/report_issues.json";
const GITHUB_RAW_BASE = "https://raw.githubusercontent.com/bharathakn49-dev/byte-bloom-cloud-scanner/main/frontend/mock";

const $ = id => document.getElementById(id);
const tbody = document.querySelector("#results tbody");
const statusEl = $("status");
const spinner = $("spinner");

let token = localStorage.getItem("bb_token") || "";
let currentUser = localStorage.getItem("bb_user") || "";

function showSpinner(on=true){ spinner.style.display = on ? "block" : "none"; }
function setStatus(txt, tone="info"){ 
  statusEl.textContent = txt;
  statusEl.style.color = 
    tone === "error" ? "var(--danger)" :
    tone === "ok" ? "var(--success)" :
    "var(--muted)";
}
function authHeaders(){ return token ? {"Authorization": "Bearer " + token} : {}; }

function escapeHtml(s){ return String(s || "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"); }
function clearResults(){ tbody.innerHTML = ""; }
function addRow(type, name, detail){
  const tr = document.createElement("tr");
  tr.innerHTML = `
    <td><span class="badge">${escapeHtml(type)}</span></td>
    <td><strong>${escapeHtml(name)}</strong></td>
    <td><div style="font-size:13px;color:var(--muted)">${escapeHtml(detail)}</div></td>`;
  tbody.appendChild(tr);
}

async function fetchWithTimeout(url, opts={}, timeout=25000){
  const ac = new AbortController(); 
  const id = setTimeout(()=>ac.abort(), timeout);
  try{
    const res = await fetch(url, {...opts, signal: ac.signal});
    clearTimeout(id);
    return res;
  } catch(e){
    clearTimeout(id);
    throw e;
  }
}

function toggleButtons(disabled){
  ["btnTest","btnScan","btnMock","exportCsv","btnRegister","btnLogin"]
    .forEach(id=>{ const el=$(id); if(el) el.disabled=disabled; });
}

async function postJSON(path, body, timeout=25000){
  const res = await fetchWithTimeout(API_BASE + path, {
    method:"POST",
    headers:{"Content-Type":"application/json", ...authHeaders()},
    body: JSON.stringify(body)
  }, timeout);
  const txt = await res.text();
  try{ return JSON.parse(txt); } 
  catch(e){ throw new Error(`Invalid JSON: ${txt}`); }
}

async function getJSON(path, timeout=20000){
  const res = await fetchWithTimeout(API_BASE + path, {headers:authHeaders()}, timeout);
  const txt = await res.text();
  try{ return JSON.parse(txt); } 
  catch(e){ throw new Error(`Invalid JSON: ${txt}`); }
}

// ---------- AUTH ----------
async function onRegister(){
  const username = $("username").value;
  const pass = $("password").value;

  if(!username || !pass){ alert("Enter username & password"); return; }

  setStatus("Registering...");
  showSpinner(true); toggleButtons(true);

  try{
    const r = await postJSON("/auth/register", {username, password:pass});
    if(r.ok){
      token = r.token;
      currentUser = username;
      localStorage.setItem("bb_token", token);
      localStorage.setItem("bb_user", currentUser);
      setAuthUI();
      setStatus("Registered & logged in", "ok");
    } else {
      setStatus("Register failed", "error");
      alert(r.error);
    }
  } catch(e){
    setStatus("Register error: "+e.message,"error");
  }
  showSpinner(false); toggleButtons(false);
}

async function onLogin(){
  const username = $("username").value;
  const pass = $("password").value;

  if(!username || !pass){ alert("Enter username & password"); return; }

  setStatus("Logging in...");
  showSpinner(true); toggleButtons(true);

  try{
    const r = await postJSON("/auth/login", {username, password:pass});
    if(r.ok){
      token = r.token;
      currentUser = username;
      localStorage.setItem("bb_token", token);
      localStorage.setItem("bb_user", currentUser);
      setAuthUI();
      setStatus("Logged in", "ok");
    } else {
      alert("Login failed");
      setStatus("Login failed","error");
    }
  } catch(e){
    setStatus("Login error: "+e.message,"error");
  }
  showSpinner(false); toggleButtons(false);
}

function onLogout(){
  token = "";
  currentUser = "";
  localStorage.removeItem("bb_token");
  localStorage.removeItem("bb_user");
  setAuthUI();
  setStatus("Logged out","info");
}

function setAuthUI(){
  const info = $("loggedInInfo");
  const who = $("whoami");
  const logout = $("btnLogout");
  const login = $("btnLogin");
  const reg = $("btnRegister");

  if(token){
    info.style.display="block";
    who.textContent=currentUser;
    logout.style.display="inline-block";
    login.style.display="none";
    reg.style.display="none";
  } else {
    info.style.display="none";
    logout.style.display="none";
    login.style.display="inline-block";
    reg.style.display="inline-block";
  }
}

// ---------- SCAN ----------
async function onTestKeys(){
  const ak = $("access_key").value.trim();
  const sk = $("secret_key").value.trim();
  const region = $("region").value.trim() || "us-east-1";

  if(!ak || !sk){ alert("Enter keys first"); return; }

  setStatus("Testing keys...");
  showSpinner(true); toggleButtons(true);

  try{
    const r = await postJSON("/keys/test", {access_key:ak, secret_key:sk, region});
    if(r.ok){
      setStatus("Keys valid","ok");
      alert("Summary:\n"+JSON.stringify(r.summary,null,2));
    } else {
      setStatus("Key test failed","error");
      alert(JSON.stringify(r));
    }
  } catch(e){
    setStatus("Key test error: "+e.message,"error");
  }
  showSpinner(false); toggleButtons(false);
}

async function onRunScan(){
  const ak = $("access_key").value.trim();
  const sk = $("secret_key").value.trim();
  const region = $("region").value.trim() || "us-east-1";

  if(!token){
    if(!confirm("You are not logged in. Scan won't be saved. Continue?")) return;
  }

  if(!ak || !sk){
    if(confirm("No keys given. Load mock instead?")) return loadMock();
    return;
  }

  setStatus("Running scan...");
  showSpinner(true); toggleButtons(true);

  try{
    const r = await postJSON("/scan", {access_key:ak, secret_key:sk, region}, 40000);
    if(!r.ok){
      setStatus("Scan failed","error");
      alert(JSON.stringify(r));
    } else {
      renderReport(r.report);
      setStatus("Scan complete","ok");
    }
  } catch(e){
    setStatus("Scan error: "+e.message,"error");
  }
  showSpinner(false); toggleButtons(false);
}

function renderReport(report){
  clearResults();
  if(report.issues){
    report.issues.forEach(i => {
      addRow(i.resource?.split(":")[0] || "misc", i.title, `${i.severity} — ${JSON.stringify(i.details)}`);
    });
  } else {
    (report.s3_results||[]).forEach(s => addRow("S3", s.bucket, s.public?"Public":"Not public"));
    (report.sg_results||[]).forEach(s => addRow("SecurityGroup", s.security_group, s.open_to_world?`Port ${s.port}`:"OK"));
    (report.cloudtrail_results||[]).forEach(c => addRow("CloudTrail","log group",JSON.stringify(c)));
  }
}

// ---------- MOCK ----------
async function loadMock(){
  setStatus("Loading mock...");
  showSpinner(true); toggleButtons(true);

  try{
    let r = await fetchWithTimeout(ISSUES_MOCK).catch(()=>null);
    if(r?.ok){ renderReport(await r.json()); setStatus("Issues mock loaded","ok"); return; }

    r = await fetchWithTimeout(LOCAL_MOCK).catch(()=>null);
    if(r?.ok){ renderReport(await r.json()); setStatus("Sample mock loaded","ok"); return; }

    r = await fetchWithTimeout(GITHUB_RAW_BASE + "/report_issues.json").catch(()=>null);
    if(r?.ok){ renderReport(await r.json()); setStatus("Github mock loaded","ok"); return; }

    throw new Error("No mock available");

  } catch(e){
    setStatus("Mock load error: "+e.message,"error");
  }
  showSpinner(false); toggleButtons(false);
}

// ---------- HISTORY ----------
async function fetchHistory(){
  if(!token){ alert("Login first"); return; }

  setStatus("Loading history...");
  showSpinner(true);

  try{
    const j = await getJSON("/history");
    if(!j.ok){ setStatus("History error","error"); return; }

    const wrap = $("historyList"); 
    wrap.innerHTML = "";

    j.history.forEach(s=>{
      const d = document.createElement("div");
      d.style.padding="8px";
      d.style.borderBottom="1px dashed rgba(255,255,255,0.03)";
      d.innerHTML = `
        <div style="font-weight:700">${s.timestamp}</div>
        <div style="color:var(--muted)">${JSON.stringify(s.summary)}</div>
        <div style="margin-top:6px">
          <button data-id="${s.id}" class="btn secondary">View</button>
        </div>`;
      wrap.appendChild(d);
    });

    $("historyWrap").style.display="block";

    wrap.querySelectorAll("button[data-id]").forEach(btn=>{
      btn.onclick = async () => {
        const id = btn.dataset.id;
        const j2 = await getJSON(`/history/${id}`);
        if(j2.ok){ renderReport(j2.report); setStatus("Loaded saved scan","ok"); }
      };
    });

    setStatus("History loaded","ok");

  } catch(e){
    setStatus("History error: "+e.message,"error");
  }
  showSpinner(false);
}

function exportCSV(){
  const rows = [["Type","Name","Detail"]];
  document.querySelectorAll("#results tbody tr").forEach(tr=>{
    const cells = [...tr.querySelectorAll("td")].map(td=>td.textContent.replace(/"/g,'""'));
    rows.push(cells);
  });

  if(rows.length === 1){ setStatus("Nothing to export","error"); return; }

  const csv = rows.map(r=>`"${r.join('","')}"`).join("\n");
  const blob = new Blob([csv], {type:"text/csv"});
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "scan_report.csv";
  a.click();
  setStatus("CSV exported","ok");
}

document.addEventListener("DOMContentLoaded", ()=>{
  $("btnRegister").onclick = onRegister;
  $("btnLogin").onclick = onLogin;
  $("btnLogout").onclick = onLogout;

  $("btnTest").onclick = onTestKeys;
  $("btnScan").onclick = onRunScan;
  $("btnMock").onclick = loadMock;
  $("exportCsv").onclick = exportCSV;
  $("btnShowHistory").onclick = fetchHistory;

  setAuthUI();
});


