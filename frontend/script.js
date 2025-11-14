// frontend/script.js (improved)
// Replace with your render backend URL
const BACKEND = 'https://byte-bloom-cloud-scanner.onrender.com';

// small helper to timeout fetch (milliseconds)
async function fetchWithTimeout(resource, options = {}, timeout = 30000) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(resource, { ...options, signal: controller.signal });
    clearTimeout(id);
    return res;
  } catch (err) {
    clearTimeout(id);
    throw err;
  }
}

const $ = id => document.getElementById(id);
const tbody = document.querySelector('#results tbody');
const status = $('status');
const btnTest = $('btnTest');
const btnScan = $('btnScan');
const btnMock = $('btnMock');
const exportCsv = $('exportCsv');

function setButtonsDisabled(disabled){
  [btnTest, btnScan, btnMock, exportCsv].forEach(b => {
    if(b) b.disabled = disabled;
  });
}

function showStatus(txt, ok = true) {
  if (!status) return;
  status.textContent = txt;
  status.style.color = ok ? 'green' : 'red';
}

function showTemporary(msg, time = 2500) {
  const prev = status.textContent;
  showStatus(msg);
  setTimeout(() => showStatus(prev || ''), time);
}

function clearResults(){ if(tbody) tbody.innerHTML = ''; }

function addRow(type, name, detail){
  if(!tbody) return;
  const tr = document.createElement('tr');
  tr.innerHTML = `<td>${escapeHtml(type)}</td><td>${escapeHtml(name)}</td><td>${escapeHtml(detail)}</td>`;
  tbody.appendChild(tr);
}

function escapeHtml(s){
  if (s === null || s === undefined) return '';
  return String(s)
    .replaceAll('&','&amp;')
    .replaceAll('<','&lt;')
    .replaceAll('>','&gt;')
    .replaceAll('"','&quot;')
    .replaceAll("'",'&#039;');
}

async function postJSON(path, body){
  const url = BACKEND + path;
  const res = await fetchWithTimeout(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }, 30000);

  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch (e) {
    throw new Error(`Invalid JSON response (${res.status}): ${text}`);
  }
}

function validateKeys(ak, sk) {
  if (!ak || !sk) {
    showStatus('Please enter both Access Key and Secret Key.', false);
    return false;
  }
  return true;
}

// TEST KEYS
btnTest.addEventListener('click', async () => {
  clearResults();
  const payload = {
    access_key: $('access_key').value.trim(),
    secret_key: $('secret_key').value.trim(),
    region: $('region').value.trim() || 'us-east-1'
  };

  if (!validateKeys(payload.access_key, payload.secret_key)) return;

  setButtonsDisabled(true);
  showStatus('Testing keys...');
  try {
    const r = await postJSON('/keys/test', payload);
    if (r.ok) {
      showStatus('Keys valid — summary loaded', true);
      addRow('Summary','s3_public_buckets', JSON.stringify(r.summary || {}));
    } else {
      showStatus('Keys test failed: ' + (r.error || JSON.stringify(r)), false);
    }
  } catch (e) {
    const msg = e.name === 'AbortError' ? 'Request timed out' : `Network error: ${e.message}`;
    showStatus(msg, false);
  } finally {
    setButtonsDisabled(false);
  }
});

// RUN FULL SCAN
btnScan.addEventListener('click', async () => {
  clearResults();
  const payload = {
    access_key: $('access_key').value.trim(),
    secret_key: $('secret_key').value.trim(),
    region: $('region').value.trim() || 'us-east-1'
  };

  if (!validateKeys(payload.access_key, payload.secret_key)) return;

  setButtonsDisabled(true);
  showStatus('Running scan — this may take a few seconds...');
  try {
    const r = await postJSON('/scan', payload);
    if (r.error) {
      showStatus('Scan error: ' + r.error, false);
      return;
    }
    showStatus('Scan complete', true);

    (r.s3_results || []).forEach(s =>
      addRow('S3', s.bucket || '', s.public ? 'Public' : 'Not public')
    );

    (r.sg_results || []).forEach(sg =>
      addRow('SecurityGroup', sg.security_group || '', sg.open_to_world ? `Port ${sg.port}` : 'OK')
    );

    (r.cloudtrail_results || []).forEach(ct =>
      addRow('CloudTrail', 'log_groups', JSON.stringify(ct))
    );

    if (
      (r.s3_results || []).length === 0 &&
      (r.sg_results || []).length === 0 &&
      (r.cloudtrail_results || []).length === 0
    ) {
      showTemporary('Scan finished but no items found', 3000);
    }
  } catch (e) {
    const msg = e.name === 'AbortError' ? 'Scan timed out' : `Network error: ${e.message}`;
    showStatus(msg, false);
  } finally {
    setButtonsDisabled(false);
  }
});

// USE MOCK DATA
btnMock.addEventListener('click', async () => {
  clearResults();
  showStatus('Loading mock data...');
  setButtonsDisabled(true);

  const localPath = '/mock/sample_scan.json';
  const githubRaw =
    'https://raw.githubusercontent.com/bharathakn49-dev/byte-bloom-cloud-scanner/main/mock/sample_scan.json';

  try {
    let data;
    try {
      let r = await fetchWithTimeout(localPath, {}, 8000);
      if (!r.ok) throw new Error('local mock missing');
      data = await r.json();
    } catch (e) {
      const r2 = await fetchWithTimeout(githubRaw, {}, 8000);
      if (!r2.ok) throw new Error('GitHub mock missing');
      data = await r2.json();
    }

    (data.s3_results || []).forEach(s =>
      addRow('S3', s.bucket || '', s.public ? 'Public' : 'Not public')
    );

    (data.sg_results || []).forEach(sg =>
      addRow('SecurityGroup', sg.security_group || '', sg.open_to_world ? `Port ${sg.port}` : 'OK')
    );

    showStatus('Mock loaded', true);
  } catch (e) {
    const msg =
      e.name === 'AbortError' ? 'Mock fetch timed out' : `Mock load error: ${e.message}`;
    showStatus(msg, false);
  } finally {
    setButtonsDisabled(false);
  }
});

// EXPORT CSV
exportCsv.addEventListener('click', () => {
  const rows = [['Type','Name','Detail']];
  document.querySelectorAll('#results tbody tr').forEach(tr => {
    const cells = [...tr.querySelectorAll('td')].map(td =>
      td.textContent.replace(/"/g,'""')
    );
    rows.push(cells);
  });
  if (rows.length === 1) {
    showTemporary('No rows to export', 2000);
    return;
  }
  const csv = rows.map(r => `"${r.join('","')}"`).join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'scan_report.csv';
  a.click();
  showTemporary('CSV exported', 2000);
});

