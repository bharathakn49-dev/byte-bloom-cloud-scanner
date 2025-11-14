// Replace with your render backend URL
const BACKEND = 'https://byte-bloom-cloud-scanner.onrender.com';

const $ = id => document.getElementById(id);
const tbody = document.querySelector('#results tbody');
const status = $('status');

function showStatus(txt, ok=true){
  status.textContent = txt;
  status.style.color = ok ? 'green' : 'red';
}

function clearResults(){ tbody.innerHTML = ''; }

function addRow(type,name,detail){
  const tr = document.createElement('tr');
  tr.innerHTML = `<td>${type}</td><td>${name}</td><td>${detail}</td>`;
  tbody.appendChild(tr);
}

async function postJSON(path, body){
  const res = await fetch(BACKEND + path, {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify(body)
  });
  return res.json();
}

$('btnTest').addEventListener('click', async ()=>{
  clearResults();
  const payload = {
    access_key: $('access_key').value.trim(),
    secret_key: $('secret_key').value.trim(),
    region: $('region').value.trim() || 'us-east-1'
  };
  showStatus('Testing keys...');
  try{
    const r = await postJSON('/keys/test', payload);
    if (r.ok){
      showStatus('Keys valid — summary loaded', true);
      addRow('Summary','s3_public_buckets',JSON.stringify(r.summary || {}));
    } else {
      showStatus('Keys test failed: ' + (r.error||JSON.stringify(r)), false);
    }
  }catch(e){
    showStatus('Network error: '+e, false);
  }
});

$('btnScan').addEventListener('click', async ()=>{
  clearResults();
  const payload = {
    access_key: $('access_key').value.trim(),
    secret_key: $('secret_key').value.trim(),
    region: $('region').value.trim() || 'us-east-1'
  };
  showStatus('Running scan — this may take a few seconds...');
  try{
    const r = await postJSON('/scan', payload);
    if (r.error){
      showStatus('Scan error: ' + r.error, false);
      return;
    }
    showStatus('Scan complete', true);
    // S3
    (r.s3_results||[]).forEach(s=> addRow('S3', s.bucket || '', s.public ? 'Public' : 'Not public'));
    // SG
    (r.sg_results||[]).forEach(sg=> addRow('SecurityGroup', sg.security_group || '', sg.open_to_world ? `Port ${sg.port}` : 'OK'));
    // Cloudtrail
    (r.cloudtrail_results||[]).forEach(ct => addRow('CloudTrail', 'log_groups', JSON.stringify(ct)));
  }catch(e){
    showStatus('Network error: '+e, false);
  }
});

// Mock button: load mock/sample_scan.json from repo (no keys)
$('btnMock').addEventListener('click', async ()=>{
  clearResults();
  showStatus('Loading mock data...');
  try{
    const r = await fetch('/mock/sample_scan.json').then(r=>r.json());
    (r.s3_results||[]).forEach(s=> addRow('S3', s.bucket || '', s.public ? 'Public' : 'Not public'));
    (r.sg_results||[]).forEach(sg=> addRow('SecurityGroup', sg.security_group || '', sg.open_to_world ? `Port ${sg.port}` : 'OK'));
    showStatus('Mock loaded', true);
  }catch(e){
    showStatus('Mock load error: '+e, false);
  }
});

// Export CSV (very simple)
$('exportCsv').addEventListener('click', ()=>{
  const rows = [['Type','Name','Detail']];
  document.querySelectorAll('#results tbody tr').forEach(tr=>{
    const cells = [...tr.querySelectorAll('td')].map(td=>td.textContent.replace(/"/g,'""'));
    rows.push(cells);
  });
  const csv = rows.map(r=>`"${r.join('","')}"`).join('\n');
  const blob = new Blob([csv],{type:'text/csv'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'scan_report.csv';
  a.click();
});
