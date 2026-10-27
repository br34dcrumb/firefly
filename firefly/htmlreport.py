"""A single self-contained HTML report (no network, no external assets).

The scan data is embedded as JSON and rendered client-side with vanilla JS, so
the file works offline, from `file://`, and when emailed as an attachment.
Everything in the report is already redacted, so embedding it is safe.
"""

from __future__ import annotations

import json
from typing import Any

from firefly import __version__
from firefly.report import to_dict

_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Firefly report &mdash; __TITLE__</title>
<style>
:root {
  --bg: #0f1117; --panel: #181b24; --panel2: #1f2330; --text: #e6e8ee; --muted: #9aa0b0;
  --border: #2a2f3d; --accent: #ffb020;
  --critical: #ff4d4f; --high: #ff7a45; --medium: #faad14; --low: #40a9ff; --info: #8c8c8c;
}
@media (prefers-color-scheme: light) {
  :root { --bg:#f6f7f9; --panel:#fff; --panel2:#f0f2f5; --text:#1b1f27; --muted:#5a6072; --border:#dfe3ea; }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); font: 14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; }
header { padding: 20px 24px; border-bottom: 1px solid var(--border); }
h1 { margin: 0 0 4px; font-size: 20px; }
h1 .fly { color: var(--accent); }
.meta { color: var(--muted); font-size: 12px; word-break: break-all; }
.wrap { padding: 20px 24px; max-width: 1200px; margin: 0 auto; }
.cards { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 20px; }
.card { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 12px 16px; min-width: 96px; }
.card .n { font-size: 24px; font-weight: 700; }
.card .l { font-size: 11px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); }
.sev-critical { color: var(--critical); } .sev-high { color: var(--high); }
.sev-medium { color: var(--medium); } .sev-low { color: var(--low); } .sev-info { color: var(--info); }
section { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 20px; }
section > h2 { margin: 0; padding: 12px 16px; font-size: 14px; border-bottom: 1px solid var(--border); }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 8px 16px; border-bottom: 1px solid var(--border); vertical-align: top; }
th { font-size: 11px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); }
tr:last-child td { border-bottom: none; }
.badge { display: inline-block; padding: 1px 7px; border-radius: 10px; font-size: 11px; font-weight: 600; color: #fff; }
.b-critical { background: var(--critical); } .b-high { background: var(--high); }
.b-medium { background: var(--medium); color:#1b1f27; } .b-low { background: var(--low); } .b-info { background: var(--info); }
.controls { display: flex; flex-wrap: wrap; gap: 8px 14px; padding: 12px 16px; align-items: center; border-bottom: 1px solid var(--border); }
.controls label { font-size: 12px; color: var(--muted); display: inline-flex; gap: 4px; align-items: center; }
input[type=search], select { background: var(--panel2); color: var(--text); border: 1px solid var(--border); border-radius: 6px; padding: 5px 8px; font: inherit; }
.finding { border-bottom: 1px solid var(--border); }
.finding summary { padding: 8px 16px; cursor: pointer; display: grid; grid-template-columns: 78px 52px 1fr; gap: 10px; align-items: center; }
.finding summary::-webkit-details-marker { display: none; }
.finding .ttl { font-weight: 500; }
.finding .path { color: var(--muted); font-size: 12px; font-family: ui-monospace,Menlo,Consolas,monospace; }
.finding .body { padding: 4px 16px 14px 16px; color: var(--muted); }
.finding .body code, .kv { font-family: ui-monospace,Menlo,Consolas,monospace; font-size: 12px; }
.finding .body .ev { background: var(--panel2); border: 1px solid var(--border); border-radius: 6px; padding: 6px 8px; display: inline-block; margin-top: 4px; color: var(--text); }
.score { font-family: ui-monospace,Menlo,Consolas,monospace; font-size: 12px; color: var(--muted); }
.conf { font-size: 11px; color: var(--muted); }
a { color: var(--low); }
.hidden { display: none !important; }
.empty { padding: 16px; color: var(--muted); }
.note { padding: 10px 16px; color: var(--muted); font-size: 12px; }
</style>
</head>
<body>
<header>
  <h1><span class="fly">&#9733;</span> Firefly report</h1>
  <div class="meta" id="meta"></div>
</header>
<div class="wrap">
  <div class="cards" id="cards"></div>

  <section id="comp-section">
    <h2>Components</h2>
    <div id="components"></div>
  </section>

  <section>
    <h2>Findings</h2>
    <div class="controls">
      <input type="search" id="q" placeholder="Filter by text&hellip;" style="flex:1;min-width:160px">
      <label>Analyzer <select id="fa"><option value="">all</option></select></label>
      <label>Min severity <select id="fs">
        <option value="0">info</option><option value="1">low</option>
        <option value="2" selected>medium</option><option value="3">high</option><option value="4">critical</option>
      </select></label>
      <label><input type="checkbox" id="fc"> hide low-confidence</label>
    </div>
    <div id="findings"></div>
    <div class="note" id="count"></div>
  </section>
  <div class="meta">Generated by Firefly __VERSION__ &middot; all values redacted where applicable</div>
</div>
<script id="data" type="application/json">__DATA__</script>
<script>
const SEV = {critical:4, high:3, medium:2, low:1, info:0};
const CONF = {low:0, medium:1, high:2};
const data = JSON.parse(document.getElementById('data').textContent);
const esc = s => String(s==null?'':s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

document.getElementById('meta').innerHTML =
  esc(data.input.path) + '<br>sha256 ' + esc(data.input.sha256 || 'n/a') +
  ' &middot; scanned ' + esc(data.finished || data.started || '');

const counts = {critical:0,high:0,medium:0,low:0,info:0};
data.findings.forEach(f => counts[f.severity] = (counts[f.severity]||0)+1);
document.getElementById('cards').innerHTML =
  Object.keys(SEV).reverse().map(s =>
    `<div class="card"><div class="n sev-${s}">${counts[s]||0}</div><div class="l">${s}</div></div>`
  ).join('') +
  `<div class="card"><div class="n">${(data.components||[]).length}</div><div class="l">components</div></div>`;

// components table
const comps = data.components||[];
if (comps.length) {
  const cveByComp = {};
  data.findings.filter(f=>f.metadata&&f.metadata.component).forEach(f=>{
    const c=f.metadata.component, k=(c.vendor||'')+'|'+c.product+'|'+c.version;
    (cveByComp[k]=cveByComp[k]||{n:0,kev:0,worst:'info'});
    cveByComp[k].n++; if(f.metadata.kev)cveByComp[k].kev++;
    if(SEV[f.severity]>SEV[cveByComp[k].worst])cveByComp[k].worst=f.severity;
  });
  document.getElementById('components').innerHTML =
    '<table><tr><th>Component</th><th>Version</th><th>CVEs</th><th>Found in</th></tr>' +
    comps.map(c=>{
      const k=(c.vendor||'')+'|'+c.product+'|'+c.version, cv=cveByComp[k];
      const name = (c.vendor && c.vendor!==c.product)? esc(c.vendor)+':'+esc(c.product) : esc(c.product);
      const cves = cv? `<span class="sev-${cv.worst}">${cv.n}</span>`+(cv.kev?` <b class="sev-critical">${cv.kev} KEV</b>`:'') : '';
      const where = esc(c.paths&&c.paths[0]||'') + (c.paths&&c.paths.length>1?` (+${c.paths.length-1})`:'');
      return `<tr><td>${name}</td><td class="kv">${esc(c.version)}</td><td>${cves}</td><td class="path">${where}</td></tr>`;
    }).join('') + '</table>';
} else {
  document.getElementById('comp-section').classList.add('hidden');
}

// findings
const analyzers = [...new Set(data.findings.map(f=>f.analyzer))].sort();
document.getElementById('fa').innerHTML = '<option value="">all</option>' +
  analyzers.map(a=>`<option value="${esc(a)}">${esc(a)}</option>`).join('');

function render() {
  const q = document.getElementById('q').value.toLowerCase();
  const fa = document.getElementById('fa').value;
  const fs = +document.getElementById('fs').value;
  const fc = document.getElementById('fc').checked;
  let shown = 0;
  const html = data.findings.filter(f => {
    if (SEV[f.severity] < fs) return false;
    if (fa && f.analyzer !== fa) return false;
    if (fc && CONF[f.confidence]<1) return false;
    if (q && !((f.title+' '+(f.description||'')+' '+(f.path||'')+' '+(f.metadata&&f.metadata.cve||'')).toLowerCase().includes(q))) return false;
    return true;
  }).map(f => {
    shown++;
    const md = f.metadata||{};
    const score = (typeof md.cvss_score==='number')? md.cvss_score.toFixed(1):'';
    const reasons = (md.confidence_reasons||[]).map(r=>'<li>'+esc(r)+'</li>').join('');
    const url = md.url? `<p><a href="${esc(md.url)}" target="_blank" rel="noopener">${esc(md.cve||md.url)}</a></p>`:'';
    return `<details class="finding"><summary>
        <span class="badge b-${f.severity}">${f.severity}</span>
        <span class="score">${score}</span>
        <span><span class="ttl">${esc(f.title)}</span>
          ${f.path?`<div class="path">${esc(f.path)}</div>`:''}</span>
      </summary><div class="body">
        <span class="conf">confidence: ${esc(f.confidence)} &middot; ${esc(f.analyzer)}</span>
        <p>${esc(f.description||'')}</p>
        ${f.evidence?`<div class="ev">${esc(f.evidence)}</div>`:''}
        ${reasons?`<p>Confidence notes:</p><ul>${reasons}</ul>`:''}
        ${url}
      </div></details>`;
  }).join('');
  document.getElementById('findings').innerHTML = html || '<div class="empty">No findings match the filter.</div>';
  document.getElementById('count').textContent = shown + ' of ' + data.findings.length + ' findings shown';
}
['q','fa','fs','fc'].forEach(id => document.getElementById(id).addEventListener('input', render));
render();
</script>
</body>
</html>
"""


def build(report: dict[str, Any]) -> str:
    title = report.get("input", {}).get("path", "firmware")
    # Safe JSON embedding inside a <script> element.
    payload = json.dumps(report, ensure_ascii=False).replace("</", "<\\/")
    return (
        _TEMPLATE.replace("__DATA__", payload)
        .replace("__TITLE__", _escape(str(title)))
        .replace("__VERSION__", _escape(__version__))
    )


def _escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def write_result(result, path: str) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(build(to_dict(result)))
    return path
