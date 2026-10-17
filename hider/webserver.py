"""Local web UI for JSON obfuscation.

    python -m hider serve            # http://127.0.0.1:8790

Standard library only. Binds to loopback, serves one self-contained page with
no external scripts, fonts or CDNs, and sets a Content-Security-Policy that
forbids the page from talking to anything but this server. Obfuscation and
unmasking never reach a model. The one outbound path is step 3 ("Ask Claude
Code"), which hands only the obfuscated file and a masked prompt to a
restricted, tool-limited Claude Code run (see ``research.py``).

Each upload gets a fresh vault, so labels restart at 01 per file. Results are
also written to ``out/json/`` next to the repo.
"""

from __future__ import annotations

import html
import ipaddress
import json
import re
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from . import csvmerge, jsonscrub, localcfg, research

OUT = Path(__file__).resolve().parent.parent / "out" / "json"
MAX_BYTES = 256 * 1024 * 1024
_LOCK = threading.Lock()  # one scrub at a time: the classifier is shared
_JOBS: dict[str, dict] = {}  # Claude Code runs: id -> status / result / error

CSP = (
    "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
    "connect-src 'self'; img-src data:; form-action 'none'; base-uri 'none'"
)

PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hider JSON</title>
<style>
:root{--bg:#f6f7f9;--fg:#1b1f24;--mut:#5b6573;--card:#fff;--bd:#d9dee5;--ac:#1f6feb;--ok:#1a7f37;--bad:#cf222e;--hl:#fff3c4}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--mut:#8b949e;--card:#161b22;--bd:#30363d;--ac:#4493f8;--ok:#3fb950;--bad:#f85149;--hl:#4a3b00}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,system-ui,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px}
h1{font-size:20px;margin:0 0 4px}h2{font-size:16px;margin:0 0 4px}p.sub{color:var(--mut);margin:0 0 20px}.mut{color:var(--mut)}
.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:16px;margin-bottom:16px}
#drop{border:2px dashed var(--bd);border-radius:10px;padding:28px;text-align:center;color:var(--mut);cursor:pointer}
#drop.over{border-color:var(--ac);color:var(--fg)}
textarea{width:100%;min-height:120px;font:12px/1.4 ui-monospace,Menlo,monospace;background:var(--bg);color:var(--fg);border:1px solid var(--bd);border-radius:8px;padding:10px}
input,select{padding:8px;border:1px solid var(--bd);border-radius:8px;background:var(--bg);color:var(--fg);font:inherit;max-width:100%}
label{display:block;color:var(--mut);font-size:12px;margin:10px 0 4px}
.f{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:0 12px}.f input,.f select{width:100%}
button{background:var(--ac);color:#fff;border:0;border-radius:8px;padding:9px 16px;font-weight:600;cursor:pointer}
button.sec{background:transparent;color:var(--fg);border:1px solid var(--bd)}button:disabled{opacity:.5;cursor:default}
.row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:12px}
.pill{display:inline-block;border:1px solid var(--bd);border-radius:99px;padding:2px 10px;margin:2px;font-size:12px}
.ok{color:var(--ok)}.bad{color:var(--bad)}pre{overflow:auto;max-height:420px;margin:0;font:12px/1.4 ui-monospace,Menlo,monospace;white-space:pre-wrap;word-break:break-word}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.stat b{display:block;font-size:22px}.stat span{color:var(--mut);font-size:12px}
.step{display:inline-block;width:22px;height:22px;border-radius:50%;background:var(--ac);color:#fff;text-align:center;font-size:12px;line-height:22px;margin-right:6px}
code{font:12px ui-monospace,Menlo,monospace;background:var(--bg);border:1px solid var(--bd);border-radius:4px;padding:0 4px}
details summary{cursor:pointer;color:var(--mut);margin-top:10px}
</style></head><body><main>
<h1>Hider JSON obfuscator</h1>
<p class="sub">Obfuscation and unmasking run on this machine only (127.0.0.1). Only step 3 talks to a model, and it sends just the obfuscated file and a masked prompt.</p>

<div class="card">
  <h2><span class="step">1</span>Get the logs</h2>
  <p class="mut" style="margin:0">Fill in the session, copy the prompt, paste it into Claude Code. It downloads the CSV parts with Playwright and merges them locally, without reading the rows. The portal URL default comes from <code>hider.local.json</code>.</p>
  <div class="f">
    <div style="grid-column:1/-1"><label>Portal jobs page (<code>{region}</code> is filled in)</label><input id="gPortal" value="__PORTAL__" placeholder="https://admin-portal.example.com/{region}/backup/jobs"></div>
    <div><label>Region</label><select id="gRegion"><option>AMER</option><option>EMEA</option><option>APJ</option></select></div>
    <div><label>Backup server</label><input id="gServer" placeholder="Backup Server 01 (US)"></div>
    <div><label>Backup policy</label><input id="gPolicy" placeholder="PROD SharePoint Sites - Daily (Batch 1)"></div>
    <div><label>Tenant (optional)</label><input id="gTenant" placeholder="contoso.onmicrosoft.com"></div>
    <div><label>Session</label><input id="gSession" value="latest" placeholder="latest, or 08/12/2026 7:18:01 AM"></div>
    <div><label>Save into folder</label><input id="gDir"></div>
  </div>
  <label><input type="checkbox" id="gScrub" checked style="width:auto"> Also obfuscate it with the terms from step 2</label>
  <textarea id="gOut" readonly style="min-height:260px;margin-top:8px"></textarea>
  <div class="row"><button id="gCopy">Copy prompt</button><span id="gMsg" class="mut"></span></div>
</div>

<div class="card">
  <h2><span class="step">2</span>Obfuscate</h2>
  <div id="drop">Drop a .json / .jsonl file, or all the .csv parts of a session, or click to choose<input id="file" type="file" multiple accept=".json,.jsonl,.csv,application/json,text/csv" hidden></div>
  <label>or paste JSON:</label>
  <textarea id="paste" placeholder='{"contact": {"name": "...", "email": "..."}}'></textarea>
  <label>Always hide these terms (comma separated; a trailing * hides every word starting with it, e.g. <code>ACME, acme*</code>):</label>
  <input id="terms" style="width:100%" placeholder="ACME, acme*, acmecorp*">
  <div class="row"><button id="go">Obfuscate</button><span id="msg" class="mut"></span></div>
</div>
<div id="res" hidden>
  <div class="card"><div class="grid" id="stats"></div><div id="types" style="margin-top:10px"></div><div id="leak" style="margin-top:10px"></div>
    <div class="row"><button id="dlOut">Download obfuscated JSON</button><button class="sec" id="dlMap">Download mapping (contains real values)</button></div>
    <p id="saved" class="mut" style="font-size:12px;margin:10px 0 0"></p>
    <details><summary>Preview</summary><pre id="preview"></pre></details></div>
</div>

<div class="card">
  <h2><span class="step">3</span>Ask Claude Code</h2>
  <p class="mut" style="margin:0">Claude Code runs headless in <code>--restricted</code> mode: no MCP servers, only Read, Grep and Glob, in a temp folder that holds just the obfuscated file. Your prompt is masked with the same mapping first, and you see exactly what goes out.</p>
  <div class="f">
    <div><label>Obfuscated run</label><select id="aRun"></select></div>
    <div><label>Model</label><select id="aModel"><option value="">Claude Code default</option><option>opus</option><option>sonnet</option><option>haiku</option></select></div>
  </div>
  <label>Your question (real names are fine here, they get masked):</label>
  <textarea id="aPrompt" placeholder="Which sites failed and why? Group the errors by cause, give counts and the first and last timestamp for each, and list which sites hit throttling (429 Too Many Requests)."></textarea>
  <div class="row"><button class="sec" id="aPrev">Preview what gets sent</button><span id="aPrevMsg" class="mut"></span></div>
  <div id="aSendBox" hidden>
    <label>This exact text goes to Claude Code (you can edit it; it is re-checked before sending):</label>
    <textarea id="aMasked"></textarea>
    <div class="row"><button id="aSend">Send to Claude Code</button><span id="aMsg" class="mut"></span></div>
  </div>
  <div id="aRes" hidden style="margin-top:12px">
    <div id="aStats"></div>
    <div class="row"><button class="sec" id="aShowReal">Real values</button><button class="sec" id="aShowMasked">As Claude wrote it</button><button class="sec" id="aDl">Download answer (real values)</button></div>
    <pre id="aOut" style="margin-top:10px;max-height:640px"></pre>
  </div>
  <details><summary>Prefer an interactive Claude Code session?</summary>
    <p class="mut">Run <code id="wsCmd"></code>. It makes a folder with only the obfuscated file and the rules, and prints the locked-down <code>claude</code> command to start in it. Paste the answers into step 4.</p></details>
</div>

<div class="card">
  <h2><span class="step">4</span>Unmask any text</h2>
  <p class="mut" style="margin:0">Paste output from any Claude session that worked on an obfuscated file. Labels are swapped back by lookup, no model.</p>
  <div class="f">
    <div><label>Mapping from run</label><select id="uRun"></select></div>
    <div><label>or a mapping file</label><input type="file" id="uMapFile" accept=".json"></div>
  </div>
  <label>Text with labels:</label>
  <textarea id="uIn" placeholder="`<Site_Name-14>` failed 37 times with `<Guid-07>` ..."></textarea>
  <div class="row"><button id="uGo">Unmask</button><button class="sec" id="uCopy">Copy result</button><span id="uMsg" class="mut"></span></div>
  <pre id="uOut" style="margin-top:10px"></pre>
</div>

<script>
const $=id=>document.getElementById(id);const REPO="__REPO__";let name="pasted.json",text=null,last=null;
function esc(s){return String(s).replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]))}
function err(el,e){el.innerHTML='<span class="bad">'+esc(e.message||e)+'</span>'}
async function api(path,body,method){const r=await fetch(path,method==="GET"?{}:{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
  const j=await r.json();if(!r.ok)throw new Error(j.error||r.status);return j}
function dl(data,fn,type){const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([data],{type:type||"application/json"}));a.download=fn;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000)}

// 1. gather prompt
const sh=s=>String(s).replace(/["$`\\]/g,"\\$&");
const slug=s=>String(s).replace(/[^A-Za-z0-9]+/g,"-").replace(/^-|-$/g,"").slice(0,60)||"session";
function gather(){
  const region=$("gRegion").value,srv=$("gServer").value.trim()||"<backup server>",pol=$("gPolicy").value.trim()||"<backup policy>",
    ten=$("gTenant").value.trim(),ses=$("gSession").value.trim()||"latest";
  if(!$("gDir").dataset.touched)$("gDir").value=REPO+"/out/json/input/"+slug(pol)+"-"+(ses==="latest"?"latest":slug(ses));
  const dir=$("gDir").value.trim(),terms=$("terms").value.split(",").map(t=>t.trim()).filter(Boolean);
  const pick=/^latest$/i.test(ses)?"the most recent session (the top row)":"the session that started "+ses;
  let cmd='cd "'+sh(REPO)+'" && .venv/bin/python -m hider merge-csv "'+sh(dir)+'" -o "'+sh(dir)+'/session.json" --policy "'+sh(pol)+'" --backup-server "'+sh(srv)+'" --region '+region+(ten?' --tenant "'+sh(ten)+'"':"")+' --session-status "<status from step 4>"';
  const portal=($("gPortal").value.trim()||"<portal jobs page URL>").replace("{region}",region);
  let steps=["In the Playwright browser, open "+portal+" . If SSO does not finish on its own, stop and ask me to log in.",
    'Select the backup server "'+srv+'".',
    'Open the backup policy "'+pol+'"'+(ten?" (tenant "+ten+")":"")+".",
    "In the policy's Sessions panel, pick "+pick+". Note its start time and status exactly as the list shows them.",
    'Click "Download logs" for that session. The portal saves one or more CSV parts named <policy>-<date>-partN.csv. Wait until every part has downloaded (the Playwright browser saves them under .playwright-mcp/ in the working directory).',
    "Create the empty folder "+dir+" and move all the parts of this one session into it. Nothing else goes in that folder.",
    "Run:\n   "+cmd];
  if($("gScrub").checked){steps.push("Run:\n   "+'cd "'+sh(REPO)+'" && .venv/bin/python -m hider scrub-json "'+sh(dir)+'/session.json"'+terms.map(t=>' --term "'+sh(t)+'"').join(""));
    steps.push("Reply with only: the folder path, the number of parts, the lines both commands printed (counts and file paths), and the session start time and status.");}
  else steps.push("Reply with only: the folder path, the number of parts, the line merge-csv printed, and the session start time and status.");
  $("gOut").value="Download a backup session log from the backup admin portal and turn it into one JSON file with Hider.\n\n"+
    "Hard rule: the logs contain customer data. Do not open, read, cat, head, tail, grep, print or summarise the CSV or JSON contents at any step, and do not inspect them in the browser. Work only with file names, file counts and sizes, and the counts the Hider commands print. Do not send anything anywhere.\n\n"+
    steps.map((s,i)=>(i+1)+". "+s).join("\n")+"\n";}
["gPortal","gRegion","gServer","gPolicy","gTenant","gSession","gDir","gScrub","terms"].forEach(id=>$(id).addEventListener("input",gather));
$("gScrub").onchange=gather;$("gDir").addEventListener("input",()=>$("gDir").dataset.touched=1);gather();
$("gCopy").onclick=async()=>{try{await navigator.clipboard.writeText($("gOut").value);$("gMsg").textContent="Copied. Paste it into Claude Code."}catch(e){$("gOut").select();$("gMsg").textContent="Select-all done, press Cmd+C."}};

// 2. obfuscate
const drop=$("drop"),file=$("file");
drop.onclick=()=>file.click();
drop.ondragover=e=>{e.preventDefault();drop.classList.add("over")};
drop.ondragleave=()=>drop.classList.remove("over");
drop.ondrop=e=>{e.preventDefault();drop.classList.remove("over");if(e.dataTransfer.files.length)load([...e.dataTransfer.files])};
file.onchange=()=>file.files.length&&load([...file.files]);
async function load(fs){
  const csvs=fs.filter(f=>/\.csv$/i.test(f.name));
  try{if(csvs.length){
      const files=await Promise.all(csvs.map(async f=>({name:f.name,text:await f.text()})));
      const j=await api("/api/csv",{files,meta:{}});text=j.json_text;
      name=csvs[0].name.replace(/-part\d+\.csv$/i,"").replace(/\.csv$/i,"")+".json";
      drop.textContent=csvs.length+" CSV part(s) merged: "+j.summary;
    }else{const f=fs[0];name=f.name;text=await f.text();drop.textContent=f.name+" ("+(f.size/1024).toFixed(1)+" KB) loaded";}
    $("paste").value="";}catch(e){drop.textContent="Could not load: "+(e.message||e)}}
$("paste").oninput=()=>{text=null;name="pasted.json"};
$("go").onclick=async()=>{
  const body=text??$("paste").value;if(!body.trim()){$("msg").textContent="Nothing to obfuscate.";return}
  $("go").disabled=true;$("msg").textContent="Working...";const t0=performance.now();
  try{const r=await fetch("/api/obfuscate?name="+encodeURIComponent(name)+"&terms="+encodeURIComponent($("terms").value),{method:"POST",headers:{"Content-Type":"application/json"},body});
    const j=await r.json();if(!r.ok)throw new Error(j.error||r.status);last=j;show(j);
    $("msg").textContent="Done in "+((performance.now()-t0)/1000).toFixed(1)+" s";await runs(j.run);
  }catch(e){err($("msg"),e)}finally{$("go").disabled=false}};
function show(j){$("res").hidden=false;const s=j.stats;
  $("stats").innerHTML=[["Mapped values",s.mapped_values],["Secrets destroyed",s.secrets_destroyed],["Degraded lines",s.degraded_lines],["Leaks found",s.leaks.length]]
    .map(([k,v])=>'<div class="stat"><b>'+v+'</b><span>'+k+'</span></div>').join("");
  $("types").innerHTML=Object.entries(s.by_type).map(([k,v])=>'<span class="pill">'+esc(k)+': '+v+'</span>').join("");
  $("leak").innerHTML=s.leaks.length?'<span class="bad">Original values still present for: '+s.leaks.map(esc).join(", ")+'. Review before sharing.</span>'
    :(s.degraded_lines?'<span class="bad">Some lines degraded (a tier failed). Review before sharing.</span>':'<span class="ok">Leak check passed: no mapped original value appears in the output.</span>');
  $("saved").textContent="Saved as run "+j.run+": "+j.saved.output+"  |  "+j.saved.mapping;
  $("preview").textContent=j.output_text.length>200000?j.output_text.slice(0,200000)+"\n... (truncated preview, download for full file)":j.output_text;}
const stem=()=>name.replace(/\.(jsonl?|txt)$/i,"");
$("dlOut").onclick=()=>last&&dl(last.output_text,stem()+".obfuscated.json");
$("dlMap").onclick=()=>last&&dl(JSON.stringify({note:"label -> original value. Keep on this machine.",mapping:last.mapping},null,2),stem()+".mapping.json");

// runs list (steps 3 and 4)
async function runs(select){try{const j=await api("/api/runs",null,"GET");
  const opts=j.runs.map(r=>'<option value="'+esc(r.run)+'">'+esc(r.run)+" ("+r.size_mb+" MB, "+esc(r.saved)+")</option>").join("")||'<option value="">no runs yet: obfuscate something first</option>';
  for(const id of ["aRun","uRun"]){const el=$(id),cur=el.value;el.innerHTML=opts;if(select)el.value=select;else if(cur)el.value=cur;}
  wsCmd();}catch(e){}}
function wsCmd(){$("wsCmd").textContent='cd "'+REPO+'" && .venv/bin/python -m hider workspace '+($("aRun").value||"<run>")}
$("aRun").onchange=()=>{wsCmd();$("aSendBox").hidden=true};runs();

// 3. ask
$("aPrompt").oninput=()=>{$("aSendBox").hidden=true};
$("aPrev").onclick=async()=>{try{const j=await api("/api/mask",{run:$("aRun").value,text:$("aPrompt").value});
  $("aMasked").value=j.masked;extra=j.extra||{};$("aSendBox").hidden=false;$("aMsg").textContent="";
  $("aPrevMsg").textContent=j.replaced?j.replaced+" customer value(s) replaced with labels.":"No customer values found in the prompt.";}catch(e){err($("aPrevMsg"),e)}};
let answer=null,extra={};
$("aSend").onclick=async()=>{$("aSend").disabled=true;$("aRes").hidden=true;
  try{const {job}=await api("/api/ask",{run:$("aRun").value,text:$("aMasked").value,model:$("aModel").value,extra});
    for(;;){await new Promise(r=>setTimeout(r,2000));const s=await api("/api/job?id="+job,null,"GET");
      if(s.status==="running"){$("aMsg").textContent="Claude Code is working... "+s.elapsed+" s";continue}
      if(s.status==="error")throw new Error(s.error);answer=s.result;break}
    const r=answer;$("aMsg").textContent="Done in "+r.seconds+" s";$("aRes").hidden=false;
    $("aStats").innerHTML='<span class="pill">'+r.replaced+' labels unmasked</span>'+(r.cost_usd!=null?'<span class="pill">cost $'+Number(r.cost_usd).toFixed(2)+'</span>':"")
      +'<span class="pill">'+r.denied_tool_calls+' blocked tool calls</span>'
      +(r.unknown_labels.length?'<span class="pill bad">not in mapping: '+r.unknown_labels.map(esc).join(", ")+'</span>':"")
      +'<div class="mut" style="font-size:12px;margin-top:6px">Saved: '+esc(r.saved)+'</div>';
    $("aOut").textContent=r.answer;
  }catch(e){err($("aMsg"),e)}finally{$("aSend").disabled=false}};
$("aShowReal").onclick=()=>answer&&($("aOut").textContent=answer.answer);
$("aShowMasked").onclick=()=>answer&&($("aOut").textContent=answer.answer_masked);
$("aDl").onclick=()=>answer&&dl(answer.answer,"answer.md","text/markdown");

// 4. unmask
let upMap=null;
$("uMapFile").onchange=async()=>{const f=$("uMapFile").files[0];if(!f){upMap=null;return}
  try{const d=JSON.parse(await f.text());upMap=d.mapping||d;$("uMsg").textContent="Using "+f.name+" ("+Object.keys(upMap).length+" labels)"}catch(e){upMap=null;err($("uMsg"),"not a mapping file")}};
$("uGo").onclick=async()=>{try{const j=await api("/api/unmask",upMap?{mapping:upMap,text:$("uIn").value}:{run:$("uRun").value,text:$("uIn").value});
  $("uOut").textContent=j.text;$("uMsg").textContent=j.replaced+" label(s) unmasked"+(j.unknown_labels.length?"; not in this mapping: "+j.unknown_labels.join(", "):"");}catch(e){err($("uMsg"),e)}};
$("uCopy").onclick=()=>navigator.clipboard.writeText($("uOut").textContent).then(()=>$("uMsg").textContent="Copied.");
</script></main></body></html>"""


def _safe_stem(name: str) -> str:
    stem = re.sub(r"\.(jsonl?|txt)$", "", Path(name).name, flags=re.I)
    return re.sub(r"[^A-Za-z0-9._-]+", "_", stem)[:80] or "input"


def obfuscate_text(
    raw: str, name: str = "input.json", tier2: str = "classifier", terms: list[str] | None = None
) -> dict:
    """Obfuscate a JSON or JSON Lines string and save both halves under ``out/json/``.

    Returns the output text, the mapping, the stats, the run name and the saved
    paths. The mapping file holds real values and stays on this machine.
    """
    doc, jsonl = jsonscrub.parse(raw)
    with _LOCK:
        res = jsonscrub.scrub(doc, tier2=tier2, terms=terms)
    if jsonl:
        output_text = "\n".join(json.dumps(r, ensure_ascii=False) for r in res.output) + "\n"
    else:
        output_text = json.dumps(res.output, ensure_ascii=False, indent=2) + "\n"
    OUT.mkdir(parents=True, exist_ok=True)
    stem = f"{_safe_stem(name)}-{time.strftime('%Y%m%d-%H%M%S')}"
    out_path = OUT / f"{stem}.obfuscated.json"
    map_path = OUT / f"{stem}.mapping.json"
    out_path.write_text(output_text, encoding="utf-8")
    map_path.write_text(
        json.dumps(
            {
                "note": "label -> original value. Holds real customer data; keep on this machine.",
                "terms": terms or [],
                "mapping": res.mapping,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    return {
        "output_text": output_text,
        "mapping": res.mapping,
        "stats": res.stats,
        "run": stem,
        "saved": {"output": str(out_path), "mapping": str(map_path)},
    }


class Handler(BaseHTTPRequestHandler):
    """The web UI's request handler: serves the page and the local JSON API."""

    tier2 = "classifier"

    def log_message(self, fmt: str, *args: Any) -> None:  # no bodies or values in the console
        """Log the request line only, never a body or a value."""
        sys.stderr.write(f"{self.address_string()} {fmt % args}\n")

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj: dict) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode(), "application/json")

    def do_GET(self) -> None:
        """Serve the page, the list of runs, or a Claude Code job's status."""
        url = urlparse(self.path)
        if url.path in ("/", "/index.html"):
            page = PAGE.replace("__REPO__", str(OUT.parent.parent)).replace(
                "__PORTAL__", html.escape(localcfg.settings().get("portal_url", ""), quote=True)
            )
            self._send(200, page.encode(), "text/html; charset=utf-8")
        elif url.path == "/api/runs":
            self._json(200, {"runs": research.list_runs()})
        elif url.path == "/api/job":
            job = _JOBS.get((parse_qs(url.query).get("id") or [""])[0])
            if job is None:
                return self._json(404, {"error": "no such job"})
            self._json(200, {**job, "elapsed": round(time.time() - job["started"])})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        """Handle an API call: obfuscate, merge CSV parts, mask, ask or unmask.

        Refuses cross-origin posts (403) and bodies outside the size limit (413).
        """
        url = urlparse(self.path)
        if url.path not in ("/api/obfuscate", "/api/mask", "/api/ask", "/api/unmask", "/api/csv"):
            return self._json(404, {"error": "not found"})
        # Reject cross-site posts: only this page may call the API.
        origin = self.headers.get("Origin")
        if origin and urlparse(origin).hostname not in ("127.0.0.1", "localhost", "::1"):
            return self._json(403, {"error": "cross-origin request refused"})
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > MAX_BYTES:
            return self._json(413, {"error": f"body must be 1 byte to {MAX_BYTES // 2**20} MB"})
        raw = self.rfile.read(n).decode("utf-8-sig", errors="strict")
        if url.path != "/api/obfuscate":
            try:
                return self._research(url.path, json.loads(raw))
            except (ValueError, FileNotFoundError) as e:
                return self._json(400, {"error": str(e)})
        q = parse_qs(url.query)
        name = (q.get("name") or ["input.json"])[0]
        terms = [t for t in (q.get("terms") or [""])[0].split(",") if t.strip()]
        try:
            result = obfuscate_text(raw, name, tier2=self.tier2, terms=terms)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            return self._json(400, {"error": f"not valid JSON or JSON Lines: {e}"})
        except Exception as e:  # fail closed: no partial output
            return self._json(
                500, {"error": f"obfuscation failed, nothing returned: {type(e).__name__}"}
            )
        self._json(200, result)

    def _research(self, path: str, body: dict) -> None:
        if path == "/api/csv":
            doc = csvmerge.merge(
                [(f["name"], f["text"]) for f in body.get("files") or []], body.get("meta")
            )
            return self._json(
                200,
                {
                    "json_text": json.dumps(doc, ensure_ascii=False, indent=2),
                    "summary": csvmerge.summary(doc),
                },
            )
        if path == "/api/unmask" and isinstance(body.get("mapping"), dict):
            mapping, terms, public = body["mapping"], [], None  # a dropped mapping file
        else:
            mapping, terms, public = research.run_context(str(body.get("run")))
        text = str(body.get("text") or "")
        if path == "/api/mask":
            masked, extra, n = research.mask_prompt(text, mapping, terms, public)
            return self._json(200, {"masked": masked, "replaced": n, "extra": extra})
        if path == "/api/unmask":
            out, n, unknown = research.unmask(text, mapping)
            return self._json(200, {"text": out, "replaced": n, "unknown_labels": unknown})
        # /api/ask: refuse up front, then run Claude Code in the background
        if research.prompt_leaks(text, mapping, terms, public):
            raise ValueError("the prompt still contains customer values: press Preview again")
        job_id = uuid.uuid4().hex[:12]
        _JOBS[job_id] = {"status": "running", "started": time.time()}

        def work() -> None:
            try:
                _JOBS[job_id].update(
                    status="done",
                    result=research.ask(
                        str(body["run"]),
                        text,
                        model=body.get("model") or None,
                        extra={str(k): str(v) for k, v in (body.get("extra") or {}).items()},
                    ),
                )
            except Exception as e:  # reported to the page, never swallowed
                _JOBS[job_id].update(status="error", error=f"{type(e).__name__}: {e}")

        threading.Thread(target=work, daemon=True).start()
        self._json(202, {"job": job_id})


def serve(
    host: str = "127.0.0.1", port: int = 8790, tier2: str = "classifier", allow_remote: bool = False
) -> None:
    """Run the web UI until interrupted.

    Refuses a non-loopback address unless ``allow_remote`` is set, and trains
    the tier 2 model before the first request.
    """
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host == "localhost"
    if not loopback and not allow_remote:
        raise SystemExit(
            f"refusing to bind {host}: not a loopback address "
            f"(pass --allow-remote if you really mean it)"
        )
    Handler.tier2 = tier2
    # Train the tier 2 model now, not on the first request.
    jsonscrub.scrub({"warmup": "x"}, tier2=tier2)
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"Hider JSON obfuscator on http://{host}:{port}  (Ctrl+C to stop)", file=sys.stderr)
    print(f"results also saved to {OUT}", file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
