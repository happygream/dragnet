package dashboard

const indexHTML = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>dragnet monitor</title>
<style>
:root{--bg:#0c0a08;--panel:#16120d;--line:#2a2118;--amber:#e8a33d;--amber-dim:#7a5a26;--ink:#e6dccb;--muted:#8a7c66;--bad:#d9534f;--good:#6fae5f}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 "JetBrains Mono",ui-monospace,Menlo,Consolas,monospace}
.wrap{max-width:1100px;margin:0 auto;padding:32px 24px}
header{display:flex;align-items:baseline;gap:14px;border-bottom:1px solid var(--line);padding-bottom:16px;margin-bottom:8px}
.brand{font-size:26px;font-weight:800;color:var(--amber);letter-spacing:.04em}
.tag{color:var(--muted);text-transform:uppercase;letter-spacing:.1em;font-size:11px}
.status{margin-left:auto;font-size:12px;color:var(--muted)}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--amber-dim);margin-right:6px;vertical-align:middle}
.dot.live{background:var(--good);animation:pulse 1.4s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:.4}50%{opacity:1}}
.meta{display:flex;flex-wrap:wrap;gap:1px;background:var(--line);border:1px solid var(--line);margin:18px 0 28px}
.meta>div{background:var(--panel);padding:10px 14px;flex:1;min-width:130px;display:flex;flex-direction:column;gap:3px}
.meta span{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.07em}
.meta strong{color:var(--amber);font-weight:600}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin:28px 0 12px;font-weight:600}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:24px}
@media(max-width:820px){.grid{grid-template-columns:1fr}}
.host{border:1px solid var(--line);background:var(--panel);padding:12px 14px;margin-bottom:10px}
.host .hh{display:flex;align-items:baseline;gap:10px}
.host .ip{color:var(--amber);font-weight:700}
.host .hn{color:var(--muted);font-size:12px}
.host .rtt{margin-left:auto;color:var(--amber-dim);font-size:11px}
.host .dev{color:var(--ink);font-size:12px;margin-top:3px}
.host .ports{color:var(--muted);font-size:12px;margin-top:6px}
.host .port{color:var(--amber)}
.decoy{color:var(--bad);font-size:11px;margin-top:5px;border:1px solid var(--bad);display:inline-block;padding:1px 7px;letter-spacing:.06em}
.change{border-left:2px solid var(--line);padding:6px 0 6px 12px;margin-bottom:2px;font-size:13px}
.change .k{font-weight:600;letter-spacing:.03em}
.change .ip{color:var(--amber)}
.change .t{color:var(--muted);font-size:11px}
.change.host_appeared{border-color:var(--good)}.change.host_appeared .k{color:var(--good)}
.change.host_vanished{border-color:var(--muted)}.change.host_vanished .k{color:var(--muted)}
.change.port_opened{border-color:var(--amber)}.change.port_opened .k{color:var(--amber)}
.change.port_closed{border-color:var(--amber-dim)}.change.port_closed .k{color:var(--amber-dim)}
.change.cert_expiring,.change.decoy_detected{border-color:var(--bad)}
.change.cert_expiring .k,.change.decoy_detected .k{color:var(--bad)}
.change.device_changed{border-color:var(--amber)}.change.device_changed .k{color:var(--amber)}
.empty{color:var(--muted);font-style:italic}
footer{margin-top:32px;padding-top:14px;border-top:1px solid var(--line);color:var(--muted);font-size:11px;text-align:center;letter-spacing:.06em}
</style></head>
<body><div class="wrap">
<header>
  <div class="brand">DRAGNET</div><div class="tag">monitor</div>
  <div class="status"><span id="dot" class="dot"></span><span id="statusText">connecting…</span></div>
</header>

<div class="meta">
  <div><span>Target</span><strong id="mTarget">—</strong></div>
  <div><span>Interval</span><strong id="mInterval">—</strong></div>
  <div><span>Hosts up</span><strong id="mHosts">—</strong></div>
  <div><span>Scans run</span><strong id="mRuns">—</strong></div>
  <div><span>Last scan</span><strong id="mLast">—</strong></div>
</div>

<div class="grid">
  <div>
    <h2>Current hosts</h2>
    <div id="hosts"><div class="empty">waiting for first scan…</div></div>
  </div>
  <div>
    <h2>Change timeline</h2>
    <div id="changes"><div class="empty">no changes recorded yet</div></div>
  </div>
</div>

<footer>dragnet monitor · auto-refreshes every 5s · localhost only unless -listen set</footer>
</div>

<script>
function esc(s){return (s==null?"":String(s)).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));}
function ago(iso){ if(!iso) return "never"; const d=new Date(iso), s=Math.floor((Date.now()-d)/1000);
  if(s<60) return s+"s ago"; if(s<3600) return Math.floor(s/60)+"m ago"; return Math.floor(s/3600)+"h ago"; }

async function refresh(){
  try{
    const st = await (await fetch("/api/state")).json();
    document.getElementById("mTarget").textContent = st.target||"—";
    document.getElementById("mInterval").textContent = st.interval||"—";
    document.getElementById("mHosts").textContent = st.hosts_up;
    document.getElementById("mRuns").textContent = st.runs;
    document.getElementById("mLast").textContent = ago(st.last_scan);
    const dot=document.getElementById("dot"), txt=document.getElementById("statusText");
    if(st.scanning){dot.className="dot live";txt.textContent="scanning…";}
    else{dot.className="dot live";txt.textContent="watching";}

    const hosts = st.hosts||[];
    const hc=document.getElementById("hosts");
    if(!hosts.length){hc.innerHTML='<div class="empty">no live hosts</div>';}
    else{hc.innerHTML=hosts.map(h=>{
      const dev = h.device||h.vendor||"";
      const ports=(h.open_ports||[]).map(p=>'<span class="port">'+p.port+'</span> '+esc(p.service)).join("  ");
      return '<div class="host"><div class="hh"><span class="ip">'+esc(h.ip)+'</span>'+
        '<span class="hn">'+esc(h.hostname||"")+'</span><span class="rtt">'+esc(h.rtt||"")+'</span></div>'+
        (dev?'<div class="dev">'+esc(dev)+(h.mac?'  <span style="color:var(--muted)">'+esc(h.mac)+'</span>':"")+'</div>':"")+
        (h.honeypot?'<div class="decoy">PROBABLE DECOY</div>':"")+
        (ports?'<div class="ports">'+ports+'</div>':"")+'</div>';
    }).join("");}

    const changes = await (await fetch("/api/changes")).json();
    const cc=document.getElementById("changes");
    if(!changes||!changes.length){cc.innerHTML='<div class="empty">no changes recorded yet</div>';}
    else{cc.innerHTML=changes.map(c=>{
      return '<div class="change '+esc(c.kind)+'"><span class="k">'+esc(c.kind.replace(/_/g," "))+'</span> '+
        '<span class="ip">'+esc(c.ip)+'</span> — '+esc(c.detail)+
        '<div class="t">'+ago(c.at)+'</div></div>';
    }).join("");}
  }catch(e){
    document.getElementById("statusText").textContent="disconnected";
    document.getElementById("dot").className="dot";
  }
}
refresh(); setInterval(refresh,5000);
</script>
</body></html>`
