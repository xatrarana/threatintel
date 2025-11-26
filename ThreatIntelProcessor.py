# ThreatIntelProcessor_Pro_UI.py
# Full Flask app with professional gradient UI, dashboard charts, settings tab, and stylish footer
# Developed & Designed by Dip Kar
# Updated: Fixed datetime templating, login/logout, IP check, fetch blacklist, top malicious list + API endpoints
# Polished: Color badges for abuse score, country flag emoji, copy buttons (IP/WHOIS), Passive DNS "View all" modal
# New: Threat Score Engine (auto risk label), GeoMap (Leaflet + ip-api.com), SIEM Exports (CSV/JSON/STIX)
# Fix: Doughnut chart now always shows all three colored slices (min 8% each); tooltips show true counts

from flask import Flask, request, session, redirect, url_for, render_template_string, jsonify, flash, Response
import sqlite3, requests, json, ipaddress, socket, uuid
from datetime import datetime, timezone
from functools import wraps

# ------------------ CONFIG ------------------
OTX_API_KEY = ""
ABUSEIPDB_API_KEY = ""

ADMIN_USER = "admin"
ADMIN_PASS = "admin123"
APP_SECRET = "change_this_secret_for_prod"

ABUSE_BLACKLIST_URL = "https://api.abuseipdb.com/api/v2/blacklist"
ABUSE_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
OTX_IPV4_GENERAL = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
OTX_IPV4_REPUTATION = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/reputation"

# Free geo API (no key)
IP_GEO_API = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,lat,lon,isp,org,as,query"

DB_PATH = "threat_intel_singlefile.db"

# ------------------ APP INIT ------------------
app = Flask(__name__)
app.secret_key = APP_SECRET

# ------------------ DB HELPERS ------------------
def get_db_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    db = get_db_conn()
    cur = db.cursor()
    cur.execute("""
      CREATE TABLE IF NOT EXISTS iocs (
        ip_address TEXT PRIMARY KEY,
        abuse_confidence INTEGER,
        country_code TEXT,
        last_seen TEXT
      )
    """)
    cur.execute("""
      CREATE TABLE IF NOT EXISTS checks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        score INTEGER,
        country TEXT,
        checked_at TEXT,
        source TEXT
      )
    """)
    # simple geo cache to reduce API calls
    cur.execute("""
      CREATE TABLE IF NOT EXISTS geocache (
        ip TEXT PRIMARY KEY,
        country TEXT,
        country_code TEXT,
        region TEXT,
        city TEXT,
        lat REAL,
        lon REAL,
        isp TEXT,
        org TEXT,
        asn TEXT,
        updated_at TEXT
      )
    """)
    db.commit()
    db.close()

init_db()

# ------------------ AUTH DECORATOR ------------------
def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if session.get("user") != ADMIN_USER:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

# ------------------ UTIL ------------------
def is_valid_ip(addr):
    try:
        ipaddress.ip_address(addr)
        return True
    except Exception:
        return False

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

def utcnow_iso():
    return datetime.now(timezone.utc).isoformat()

# Threat Score Engine: label + color name
def risk_label(score):
    try:
        s = int(score)
    except Exception:
        return ("Unknown", "badge-yellow")
    if s >= 90:
        return ("Critical", "badge-red")
    if s >= 75:
        return ("High", "badge-red")
    if s >= 30:
        return ("Medium", "badge-yellow")
    if s >= 0:
        return ("Low", "badge-green")
    return ("Unknown", "badge-yellow")

# ------------------ ABUSEIPDB FUNCTIONS ------------------
def fetch_blacklist(limit=50):
    headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
    params = {"limit": limit}
    resp = requests.get(ABUSE_BLACKLIST_URL, headers=headers, params=params, timeout=20)
    resp.raise_for_status()
    data = resp.json().get("data", [])
    db = get_db_conn()
    cur = db.cursor()
    added = 0
    for rec in data:
        ip = rec.get("ipAddress") or rec.get("ip")
        score = rec.get("abuseConfidenceScore", 0)
        country = rec.get("countryCode") or rec.get("country") or ""
        last_seen = utcnow_iso()
        if not ip:
            continue
        cur.execute(
            "INSERT OR REPLACE INTO iocs (ip_address, abuse_confidence, country_code, last_seen) VALUES (?,?,?,?)",
            (ip, score, country, last_seen),
        )
        added += 1
    db.commit()
    db.close()
    return added

def check_abuseipdb(ip):
    headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    resp = requests.get(ABUSE_CHECK_URL, headers=headers, params=params, timeout=12)
    resp.raise_for_status()
    js = resp.json()
    d = js.get("data") if isinstance(js, dict) else {}
    if not isinstance(d, dict):
        d = {}
    score = d.get("abuseConfidenceScore", 0)
    country = d.get("countryCode") or "-"
    db = get_db_conn()
    cur = db.cursor()
    cur.execute(
        "INSERT INTO checks (ip, score, country, checked_at, source) VALUES (?,?,?,?,?)",
        (ip, score, country, utcnow_iso(), "AbuseIPDB"),
    )
    # Also update iocs table for top malicious tracking
    cur.execute(
        "INSERT OR REPLACE INTO iocs (ip_address, abuse_confidence, country_code, last_seen) VALUES (?,?,?,?)",
        (ip, score, country, utcnow_iso()),
    )
    db.commit()
    db.close()
    domain = d.get("domain") or reverse_dns(ip) or "-"
    rlabel, _ = risk_label(score)
    details = {
        "ipAddress": d.get("ipAddress") or ip,
        "isPublic": d.get("isPublic"),
        "ipVersion": d.get("ipVersion"),
        "isWhitelisted": d.get("isWhitelisted"),
        "abuseConfidenceScore": score,
        "riskLabel": rlabel,
        "countryCode": d.get("countryCode") or "-",
        "usageType": d.get("usageType") or "-",
        "isp": d.get("isp") or "-",
        "domain": domain,
        "hostnames": d.get("hostnames") or [],
        "totalReports": d.get("totalReports", 0),
        "numDistinctUsers": d.get("numDistinctUsers", 0),
        "lastReportedAt": d.get("lastReportedAt"),
        "raw": d,
    }
    return {"ip": ip, "score": score, "country": country, "details": details}

# ------------------ OTX FUNCTIONS ------------------
def query_otx(ip):
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    try:
        url = OTX_IPV4_GENERAL.format(ip=ip)
        r = requests.get(url, headers=headers, timeout=12)
        if r.status_code == 200:
            data = r.json()
            country = data.get("country_name") or data.get("geolocation", {}).get("country_name") or ""
            db = get_db_conn()
            cur = db.cursor()
            cur.execute(
                "INSERT INTO checks (ip, score, country, checked_at, source) VALUES (?,?,?,?,?)",
                (ip, None, country, utcnow_iso(), "OTX-general"),
            )
            db.commit()
            db.close()
            otx_summary = {
                "indicator": data.get("indicator") or ip,
                "reputation": data.get("reputation", 0),
                "whois": data.get("whois"),
                "country_name": country,
                "pulse_count": data.get("pulse_info", {}).get("count", 0),
                "passive_dns": data.get("passive_dns", []),
                "sections": data.get("sections", []),
                "raw": data,
            }
            return {"source": "OTX-general", "data": otx_summary}
    except Exception:
        pass
    try:
        url2 = OTX_IPV4_REPUTATION.format(ip=ip)
        r2 = requests.get(url2, headers=headers, timeout=12)
        if r2.status_code == 200:
            data2 = r2.json()
            country = data2.get("country_name", "")
            db = get_db_conn()
            cur = db.cursor()
            cur.execute(
                "INSERT INTO checks (ip, score, country, checked_at, source) VALUES (?,?,?,?,?)",
                (ip, None, country, utcnow_iso(), "OTX-reputation"),
            )
            db.commit()
            db.close()
            otx_summary = {
                "indicator": data2.get("indicator") or ip,
                "reputation": data2.get("reputation", 0),
                "country_name": country,
                "raw": data2,
            }
            return {"source": "OTX-reputation", "data": otx_summary}
        else:
            return {"source": "OTX", "status_code": r2.status_code, "text": r2.text}
    except Exception as e:
        return {"error": str(e)}

# ------------------ GEO FUNCTIONS ------------------
def geo_lookup(ip):
    # check cache
    db = get_db_conn()
    cur = db.cursor()
    cur.execute("SELECT * FROM geocache WHERE ip=?", (ip,))
    row = cur.fetchone()
    if row:
        db.close()
        return dict(row)
    # fetch from ip-api
    url = IP_GEO_API.format(ip=ip)
    r = requests.get(url, timeout=8)
    data = r.json()
    if data.get("status") != "success":
        db.close()
        return {"ip": ip}
    cur = db.cursor()
    cur.execute("""
      INSERT OR REPLACE INTO geocache (ip, country, country_code, region, city, lat, lon, isp, org, asn, updated_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?)
    """, (
        ip, data.get("country"), data.get("countryCode"), data.get("regionName"),
        data.get("city"), data.get("lat"), data.get("lon"), data.get("isp"),
        data.get("org"), data.get("as"), utcnow_iso()
    ))
    db.commit()
    db.close()
    data["ip"] = ip
    data["country_code"] = data.get("countryCode")
    return data

# ------------------ HTML TEMPLATES ------------------
LOGIN_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Login - ThreatIntel</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body{background:linear-gradient(135deg,#0f172a,#0b1220);color:#e2e8f0;font-family:Inter,system-ui;}
    .card{margin-top:8vh;background:rgba(255,255,255,0.03);border:none;border-radius:12px;padding:24px}
    input::placeholder{opacity:0.6}
  </style>
</head>
<body>
  <div class="container d-flex justify-content-center">
    <div class="col-md-5">
      <div class="card">
        <h3 class="mb-3">⚡ ThreatIntel Login</h3>
        {% with messages = get_flashed_messages() %}
          {% if messages %}
            <div class="alert alert-warning">{{ messages[0] }}</div>
          {% endif %}
        {% endwith %}
        <form method="post" action="{{ url_for('login') }}">
          <div class="mb-3">
            <label class="form-label">Username</label>
            <input class="form-control" name="username" placeholder="admin" />
          </div>
          <div class="mb-3">
            <label class="form-label">Password</label>
            <input class="form-control" type="password" name="password" placeholder="admin123" />
          </div>
          <button class="btn btn-primary w-100">Login</button>
        </form>
      </div>
      <p class="text-muted mt-2 text-center">Developed & Designed by <strong style="color:#38bdf8">Dip Kar</strong></p>
    </div>
  </div>
</body>
</html>
"""

DASHBOARD_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Threat Intel Processor</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" crossorigin="anonymous"/>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js" crossorigin="anonymous"></script>
  <style>
    body { font-family: 'Inter', system-ui; background: linear-gradient(135deg,#0d102c,#1f224a,#3b1d64); color: #f8f9fa; }
    .navbar { background: #060930; }
    .card { border: none; border-radius: 12px; background: rgba(255,255,255,0.05); backdrop-filter: blur(8px); color: #f8f9fa; }
    .btn-primary { background: #4f46e5; border: none; }
    .btn-primary:hover { background: #6366f1; }
    .btn-ghost { background: transparent; border: 1px dashed rgba(255,255,255,0.25); color: #e5e7eb; }
    .btn-ghost:hover { background: rgba(255,255,255,0.06); }
    footer { text-align:center; color:#9ca3af; margin-top:30px; font-size:0.9rem; }
    .small-muted { color:#9ca3af; font-size:0.9rem; }
    pre.raw{background:#11172b;padding:8px;border-radius:8px;color:#cbd5e1;}
    .detail-key { color:#9ca3af; width:35%; }
    .detail-val { color:#e6eef8; width:65%; }
    .card-compact { padding:12px; border-radius:10px; background: rgba(255,255,255,0.02); }
    .badge-soft { padding: 0.35rem 0.5rem; border-radius: 999px; font-weight:600; }
    .badge-green { background: rgba(34,197,94,0.15); color: #22c55e; border: 1px solid rgba(34,197,94,0.25); }
    .badge-yellow { background: rgba(234,179,8,0.15); color: #eab308; border: 1px solid rgba(234,179,8,0.25); }
    .badge-red { background: rgba(239,68,68,0.15); color: #ef4444; border: 1px solid rgba(239,68,68,0.25); }
    .copy-btn { margin-left: 8px; }
    #map { height: 360px; border-radius: 12px; }
  </style>
</head>
<body>
  <nav class="navbar navbar-expand-lg">
    <div class="container-fluid">
      <a class="navbar-brand text-light fw-bold" href="{{ url_for('dashboard') }}">⚡ ThreatIntel Dashboard</a>
      <div class="d-flex">
        <span class="text-white me-3">{{ session.get('user') }}</span>
        <a class="btn btn-outline-light btn-sm" href="{{ url_for('logout') }}">Logout</a>
      </div>
    </div>
  </nav>

  <div class="container py-4">
    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <div class="alert alert-warning">{{ messages[0] }}</div>
      {% endif %}
    {% endwith %}

    <div class="row g-3">
      <div class="col-md-6">
        <div class="card p-3">
          <h5>IP Lookup</h5>
          <div class="input-group mb-2">
            <input id="ipinput" class="form-control" placeholder="Enter IP e.g. 8.8.8.8"/>
            <button class="btn btn-primary" onclick="doCheckIp()">Check</button>
          </div>
          <div id="ipResult">
            <p class="small-muted">Results will appear here.</p>
          </div>
          <hr/>
          <div class="d-flex flex-wrap gap-2">
            <button class="btn btn-outline-light" onclick="fetchBlacklist()">Fetch Blacklist (AbuseIPDB)</button>
            <div class="dropdown">
              <button class="btn btn-ghost dropdown-toggle" data-bs-toggle="dropdown">Export (SIEM)</button>
              <ul class="dropdown-menu dropdown-menu-dark">
                <li><a class="dropdown-item" href="{{ url_for('export_iocs_csv') }}">Download CSV</a></li>
                <li><a class="dropdown-item" href="{{ url_for('export_iocs_json') }}">Download JSON</a></li>
                <li><a class="dropdown-item" href="{{ url_for('export_iocs_stix') }}">Download STIX 2.1</a></li>
              </ul>
            </div>
          </div>
          <div id="fetchResult" class="mt-2 small-muted"></div>
        </div>
      </div>

      <div class="col-md-6">
        <div class="card p-3">
          <h5>Threat Overview</h5>
          <canvas id="threatChart"></canvas>
          <hr/>
          <h6>Database Info</h6>
          <p>Total IOC Records: <strong id="totalRecords">{{ total_records }}</strong></p>
          <p>Last Update: <strong id="lastUpdate">{{ current_time }}</strong></p>
        </div>
      </div>

      <div class="col-12">
        <div class="card p-3">
          <h5>Top Malicious IPs (by abuse confidence)</h5>
          <div id="topList">
            <p class="small-muted">Loading...</p>
          </div>
        </div>
      </div>

      <div class="col-12">
        <div class="card p-3">
          <h5>GeoMap (Top Malicious IPs)</h5>
          <div id="map"></div>
          <p class="small-muted mt-2">Source: ip-api.com (free)</p>
        </div>
      </div>
    </div>

    <footer>Developed & Designed by <span style="color:#4f46e5;font-weight:600">Dip Kar</span></footer>
  </div>

  <!-- Passive DNS Modal -->
  <div class="modal fade" id="pdnsModal" tabindex="-1" aria-labelledby="pdnsLabel" aria-hidden="true">
    <div class="modal-dialog modal-lg modal-dialog-scrollable">
      <div class="modal-content" style="background:#0b1030;color:#e5e7eb;border:1px solid rgba(255,255,255,0.1)">
        <div class="modal-header">
          <h5 class="modal-title" id="pdnsLabel">Passive DNS Records</h5>
          <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body">
          <div id="pdnsBody">Loading...</div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-ghost" data-bs-dismiss="modal">Close</button>
        </div>
      </div>
    </div>
  </div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
<script>
  // ---------- Chart init with locked colors (G/Y/R) ----------
  let lastCounts = { clean: 0, suspicious: 0, malicious: 0 }; // true counts for tooltips

  const ctx = document.getElementById('threatChart');
  const chart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Clean', 'Suspicious', 'Malicious'],
      datasets: [{
        label:'Threat Status',
        data:[1,1,1], // placeholder (equal slices)
        backgroundColor: [
          'rgba(34,197,94,0.85)',   // Clean  -> Green
          'rgba(234,179,8,0.85)',   // Suspicious -> Yellow
          'rgba(239,68,68,0.85)'    // Malicious -> Red
        ],
        borderColor: [
          'rgba(34,197,94,1)',
          'rgba(234,179,8,1)',
          'rgba(239,68,68,1)'
        ],
        borderWidth:1
      }]
    },
    options: {
      cutout: '60%',
      plugins:{
        legend:{ labels:{ color:'#f8f9fa' } },
        tooltip:{
          callbacks:{
            // Show REAL counts in tooltip, not adjusted slice sizes
            label: (ctx) => {
              const idx = ctx.dataIndex;
              const names = ['Clean','Suspicious','Malicious'];
              const vals = [lastCounts.clean, lastCounts.suspicious, lastCounts.malicious];
              return `${names[idx]}: ${vals[idx]}`;
            }
          }
        }
      },
      animation: { animateRotate: true, animateScale: true }
    }
  });

  // Helper: always-visible wedges (min percentage per slice), but tooltips show true counts
  function updateThreatChart(clean, suspicious, malicious){
    lastCounts = { clean, suspicious, malicious };

    const total = clean + suspicious + malicious;
    if(total === 0){
      chart.data.datasets[0].data = [1,1,1]; // equal, all visible
      chart.update();
      return;
    }
    const minPct = 0.08; // minimum 8% slice for visibility
    let pClean = clean / total;
    let pSusp  = suspicious / total;
    let pMal   = malicious / total;

    // Enforce minimum slice visibility
    pClean = Math.max(pClean, minPct);
    pSusp  = Math.max(pSusp,  minPct);
    pMal   = Math.max(pMal,   minPct);

    // Renormalize to sum=1
    const sum = pClean + pSusp + pMal;
    pClean /= sum; pSusp /= sum; pMal /= sum;

    chart.data.datasets[0].data = [pClean, pSusp, pMal];
    chart.update();
  }
  // -----------------------------------------------------------

  // Leaflet Map init
  let map = L.map('map').setView([20, 0], 2);
  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', { maxZoom: 6 }).addTo(map);
  let markersLayer = L.layerGroup().addTo(map);

  // helpers
  function kvRow(k, v, extraHtmlRight=''){
    if(v === null || v === undefined) v = '-';
    if(Array.isArray(v)) v = v.length ? v.join(', ') : '-';
    return `<div class="d-flex py-1 align-items-center">
      <div class="detail-key">${k}</div>
      <div class="detail-val"><strong>${String(v)}</strong>${extraHtmlRight}</div>
    </div>`;
  }

  function scoreBadge(score){
    let s = Number(score);
    if(isNaN(s)) return `<span class="badge-soft badge-yellow">-</span>`;
    let cls = s >= 75 ? 'badge-red' : (s >= 30 ? 'badge-yellow' : 'badge-green');
    return `<span class="badge-soft ${cls}">${s}</span>`;
  }

  function riskLabel(score){
    let s = Number(score);
    if(isNaN(s)) return `<span class="badge-soft badge-yellow">Unknown</span>`;
    if(s >= 90) return `<span class="badge-soft badge-red">Critical</span>`;
    if(s >= 75) return `<span class="badge-soft badge-red">High</span>`;
    if(s >= 30) return `<span class="badge-soft badge-yellow">Medium</span>`;
    return `<span class="badge-soft badge-green">Low</span>`;
  }

  function countryFlag(cc){
    if(!cc) return '';
    cc = cc.toUpperCase();
    if(cc.length !== 2) return cc;
    const A = 0x1F1E6;
    const codePoints = [cc.charCodeAt(0)-65 + A, cc.charCodeAt(1)-65 + A];
    try { return String.fromCodePoint(...codePoints) + ' ' + cc; } catch(e){ return cc; }
  }

  async function copyToClipboard(text){
    try{ await navigator.clipboard.writeText(text); }catch(e){
      const ta = document.createElement('textarea'); ta.value = text;
      document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta);
    }
  }

  let lastOtxPassiveDns = [];

  async function doCheckIp(){
    const ip = document.getElementById('ipinput').value.trim();
    if(!ip){ alert('Enter IP'); return; }
    const resultEl = document.getElementById('ipResult');
    resultEl.innerHTML = '<p class="small-muted">Checking...</p>';
    try {
      const resp = await fetch('{{ url_for("api_check_ip") }}', {
        method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ ip })
      });
      const js = await resp.json();
      if(js.error){
        resultEl.innerHTML = '<div class="text-danger">'+js.error+'</div>';
        return;
      }

      // AbuseIPDB card
      let abuse = js.abuse || {};
      let abuseCard = '';
      if(abuse.error){
        abuseCard = `<div class="card-compact"><h6>AbuseIPDB</h6><div class="text-danger">${abuse.error}</div></div>`;
      } else {
        const d = abuse.details || {};
        const ipCopy = `<button class="btn btn-sm btn-ghost copy-btn" onclick="copyToClipboard('${d.ipAddress || abuse.ip || ''}')">Copy</button>`;
        const scoreHtml = scoreBadge(d.abuseConfidenceScore ?? abuse.score ?? '-');
        const riskHtml = riskLabel(d.abuseConfidenceScore ?? abuse.score ?? '-');
        const cc = d.countryCode || abuse.country || '';
        const flag = countryFlag(cc) || cc || '-';
        abuseCard = `<div class="card-compact mb-2">
          <h6>AbuseIPDB</h6>
          ${kvRow('IP', d.ipAddress || abuse.ip || '-', ipCopy)}
          ${kvRow('Abuse Score', scoreHtml)}
          ${kvRow('Risk', riskHtml)}
          ${kvRow('Country', flag)}
          ${kvRow('ISP', d.isp || '-')}
          ${kvRow('Usage Type', d.usageType || '-')}
          ${kvRow('Domain / Reverse DNS', d.domain || '-')}
          ${kvRow('Hostnames', (d.hostnames && d.hostnames.length)? d.hostnames : '-')}
          ${kvRow('Total Reports', d.totalReports ?? 0)}
          ${kvRow('Distinct Reporters', d.numDistinctUsers ?? 0)}
          ${kvRow('Last Reported At', d.lastReportedAt || '-')}
        </div>`;
      }

      // OTX card
      let otx = js.otx || {};
      let otxCard = '';
      lastOtxPassiveDns = [];
      if(otx.error){
        otxCard = `<div class="card-compact"><h6>OTX</h6><div class="text-danger">${otx.error}</div></div>`;
      } else {
        const od = otx.data || {};
        const whoisText = (typeof od.whois === 'string') ? od.whois :
                           (od.raw && typeof od.raw.whois === 'string' ? od.raw.whois : '');
        const whoisCopyBtn = whoisText ? `<button class="btn btn-sm btn-ghost copy-btn" onclick="copyToClipboard(\`${whoisText.replace(/`/g,'\\`')}\`)">Copy</button>` : '';
        lastOtxPassiveDns = Array.isArray(od.passive_dns) ? od.passive_dns : [];
        const pdnsPreview = lastOtxPassiveDns.slice(0,5).map(x => x.host || x.hostname || JSON.stringify(x)).join(', ') || '-';
        const viewAllBtn = lastOtxPassiveDns.length > 5
              ? `<button class="btn btn-sm btn-primary copy-btn" onclick="openPdnsModal()">View all (${lastOtxPassiveDns.length})</button>` : '';
        const ccMaybe = (od.raw && od.raw.country_name && od.raw.country_name.length===2) ? od.raw.country_name : '';
        const flag2 = ccMaybe ? countryFlag(ccMaybe) : (od.country_name || '-');
        otxCard = `<div class="card-compact mb-2">
          <h6>OTX (${otx.source || 'OTX'})</h6>
          ${kvRow('Indicator', od.indicator || '-')}
          ${kvRow('Reputation', od.reputation ?? '-')}
          ${kvRow('Country', flag2)}
          ${kvRow('Pulse Count', od.pulse_count ?? (od.raw && od.raw.pulse_info? od.raw.pulse_info.count : '-'))}
          ${kvRow('Whois', whoisText ? 'Available' : '-', whoisCopyBtn)}
          ${kvRow('Passive DNS', pdnsPreview, viewAllBtn)}
        </div>`;
      }

      const rawHtml = `<details style="margin-top:6px;color:#9ca3af;"><summary>Show raw JSON</summary><pre class="raw">${JSON.stringify(js, null, 2)}</pre></details>`;
      resultEl.innerHTML = `<div>${abuseCard}${otxCard}${rawHtml}</div>`;

      refreshTopList();
      refreshTotals();

    } catch(e){
      resultEl.innerHTML = '<div class="text-danger">Error: '+e.message+'</div>';
    }
  }

  function openPdnsModal(){
    const body = document.getElementById('pdnsBody');
    if(!lastOtxPassiveDns || lastOtxPassiveDns.length===0){
      body.innerHTML = '<p class="small-muted">No Passive DNS records.</p>';
    } else {
      let html = '<div class="table-responsive"><table class="table table-dark table-sm"><thead><tr><th>#</th><th>Host</th><th>IP</th><th>Last Seen</th></tr></thead><tbody>';
      lastOtxPassiveDns.forEach((r,i) => {
        const host = r.host || r.hostname || '-';
        const ip = r.ip || r.address || '-';
        const ts = r.last || r.last_seen || r.first || '-';
        html += `<tr><td>${i+1}</td><td>${host}</td><td>${ip}</td><td>${ts}</td></tr>`;
      });
      html += '</tbody></table></div>';
      body.innerHTML = html;
    }
    const modal = new bootstrap.Modal(document.getElementById('pdnsModal'));
    modal.show();
  }

  async function fetchBlacklist(){
    if(!confirm('Fetch latest blacklist from AbuseIPDB and update DB?')) return;
    document.getElementById('fetchResult').innerText = 'Fetching...';
    try {
      const resp = await fetch('{{ url_for("api_fetch_blacklist") }}', { method:'POST' });
      const js = await resp.json();
      if(js.error) document.getElementById('fetchResult').innerText = 'Error: '+js.error;
      else document.getElementById('fetchResult').innerText = 'Added/Updated: '+js.added+' records';
      refreshTopList();
      refreshTotals();
    } catch(e){
      document.getElementById('fetchResult').innerText = 'Error: '+e.message;
    }
  }

  async function refreshTopList(){
    const el = document.getElementById('topList');
    el.innerHTML = '<p class="small-muted">Loading...</p>';
    try {
      const resp = await fetch('{{ url_for('api_top_malicious') }}');
      const js = await resp.json();
      if(js.error){ el.innerHTML = '<div class="text-danger">'+js.error+'</div>'; updateThreatChart(0,0,0); return; }
      if(js.items.length === 0){
        el.innerHTML = '<p class="small-muted">No records</p>';
        markersLayer.clearLayers();
        updateThreatChart(0,0,0);
        return;
      }
      let html = '<div class="table-responsive"><table class="table table-dark table-sm"><thead><tr><th>IP</th><th>Score</th><th>Risk</th><th>Country</th><th>Last Seen</th></tr></thead><tbody>';
      markersLayer.clearLayers();

      // counts from actual rows
      let malicious = 0, suspicious = 0, clean = 0;

      for (const r of js.items){
        const cc = r.country || '';
        const flag = countryFlag(cc) || cc || '-';
        const sBadge = scoreBadge(r.score ?? '-');
        const rBadge = riskLabel(r.score ?? '-');
        html += `<tr><td>${r.ip}</td><td>${sBadge}</td><td>${rBadge}</td><td>${flag}</td><td>${r.last_seen || '-'}</td></tr>`;

        // counting by thresholds
        const s = Number(r.score || 0);
        if(s >= 75) malicious++;
        else if(s >= 30) suspicious++;
        else clean++;

        // add marker to map
        try{
          const g = await (await fetch(`{{ url_for('api_geo') }}?ip=${encodeURIComponent(r.ip)}`)).json();
          if(g && g.lat && g.lon){
            const popup = `<strong>${r.ip}</strong><br/>Score: ${s || '-'}<br/>${g.city || ''} ${g.country || ''}<br/>ISP: ${g.isp || '-'}`;
            L.marker([g.lat, g.lon]).bindPopup(popup).addTo(markersLayer);
          }
        }catch(e){}
      }
      el.innerHTML = html + '</tbody></table></div>';

      // Update chart (always-visible wedges; tooltips show true counts)
      updateThreatChart(clean, suspicious, malicious);

    } catch(e){
      el.innerHTML = '<div class="text-danger">Error: '+e.message+'</div>';
      updateThreatChart(0,0,0);
    }
  }

  async function refreshTotals(){
    try {
      const resp = await fetch('{{ url_for('api_totals') }}');
      const js = await resp.json();
      document.getElementById('totalRecords').innerText = js.total_records;
      const lu = document.getElementById('lastUpdate');
      if(lu) lu.innerText = js.current_time;
    } catch(e){}
  }

  // initial load
  refreshTopList();
  refreshTotals();
</script>
</body>
</html>
"""

# ------------------ ROUTES ------------------
@app.route('/')
def root():
    if session.get("user") == ADMIN_USER:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = request.form.get('username', '')
        p = request.form.get('password', '')
        if u == ADMIN_USER and p == ADMIN_PASS:
            session['user'] = ADMIN_USER
            return redirect(url_for('dashboard'))
        flash('Invalid credentials')
        return render_template_string(LOGIN_HTML)
    else:
        return render_template_string(LOGIN_HTML)

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('Logged out')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db_conn()
    cur = db.cursor()
    cur.execute("SELECT COUNT(*) as total FROM iocs")
    total_records = cur.fetchone()["total"]
    db.close()
    return render_template_string(
        DASHBOARD_HTML,
        total_records=total_records,
        current_time=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    )

# ------------------ API ENDPOINTS ------------------
@app.route('/api/check_ip', methods=['POST'])
@login_required
def api_check_ip():
    try:
        data = request.get_json() or {}
        ip = data.get('ip') or data.get('address') or ''
        ip = ip.strip()
        if not ip:
            return jsonify({"error":"No IP provided"}), 400
        if not is_valid_ip(ip):
            return jsonify({"error":"Invalid IP address"}), 400
        try:
            abuse_result = check_abuseipdb(ip)
        except Exception as e:
            abuse_result = {"error": f"AbuseIPDB error: {str(e)}"}
        try:
            otx = query_otx(ip)
        except Exception as e:
            otx = {"error": f"OTX error: {str(e)}"}
        return jsonify({"abuse": abuse_result, "otx": otx})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/fetch_blacklist', methods=['POST'])
@login_required
def api_fetch_blacklist():
    try:
        added = fetch_blacklist(limit=100)
        return jsonify({"added": added})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/top_malicious', methods=['GET'])
@login_required
def api_top_malicious():
    try:
        db = get_db_conn()
        cur = db.cursor()
        cur.execute("SELECT ip_address as ip, abuse_confidence as score, country_code as country, last_seen FROM iocs ORDER BY abuse_confidence DESC LIMIT 25")
        rows = cur.fetchall()
        items = [{"ip": r["ip"], "score": r["score"], "country": r["country"], "last_seen": r["last_seen"]} for r in rows]
        db.close()
        return jsonify({"items": items})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/totals', methods=['GET'])
@login_required
def api_totals():
    try:
        db = get_db_conn()
        cur = db.cursor()
        cur.execute("SELECT COUNT(*) as total FROM iocs")
        total = cur.fetchone()["total"]
        db.close()
        return jsonify({"total_records": total, "current_time": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/geo', methods=['GET'])
@login_required
def api_geo():
    ip = request.args.get("ip","").strip()
    if not ip or not is_valid_ip(ip):
        return jsonify({"error":"invalid ip"}), 400
    try:
        g = geo_lookup(ip)
        return jsonify(g)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ------------------ EXPORTS (CSV/JSON/STIX) ------------------
@app.route('/export/iocs.csv')
@login_required
def export_iocs_csv():
    db = get_db_conn()
    cur = db.cursor()
    cur.execute("SELECT ip_address, abuse_confidence, country_code, last_seen FROM iocs ORDER BY abuse_confidence DESC")
    rows = cur.fetchall()
    db.close()
    # build CSV
    lines = ["ip_address,abuse_confidence,country_code,last_seen,risk_label"]
    for r in rows:
        label, _ = risk_label(r["abuse_confidence"])
        ip = r["ip_address"] or ""
        score = r["abuse_confidence"] if r["abuse_confidence"] is not None else ""
        cc = r["country_code"] or ""
        ls = r["last_seen"] or ""
        lines.append(f"{ip},{score},{cc},{ls},{label}")
    data = "\n".join(lines)
    return Response(
        data,
        mimetype="text/csv",
        headers={"Content-Disposition":"attachment; filename=iocs_export.csv"}
    )

@app.route('/export/iocs.json')
@login_required
def export_iocs_json():
    db = get_db_conn()
    cur = db.cursor()
    cur.execute("SELECT ip_address, abuse_confidence, country_code, last_seen FROM iocs ORDER BY abuse_confidence DESC")
    rows = [dict(r) for r in cur.fetchall()]
    db.close()
    # add risk label
    for r in rows:
        r["risk_label"] = risk_label(r.get("abuse_confidence"))[0]
    return Response(
        json.dumps({"generated_at": utcnow_iso(), "items": rows}, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition":"attachment; filename=iocs_export.json"}
    )

@app.route('/export/iocs.stix')
@login_required
def export_iocs_stix():
    # minimal STIX 2.1 bundle with indicator objects for IPs
    db = get_db_conn()
    cur = db.cursor()
    cur.execute("SELECT ip_address, abuse_confidence, country_code, last_seen FROM iocs ORDER BY abuse_confidence DESC")
    rows = [dict(r) for r in cur.fetchall()]
    db.close()
    now = utcnow_iso()
    objects = []
    for r in rows:
        ip = r["ip_address"]
        score = r.get("abuse_confidence", 0) or 0
        label = risk_label(score)[0]
        ind = {
          "type": "indicator",
          "spec_version": "2.1",
          "id": f"indicator--{uuid.uuid4()}",
          "created": now,
          "modified": now,
          "name": f"IP reputation: {ip}",
          "description": f"AbuseIPDB score {score}, risk {label}",
          "indicator_types": ["malicious-activity"] if score >= 30 else ["anomalous-activity"],
          "pattern": f"[ipv4-addr:value = '{ip}']",
          "pattern_type": "stix",
          "valid_from": now,
          "x_abuseipdb_score": score,
          "x_country_code": r.get("country_code")
        }
        objects.append(ind)
    bundle = {
      "type": "bundle",
      "id": f"bundle--{uuid.uuid4()}",
      "spec_version": "2.1",
      "objects": objects
    }
    return Response(
        json.dumps(bundle, indent=2),
        mimetype="application/stix+json",
        headers={"Content-Disposition":"attachment; filename=iocs_export.stix.json"}
    )

# ------------------ RUN FLASK APP ------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
