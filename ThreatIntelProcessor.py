# ThreatIntelProcessor.py
# Streamlit version of ThreatIntelProcessor — AbuseIPDB + OTX + Geo + Exports
# Developed for Streamlit deploy by Dip Kar (converted from Flask UI)
import streamlit as st
import requests, sqlite3, json, ipaddress, socket, uuid, os
from datetime import datetime, timezone
from streamlit_folium import st_folium
import folium
import pandas as pd

st.set_page_config(page_title="ThreatIntel Processor", layout="wide")

# ------------------ CONFIG / DB ------------------
DB_PATH = "threat_intel_singlefile.db"
ABUSE_BLACKLIST_URL = "https://api.abuseipdb.com/api/v2/blacklist"
ABUSE_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
OTX_IPV4_GENERAL = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
IP_GEO_API = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,lat,lon,isp,org,as,query"

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    db = get_db()
    cur = db.cursor()
    cur.execute("""
      CREATE TABLE IF NOT EXISTS iocs (
        ip_address TEXT PRIMARY KEY,
        abuse_confidence INTEGER,
        country_code TEXT,
        last_seen TEXT
      )""")
    cur.execute("""
      CREATE TABLE IF NOT EXISTS checks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        score INTEGER,
        country TEXT,
        checked_at TEXT,
        source TEXT
      )""")
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
      )""")
    db.commit(); db.close()

init_db()

def utcnow_iso(): return datetime.now(timezone.utc).isoformat()
def is_valid_ip(ip):
    try: ipaddress.ip_address(ip); return True
    except: return False
def reverse_dns(ip):
    try: return socket.gethostbyaddr(ip)[0]
    except: return None

# ------------------ API FUNCTIONS ------------------
def fetch_blacklist(abuse_key, limit=100):
    if not abuse_key:
        raise RuntimeError("AbuseIPDB key missing")
    headers = {"Accept":"application/json","Key":abuse_key}
    params = {"limit": limit}
    r = requests.get(ABUSE_BLACKLIST_URL, headers=headers, params=params, timeout=20)
    r.raise_for_status()
    data = r.json().get("data", [])
    db = get_db(); cur = db.cursor(); added = 0
    for rec in data:
        ip = rec.get("ipAddress") or rec.get("ip")
        score = rec.get("abuseConfidenceScore",0)
        cc = rec.get("countryCode") or ""
        last = utcnow_iso()
        if not ip: continue
        cur.execute("INSERT OR REPLACE INTO iocs (ip_address, abuse_confidence, country_code, last_seen) VALUES (?,?,?,?)",
                    (ip, score, cc, last))
        added += 1
    db.commit(); db.close()
    return added

def check_abuseipdb(ip, abuse_key):
    if not abuse_key:
        return {"error":"AbuseIPDB key missing"}
    headers = {"Accept":"application/json","Key":abuse_key}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    r = requests.get(ABUSE_CHECK_URL, headers=headers, params=params, timeout=12)
    r.raise_for_status()
    js = r.json().get("data", {}) if isinstance(r.json(), dict) else {}
    score = js.get("abuseConfidenceScore", 0)
    country = js.get("countryCode") or "-"
    db = get_db(); cur = db.cursor()
    cur.execute("INSERT INTO checks (ip, score, country, checked_at, source) VALUES (?,?,?,?,?)",
                (ip, score, country, utcnow_iso(), "AbuseIPDB"))
    cur.execute("INSERT OR REPLACE INTO iocs (ip_address, abuse_confidence, country_code, last_seen) VALUES (?,?,?,?)",
                (ip, score, country, utcnow_iso()))
    db.commit(); db.close()
    domain = js.get("domain") or reverse_dns(ip) or "-"
    return {"ip": ip, "score": score, "country": country, "details": js, "domain": domain}

def query_otx(ip, otx_key):
    if not otx_key:
        return {"error":"OTX key not set"}
    headers = {"X-OTX-API-KEY": otx_key}
    try:
        url = OTX_IPV4_GENERAL.format(ip=ip)
        r = requests.get(url, headers=headers, timeout=12)
        if r.status_code == 200:
            return {"source":"OTX-general","data": r.json()}
    except Exception as e:
        return {"error": str(e)}
    return {"error":"no-data"}

def geo_lookup(ip):
    db = get_db(); cur = db.cursor()
    cur.execute("SELECT * FROM geocache WHERE ip=?", (ip,))
    row = cur.fetchone()
    if row:
        db.close(); return dict(row)
    try:
        r = requests.get(IP_GEO_API.format(ip=ip), timeout=8)
        js = r.json()
        if js.get("status") != "success": db.close(); return {}
        cur = db.cursor()
        cur.execute("""INSERT OR REPLACE INTO geocache (ip, country, country_code, region, city, lat, lon, isp, org, asn, updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (ip, js.get("country"), js.get("countryCode"), js.get("regionName"), js.get("city"),
                     js.get("lat"), js.get("lon"), js.get("isp"), js.get("org"), js.get("as"), utcnow_iso()))
        db.commit(); db.close()
        js["ip"] = ip; js["country_code"] = js.get("countryCode")
        return js
    except:
        try: db.close()
        except: pass
        return {}

# ------------------ UI ------------------
st.title("⚡ ThreatIntel Processor")
st.markdown("Developed by **Dip Kar** — AbuseIPDB + OTX + Geo + Exports")

# Sidebar keys & tips
st.sidebar.title("Settings & Keys")
st.sidebar.info("Add AbuseIPDB / OTX keys here. For public deploy, users should use their own keys (do not commit keys).")

use_secrets = st.sidebar.checkbox("Prefer using Streamlit secrets (if set)", value=True)
secrets_abuse = st.secrets.get("ABUSEIPDB_API_KEY") if (use_secrets and hasattr(st, "secrets") and "ABUSEIPDB_API_KEY" in st.secrets) else ""
secrets_otx = st.secrets.get("OTX_API_KEY") if (use_secrets and hasattr(st, "secrets") and "OTX_API_KEY" in st.secrets) else ""

abuse_key = st.sidebar.text_input("AbuseIPDB API Key", value=secrets_abuse, type="password")
otx_key = st.sidebar.text_input("OTX API Key (optional)", value=secrets_otx, type="password")
st.sidebar.checkbox("Keep keys only for session (no permanent save)", value=True)

st.sidebar.markdown("---")
st.sidebar.write("- Do NOT commit API keys to public GitHub. Use Streamlit Secrets.")
st.sidebar.write("- ip-api free geo is rate-limited; caching is used.")

# Main columns
col1, col2 = st.columns([1,2])

with col1:
    st.subheader("IP Lookup")
    ip_input = st.text_input("Enter IP (e.g. 8.8.8.8)")
    if st.button("Check IP"):
        if not ip_input:
            st.warning("Enter IP first")
        elif not is_valid_ip(ip_input.strip()):
            st.error("Invalid IP")
        else:
            with st.spinner("Querying AbuseIPDB & OTX..."):
                abuse_res = {}
                otx_res = {}
                try:
                    abuse_res = check_abuseipdb(ip_input.strip(), abuse_key)
                except Exception as e:
                    abuse_res = {"error": str(e)}
                try:
                    otx_res = query_otx(ip_input.strip(), otx_key)
                except Exception as e:
                    otx_res = {"error": str(e)}
            st.markdown("**AbuseIPDB Result**")
            st.json(abuse_res)
            st.markdown("**OTX Result**")
            st.json(otx_res)

    st.markdown("---")
    if st.button("Fetch AbuseIPDB Blacklist (update DB)"):
        if not abuse_key:
            st.error("Set AbuseIPDB key first in sidebar or secrets")
        else:
            with st.spinner("Fetching blacklist..."):
                try:
                    added = fetch_blacklist(abuse_key, limit=100)
                    st.success(f"Added/Updated {added} records")
                except Exception as e:
                    st.error(f"Error: {e}")

    st.markdown("---")
    st.subheader("Manual Exports")
    df_all = None
    try:
        db = get_db(); cur = db.cursor()
        cur.execute("SELECT ip_address, abuse_confidence, country_code, last_seen FROM iocs ORDER BY abuse_confidence DESC")
        rows = [dict(r) for r in cur.fetchall()]; db.close()
        df_all = pd.DataFrame(rows)
    except:
        df_all = pd.DataFrame(columns=["ip_address","abuse_confidence","country_code","last_seen"])

    if not df_all.empty:
        csv = df_all.to_csv(index=False)
        st.download_button("Download CSV", csv, file_name="iocs_export.csv", mime="text/csv")
        st.download_button("Download JSON", df_all.to_json(orient="records", indent=2), file_name="iocs_export.json")
        if st.button("Generate minimal STIX bundle"):
            objects=[]
            now = utcnow_iso()
            for _,r in df_all.iterrows():
                ip = r["ip_address"]
                score = int(r["abuse_confidence"] or 0)
                obj = {"type":"indicator","spec_version":"2.1","id":f"indicator--{uuid.uuid4()}",
                       "created":now,"modified":now,"name":f"IP reputation: {ip}",
                       "pattern":f"[ipv4-addr:value = '{ip}']","pattern_type":"stix",
                       "valid_from":now,"x_abuseipdb_score":score,"x_country_code":r.get("country_code")}
                objects.append(obj)
            bundle={"type":"bundle","id":f"bundle--{uuid.uuid4()}","spec_version":"2.1","objects":objects}
            st.download_button("Download STIX JSON", json.dumps(bundle, indent=2), file_name="iocs_export.stix.json")

with col2:
    st.subheader("Top Malicious IPs & GeoMap")
    df = df_all.copy() if df_all is not None else pd.DataFrame()
    if df.empty:
        st.info("No IOC records yet. Use 'Fetch AbuseIPDB Blacklist' or check some IPs.")
    else:
        def risk_label(x):
            try:
                s = int(x)
            except:
                return "Unknown"
            if s >= 90: return "Critical"
            if s >= 75: return "High"
            if s >= 30: return "Medium"
            return "Low"
        df["risk"] = df["abuse_confidence"].apply(risk_label)
        st.dataframe(df.rename(columns={"ip_address":"IP","abuse_confidence":"Score","country_code":"Country","last_seen":"Last Seen"}).head(50), height=260)

        m = folium.Map(location=[20,0], zoom_start=2)
        mapped = 0
        for _, row in df.head(200).iterrows():
            ip = row["ip_address"]
            try:
                g = geo_lookup(ip)
                lat = g.get("lat"); lon = g.get("lon")
                if lat and lon:
                    color = 'red' if int(row["abuse_confidence"] or 0) >= 75 else 'orange' if int(row["abuse_confidence"] or 0) >= 30 else 'green'
                    folium.CircleMarker(location=[lat,lon], radius=6, tooltip=f"{ip} | {row['abuse_confidence']} | {row.get('country_code','')}", color=color, fill=True).add_to(m)
                    mapped += 1
            except:
                pass
        if mapped == 0:
            st.info("No geo locations found (ip-api rate-limited or missing).")
        st_folium(m, width=800, height=420)

st.markdown("---")
st.markdown("**Notes / Security**")
st.markdown("- Do NOT commit API keys to public GitHub. Use Streamlit Secrets (recommended).")
st.markdown("- ip-api free endpoint is rate-limited; caching is implemented. For heavy use get paid geo provider.")
st.markdown("- Streamlit Cloud provides automatic HTTPS. Each visitor should provide own keys (recommended).")
