#!/usr/bin/env python3
import os
import re
import textwrap
from urllib.parse import quote_plus
from collections import Counter
from datetime import datetime

import requests
import streamlit as st
import networkx as nx
import matplotlib.pyplot as plt
from fpdf import FPDF

# ==============================
# Config & constants
# ==============================

MITRE_API_BASE = "https://cveawg.mitre.org/api/cve"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

POPULAR_CVES = [
    "CVE-2021-44228",
    "CVE-2017-0144",
    "CVE-2021-34527",
    "CVE-2022-26134",
    "CVE-2021-21985",
    "CVE-2024-6387",
    "CVE-2024-21762",
    "CVE-2024-30051",
    "CVE-2025-24085",
    "CVE-2025-24793",
]

VENDOR_COUNTRY_MAP = {
    "microsoft": "United States",
    "apache": "United States",
    "google": "United States",
    "chromium": "United States",
    "mozilla": "United States",
    "fortinet": "United States",
    "cisco": "United States",
    "vmware": "United States",
    "red hat": "United States",
    "oracle": "United States",
    "ibm": "United States",
    "atlassian": "Australia",
    "huawei": "China",
    "qnap": "Taiwan",
    "samsung": "South Korea",
    "siemens": "Germany",
    "sap": "Germany",
    "trend micro": "Japan",
    "toshiba": "Japan",
    "sony": "Japan",
}

PATCH_VENDOR_KEYWORDS = [
    "microsoft.com",
    "security-update-guide",
    "msrc",
    "support.microsoft.com",
    "learn.microsoft.com",
    "oracle.com",
    "linux.oracle.com",
    "access.redhat.com",
    "kb.vmware.com",
    "fortinet.com",
    "cisco.com",
    "kb.juniper.net",
    "support.apple.com",
    "kb.cert.org",
    "atlassian.com",
    "github.com/advisories",
]

# ==============================
# Helper functions
# ==============================

def normalize_cve_id(cve_id: str) -> str:
    if not cve_id:
        return ""
    cve_id = cve_id.strip().upper()
    cve_id = cve_id.replace("–", "-").replace("—", "-").replace("－", "-")
    if not cve_id.startswith("CVE-"):
        cve_id = "CVE-" + cve_id
    return cve_id


def fetch_cve_mitre(cve_id: str):
    url = f"{MITRE_API_BASE}/{quote_plus(cve_id)}"
    try:
        resp = requests.get(url, timeout=15)
    except requests.RequestException:
        return None, "Network error while contacting MITRE CVE API."

    if resp.status_code != 200:
        return None, f"MITRE API error: HTTP {resp.status_code}"

    try:
        data = resp.json()
    except Exception:
        return None, "Failed to parse JSON from MITRE CVE API."

    if not isinstance(data, dict) or "cveMetadata" not in data:
        return None, "Invalid response from MITRE CVE API."

    return data, None


def get_severity_label(score):
    try:
        score = float(score)
    except Exception:
        return "Unknown", "⚪", "sev-unknown"

    if score >= 9.0:
        return f"Critical ({score})", "🔴", "sev-critical"
    elif score >= 7.0:
        return f"High ({score})", "🟠", "sev-high"
    elif score >= 4.0:
        return f"Medium ({score})", "🟡", "sev-medium"
    elif score > 0:
        return f"Low ({score})", "🟢", "sev-low"
    else:
        return "None (0.0)", "⚪", "sev-none"


def predict_severity_from_text(summary: str):
    if not summary:
        return None, "Unknown", "⚪", "sev-unknown", "Predicted"

    s = summary.lower()

    if "remote code execution" in s or " rce" in s or "rce " in s or "execute arbitrary code" in s:
        score = 9.8
    elif "privilege escalation" in s or "elevation of privilege" in s or "eop" in s or "elevate privilege" in s or "elevate privileges" in s:
        score = 8.8
    elif "sql injection" in s or "sql-injection" in s or "sqli" in s:
        score = 8.5
    elif "directory traversal" in s or "path traversal" in s:
        score = 7.5
    elif "cross-site scripting" in s or "xss" in s:
        score = 6.5
    elif "information disclosure" in s or "info leak" in s or "leak" in s:
        score = 5.5
    elif "denial of service" in s or "dos" in s:
        score = 5.0
    else:
        score = 5.0

    label, icon, css = get_severity_label(score)
    return score, label, icon, css, "Predicted"


def predict_epss_score(score, in_kev: bool):
    try:
        score = float(score) if score is not None else 5.0
    except Exception:
        score = 5.0

    base = score / 10.0
    if in_kev:
        base = min(0.95, base + 0.25)
    else:
        base = min(0.90, base + 0.05)

    if score >= 9.0:
        base = max(base, 0.85)
    elif score <= 4.0:
        base = min(base, 0.55)

    return round(base, 3)


def wrap_text(text, width=90):
    return "\n".join(textwrap.wrap(text or "", width=width))


def search_github_pocs(cve_id: str, max_results: int = 5):
    q = f'{cve_id} PoC'
    url = "https://api.github.com/search/repositories"
    params = {
        "q": q,
        "sort": "stars",
        "order": "desc",
        "per_page": max_results
    }
    headers = {"Accept": "application/vnd.github+json"}
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        resp = requests.get(url, params=params, headers=headers, timeout=15)
    except requests.RequestException:
        return [], "Network error while contacting GitHub."

    if resp.status_code == 403:
        return [], "GitHub rate limit exceeded (try later or set GITHUB_TOKEN)."
    if resp.status_code != 200:
        return [], f"GitHub API error: HTTP {resp.status_code}"

    try:
        data = resp.json()
    except Exception:
        return [], "Failed to parse GitHub JSON."

    items = data.get("items", []) or []
    results = []
    for item in items:
        results.append({
            "name": item.get("full_name"),
            "url": item.get("html_url"),
            "description": item.get("description"),
            "stars": item.get("stargazers_count", 0),
            "language": item.get("language")
        })
    return results, None


# ==============================
# CISA KEV loader & checker
# ==============================

def load_kev_catalog():
    if "kev_set" in st.session_state and "kev_list" in st.session_state:
        return (
            st.session_state["kev_set"],
            st.session_state["kev_list"],
            st.session_state.get("kev_error"),
        )

    try:
        resp = requests.get(CISA_KEV_URL, timeout=20)
        if resp.status_code != 200:
            st.session_state["kev_set"] = set()
            st.session_state["kev_list"] = []
            st.session_state["kev_error"] = f"CISA KEV HTTP {resp.status_code}"
            return st.session_state["kev_set"], st.session_state["kev_list"], st.session_state["kev_error"]

        data = resp.json()
        vulns = data.get("vulnerabilities", []) or data.get("vulnerability", []) or []
        kev_ids = set()
        kev_list = []
        for v in vulns:
            cve = v.get("cveID") or v.get("cve_id") or v.get("cveId")
            if cve:
                cid = cve.strip().upper()
                kev_ids.add(cid)
                kev_list.append({
                    "cve": cid,
                    "vendor": v.get("vendorProject", ""),
                    "product": v.get("product", ""),
                    "dateAdded": v.get("dateAdded", ""),
                    "desc": v.get("shortDescription", ""),
                })
        st.session_state["kev_set"] = kev_ids
        st.session_state["kev_list"] = kev_list
        st.session_state["kev_error"] = None
        return kev_ids, kev_list, None
    except Exception as e:
        st.session_state["kev_set"] = set()
        st.session_state["kev_list"] = []
        st.session_state["kev_error"] = f"Error loading KEV: {e}"
        return st.session_state["kev_set"], st.session_state["kev_list"], st.session_state["kev_error"]


# ==============================
# Attack flow logic
# ==============================

def detect_category(summary: str, references=None, cve_id: str = ""):
    text_blobs = [summary or ""]
    if references:
        text_blobs.extend(references)
    if cve_id:
        text_blobs.append(cve_id)

    s = " ".join(text_blobs).lower()
    cid = (cve_id or "").upper()

    if "log4j" in s or "log4shell" in s or cid == "CVE-2021-44228":
        return "Remote Code Execution (Log4Shell)"
    if cid == "CVE-2017-0144" or ("eternalblue" in s and "smb" in s):
        return "Remote Code Execution (Wormable SMB)"
    if cid == "CVE-2021-34527" or "printnightmare" in s:
        if "privilege" in s or "elevation" in s:
            return "Privilege Escalation / Remote Code Execution (PrintNightmare)"
        return "Remote Code Execution (PrintNightmare)"
    if cid == "CVE-2022-26134" or ("ognl" in s and "confluence" in s):
        return "Remote Code Execution (Confluence OGNL)"
    if cid == "CVE-2021-4034" or "pwnkit" in s:
        return "Privilege Escalation (PwnKit)"
    if "vpn" in s and ("fortigate" in s or "fortinet" in s) and "authentication" in s:
        return "Auth Bypass (VPN / Edge Device)"

    if "sql injection" in s or "sql-injection" in s or "sqli" in s:
        return "SQL Injection"
    if "cross-site scripting" in s or "xss" in s:
        return "Cross-Site Scripting"
    if ("privilege escalation" in s or
        "elevation of privilege" in s or
        "eop" in s or
        "elevate privilege" in s or
        "elevate privileges" in s):
        return "Privilege Escalation"
    if "remote code execution" in s or " rce" in s or "rce " in s:
        return "Remote Code Execution"
    if "directory traversal" in s or "path traversal" in s:
        return "Directory Traversal"
    if "deserialization" in s:
        return "Insecure Deserialization"
    if "buffer overflow" in s or "heap overflow" in s or "stack overflow" in s:
        return "Memory Corruption / Overflow"
    if "authentication bypass" in s or "bypass authentication" in s:
        return "Auth Bypass"
    if "information disclosure" in s or "info leak" in s:
        return "Information Disclosure"

    return "Generic Attack Path"


def build_attack_template(category: str, summary: str):
    base_nodes = []
    base_edges = []
    steps = []

    category = category or "Generic Attack Path"
    cat = category.lower()
    attacker = "Attacker"
    goal = "Target Impact / Post-Exploitation"

    if "sql injection" in cat:
        base_nodes = [
            attacker,
            "Web Application Frontend",
            "Vulnerable SQL Query",
            "Database Server",
            goal
        ]
        steps = [
            "The attacker sends crafted input via a web parameter.",
            "The web application concatenates input into an SQL query without sanitization.",
            "The database executes the malicious query.",
            "The attacker can read/modify data and potentially execute OS-level commands.",
        ]
    elif "cross-site scripting" in cat:
        base_nodes = [
            attacker,
            "Victim Browser",
            "Vulnerable Web Page",
            "Injected JavaScript",
            goal
        ]
        steps = [
            "The attacker crafts a malicious URL or payload containing JavaScript.",
            "The victim loads a vulnerable page that reflects or stores the payload.",
            "The injected JavaScript executes in the victim's browser.",
            "The attacker can steal cookies, tokens, or perform actions as the victim.",
        ]
    elif "remote code execution" in cat:
        base_nodes = [
            attacker,
            "Network / Internet",
            "Vulnerable Service / Component",
            "Remote Code Execution",
            goal
        ]
        steps = [
            "The attacker identifies an exposed service running the vulnerable version.",
            "The attacker sends a crafted request to trigger the vulnerability.",
            "The vulnerable component executes attacker-controlled code.",
            "The attacker gains remote access and can run arbitrary commands.",
        ]
    elif "privilege escalation" in cat:
        base_nodes = [
            attacker,
            "Low-Privilege Account",
            "Vulnerable Local Component",
            "Privilege Escalation",
            goal
        ]
        steps = [
            "The attacker obtains a low-privilege account.",
            "The attacker runs a local exploit targeting the vulnerable component.",
            "The exploit abuses improper permission checks or memory corruption.",
            "The attacker escalates to higher privileges (e.g., SYSTEM/root).",
        ]
    elif "directory traversal" in cat:
        base_nodes = [
            attacker,
            "Web Application Input",
            "Path Traversal Handling",
            "Sensitive Files Read",
            goal
        ]
        steps = [
            "The attacker sends input containing ../ traversal sequences.",
            "The application fails to sanitize or normalize the file path.",
            "The attacker reads arbitrary files on the server.",
            "Leaked files may contain secrets or credentials.",
        ]
    elif "deserialization" in cat:
        base_nodes = [
            attacker,
            "Untrusted Serialized Data",
            "Vulnerable Deserialization Logic",
            "Arbitrary Code Execution",
            goal
        ]
        steps = [
            "The attacker crafts a malicious serialized object.",
            "The application deserializes untrusted data without validation.",
            "Gadget chains are triggered during deserialization.",
            "The attacker gains code execution or changes application state.",
        ]
    elif "memory corruption" in cat:
        base_nodes = [
            attacker,
            "Vulnerable Parser / Buffer",
            "Memory Corruption",
            "Control-Flow Hijack",
            goal
        ]
        steps = [
            "The attacker sends oversized or malformed input to a vulnerable parser.",
            "Input overflows a buffer or corrupts memory structures.",
            "Attacker-controlled data overwrites control-flow data.",
            "The attacker can execute arbitrary code or cause a crash.",
        ]
    elif "auth bypass" in cat:
        base_nodes = [
            attacker,
            "Authentication / Access Control Layer",
            "Bypass Condition Met",
            "Unauthorized Access",
            goal
        ]
        steps = [
            "The attacker crafts requests to manipulate auth or access checks.",
            "The application incorrectly validates sessions or tokens.",
            "The attacker bypasses authentication.",
            "The attacker accesses or modifies protected resources.",
        ]
    elif "information disclosure" in cat:
        base_nodes = [
            attacker,
            "Vulnerable Endpoint / Component",
            "Sensitive Data Exposure",
            goal
        ]
        steps = [
            "The attacker interacts with an endpoint returning too much data.",
            "The application fails to filter or mask sensitive fields.",
            "The attacker collects leaked information.",
            "The leaked data is used for further attacks or intel.",
        ]
    else:
        base_nodes = [
            attacker,
            "Entry Point",
            "Vulnerable Component",
            goal
        ]
        steps = [
            "The attacker identifies a vulnerable entry point.",
            "The attacker triggers the vulnerable behavior with crafted input.",
            "The component misbehaves (crash, data leak, code execution).",
            "Impact depends on deployment and environment.",
        ]

    for i in range(len(base_nodes) - 1):
        base_edges.append((base_nodes[i], base_nodes[i + 1]))

    if summary:
        clean_summary = " ".join(str(summary).splitlines()).strip()
        if clean_summary:
            steps.append("Summary (from CVE): " + clean_summary)

    return {
        "category": category,
        "nodes": base_nodes,
        "edges": base_edges,
        "steps": steps,
    }


# ==============================
# Attack graph (matplotlib)
# ==============================

def render_attack_graph(template, cve_id: str):
    nodes = template["nodes"]
    edges = template["edges"]

    G = nx.DiGraph()
    for n in nodes:
        G.add_node(n)
    for src, dst in edges:
        G.add_edge(src, dst)

    pos = nx.spring_layout(G, seed=42)

    fig, ax = plt.subplots(figsize=(8, 6))

    node_colors = []
    for n in G.nodes():
        lname = n.lower()
        if n == "Attacker":
            node_colors.append("#f97316")
        elif "web application" in lname or "network" in lname or "browser" in lname:
            node_colors.append("#22c55e")
        elif "vulnerable" in lname:
            node_colors.append("#eab308")
        elif "database" in lname:
            node_colors.append("#38bdf8")
        elif "impact" in lname or "post-exploitation" in lname:
            node_colors.append("#a855f7")
        else:
            node_colors.append("#06b6d4")

    nx.draw_networkx_nodes(
        G, pos,
        node_size=1500,
        node_color=node_colors,
        ax=ax,
    )

    nx.draw_networkx_edges(
        G, pos,
        arrowstyle="->",
        arrowsize=20,
        edge_color="#e5e7eb",
        width=2.2,
        ax=ax,
    )

    nx.draw_networkx_labels(
        G, pos,
        font_size=9,
        font_color="white",
        ax=ax,
    )

    ax.set_title(f"Attack Flow for {cve_id}", fontsize=12, color="white")
    ax.set_facecolor("#020617")
    fig.patch.set_facecolor("#020617")
    ax.axis("off")
    st.pyplot(fig)


# ==============================
# Analytics
# ==============================

def add_to_history(cve_id, published, vendor, cvss, in_kev):
    if "cve_history" not in st.session_state:
        st.session_state["cve_history"] = []

    year = None
    if published:
        try:
            year = int(str(published)[:4])
        except Exception:
            year = None

    rec = {
        "id": cve_id,
        "year": year,
        "vendor": vendor.lower() if vendor else "unknown",
        "cvss": cvss,
        "kev": bool(in_kev),
    }
    if not any(r["id"] == cve_id for r in st.session_state["cve_history"]):
        st.session_state["cve_history"].append(rec)


def render_trending_chart():
    history = st.session_state.get("cve_history", [])
    years = [r["year"] for r in history if r["year"] is not None]
    if not years:
        st.info("No trend data yet. Analyze a few CVEs first.")
        return

    counts = Counter(years)
    xs = sorted(counts.keys())
    ys = [counts[y] for y in xs]

    fig, ax = plt.subplots(figsize=(6, 3))
    ax.plot(xs, ys, marker="o")
    ax.set_xlabel("Year")
    ax.set_ylabel("# of CVEs analyzed")
    ax.set_title("CVE Trend (based on your analyzed CVEs)")
    st.pyplot(fig)


def render_vendor_chart():
    history = st.session_state.get("cve_history", [])
    vendors = [r["vendor"] for r in history if r["vendor"]]
    if not vendors:
        st.info("No vendor data yet.")
        return

    counts = Counter(vendors)
    top = counts.most_common(8)
    labels = [v.title() for v, _ in top]
    values = [c for _, c in top]

    fig, ax = plt.subplots(figsize=(6, 3))
    ax.bar(labels, values)
    ax.set_xlabel("Vendor")
    ax.set_ylabel("# of CVEs analyzed")
    ax.set_title("Vendor-wise CVEs (session)")
    plt.xticks(rotation=30, ha="right")
    st.pyplot(fig)


def render_country_heatmap():
    history = st.session_state.get("cve_history", [])
    if not history:
        st.info("No data to build country overview yet.")
        return

    countries = []
    for r in history:
        v = r["vendor"]
        country = "Unknown"
        for key, val in VENDOR_COUNTRY_MAP.items():
            if key in v:
                country = val
                break
        countries.append(country)

    counts = Counter(countries)
    labels = list(counts.keys())
    values = [counts[c] for c in labels]

    fig, ax = plt.subplots(figsize=(6, 3))
    ax.bar(labels, values)
    ax.set_xlabel("Country (based on vendor HQ)")
    ax.set_ylabel("# of CVEs analyzed")
    ax.set_title("Country-wise Exploitation Overview (approx.)")
    plt.xticks(rotation=30, ha="right")

    st.pyplot(fig)


def render_live_threat_feed(kev_list):
    if not kev_list:
        st.info("KEV feed not loaded.")
        return

    def parse_date(d):
        try:
            return datetime.strptime(d, "%Y-%m-%d")
        except Exception:
            return datetime.min

    sorted_v = sorted(kev_list, key=lambda x: parse_date(x["dateAdded"]), reverse=True)
    top = sorted_v[:7]

    for v in top:
        st.markdown(
            f"- **{v['cve']}** · `{v.get('vendor','')}` / `{v.get('product','')}`  \n"
            f"  _{v.get('desc','')}_  \n"
            f"  Added: `{v.get('dateAdded','')}`"
        )


# ==============================
# PDF helpers
# ==============================

def pdf_safe(text):
    if text is None:
        return ""
    text = str(text)
    replacements = {
        "–": "-",
        "—": "-",
        "−": "-",
        "•": "*",
        "’": "'",
        "‘": "'",
        "“": '"',
        "”": '"',
        "…": "...",
        "©": "(c)",
        "®": "(R)",
        "™": "(TM)",
    }
    for bad, good in replacements.items():
        text = text.replace(bad, good)
    text = text.encode("latin-1", "ignore").decode("latin-1")
    return text


def break_long_words(text: str, max_len: int = 60) -> str:
    """Insert spaces inside very long 'words' (e.g., URLs) so FPDF can wrap."""
    if not text:
        return ""
    text = str(text)
    parts = []
    for word in text.split(" "):
        if len(word) <= max_len:
            parts.append(word)
        else:
            parts.extend(word[i:i + max_len] for i in range(0, len(word), max_len))
    return " ".join(parts)


def generate_pdf_report(
    cve_id,
    summary,
    sev_label,
    display_score,
    sev_origin,
    epss_score,
    primary_vendor,
    published,
    modified,
    in_kev,
    products,
    refs,
    attack_category,
    steps,
):
    pdf = FPDF()
    pdf.set_margins(15, 15, 15)
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    usable_width = pdf.w - pdf.l_margin - pdf.r_margin

    # Header
    pdf.set_fill_color(15, 23, 42)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Arial", "B", 16)
    pdf.set_x(pdf.l_margin)
    pdf.cell(usable_width, 12, pdf_safe("ZeroDay Visualizer - CVE Report"), ln=True, fill=True)

    pdf.set_font("Arial", "I", 10)
    pdf.set_x(pdf.l_margin)
    pdf.cell(usable_width, 7, pdf_safe("Created by Dip Kar (HackerBlazeX)"), ln=True)
    pdf.ln(4)
    pdf.set_text_color(0, 0, 0)

    # small helper for multi_cell with fixed width
    def mc(text, h=6, font="Arial", style="", size=11, ln_extra=0, max_len=60):
        pdf.set_font(font, style, size)
        pdf.set_x(pdf.l_margin)
        txt = pdf_safe(break_long_words(text, max_len=max_len))
        pdf.multi_cell(usable_width, h, txt)
        if ln_extra:
            pdf.ln(ln_extra)

    # Helper: section heading
    def section(title: str):
        pdf.ln(2)
        mc(title, h=7, font="Arial", style="B", size=12, ln_extra=1)

    # ===== 1. CVE Overview =====
    section("1. CVE Overview")

    if isinstance(display_score, (int, float)):
        score_txt = f"{float(display_score):.1f}"
    else:
        score_txt = str(display_score)

    overview_lines = [
        f"CVE ID: {cve_id}",
        f"Severity: {sev_label}",
        f"Score Source: {sev_origin} (Score: {score_txt})",
        f"EPSS-style risk (estimated): {epss_score}",
        f"Primary Vendor: {primary_vendor}",
        f"Published: {published or 'Unknown'}",
        f"Last Modified: {modified or 'Unknown'}",
        "CISA KEV: " + ("Yes (Known Exploited)" if in_kev else "Not listed"),
    ]
    for line in overview_lines:
        mc(line)

    # divider line
    pdf.ln(2)
    pdf.set_draw_color(180, 180, 180)
    pdf.set_line_width(0.2)
    pdf.set_x(pdf.l_margin)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.l_margin + usable_width, pdf.get_y())
    pdf.ln(4)

    # ===== 2. Technical Summary & Attack Category =====
    section("2. Technical Summary & Attack Category")

    summary_clean = " ".join(str(summary or "").splitlines()).strip()

    mc("Summary", font="Arial", style="B", size=11)
    if summary_clean:
        mc(summary_clean)
    else:
        mc("No summary available.")
    pdf.ln(2)

    mc("Attack Category", font="Arial", style="B", size=11)
    mc(attack_category)

    # ===== 3. High-Level Exploitation Steps =====
    section("3. High-Level Exploitation Steps")

    filtered_steps = []
    for s in steps:
        s_text = str(s).strip()
        if s_text.lower().startswith("summary (from cve):"):
            continue
        filtered_steps.append(" ".join(s_text.splitlines()).strip())

    if not filtered_steps:
        mc("No exploitation steps available.")
    else:
        for i, step in enumerate(filtered_steps, start=1):
            line = f"{i}. {step}"
            mc(line)
            pdf.ln(1)

    # ===== 4. Affected Products (Top 20) =====
    if products:
        section("4. Affected Products (Top 20)")
        for p in products[:20]:
            mc(f"- {p}")
        if len(products) > 20:
            mc(f"... (+{len(products) - 20} more)")

    # ===== 5. References =====
    if refs:
        section("5. References")
        max_refs = min(len(refs), 15)
        for idx in range(max_refs):
            r = refs[idx]
            ref_text = f"[{idx+1}] {r}"
            mc(ref_text, h=6, font="Arial", style="", size=10, max_len=50)
        if len(refs) > max_refs:
            mc(f"... (+{len(refs) - max_refs} more)", h=6, font="Arial", style="", size=10, max_len=50)

    # Footer
    pdf.ln(6)
    footer_text = (
        "Generated by ZeroDay Visualizer - research-focused CVE attack path & "
        "intel dashboard. Use only in authorized, controlled environments."
    )
    mc(footer_text, h=5, font="Arial", style="I", size=9, max_len=70)

    pdf_out = pdf.output(dest="S")
    if isinstance(pdf_out, (bytes, bytearray)):
        return bytes(pdf_out)
    else:
        return str(pdf_out).encode("latin-1", "ignore")


# ==============================
# Streamlit UI
# ==============================

def main():
    st.set_page_config(
        page_title="ZeroDay Visualizer – CVE Attack Paths Dashboard",
        page_icon="🕸️",
        layout="wide",
    )

    if "dark_mode" not in st.session_state:
        st.session_state["dark_mode"] = True

    with st.sidebar:
        st.markdown("## ⚙️ Settings")
        dark_mode = st.checkbox("Dark mode", value=st.session_state["dark_mode"])
        st.session_state["dark_mode"] = dark_mode
        st.markdown("---")
        st.markdown("**About**")
        st.caption(
            "ZeroDay Visualizer – CVE intel, attack paths, PoCs, KEV & analytics.\n"
            "Created by **Dip Kar (HackerBlazeX)**.\n"
            "For blue-team / research use only."
        )

    if dark_mode:
        bg_style = """
        .stApp {
            background: radial-gradient(circle at top, #020617 0, #020617 30%, #020617 60%, #020617 100%);
            color: #e5e7eb;
        }
        """
    else:
        bg_style = """
        .stApp {
            background: #f3f4f6;
            color: #111827;
        }
        """

    st.markdown(
        f"""
        <style>
        {bg_style}
        .neon-title {{
            font-size: 40px;
            font-weight: 900;
            text-align: left;
            color: {"#f9fafb" if dark_mode else "#111827"};
            text-shadow: 0 0 10px #22d3ee, 0 0 40px #0ea5e9;
        }}
        .neon-subtitle {{
            font-size: 16px;
            color: {"#9ca3af" if dark_mode else "#4b5563"};
        }}
        .glass-card {{
            background: {"rgba(15, 23, 42, 0.85)" if dark_mode else "rgba(255,255,255,0.9)"};
            border-radius: 16px;
            padding: 18px 20px;
            border: 1px solid rgba(148, 163, 184, 0.3);
            box-shadow: 0 0 25px rgba(15, 23, 42, 0.4);
        }}
        .metric-card {{
            background: {"radial-gradient(circle at top left, #0f172a, #020617)" if dark_mode else "white"};
            border-radius: 14px;
            padding: 14px 16px;
            border: 1px solid rgba(148, 163, 184, 0.45);
        }}
        .sev-pill {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 999px;
            font-size: 13px;
            font-weight: 600;
        }}
        .sev-critical {{
            background: rgba(248, 113, 113, 0.15);
            border: 1px solid #ef4444;
            color: #b91c1c;
        }}
        .sev-high {{
            background: rgba(251, 146, 60, 0.15);
            border: 1px solid #f97316;
            color: #9a3412;
        }}
        .sev-medium {{
            background: rgba(234, 179, 8, 0.15);
            border: 1px solid #eab308;
            color: #854d0e;
        }}
        .sev-low {{
            background: rgba(34, 197, 94, 0.15);
            border: 1px solid #22c55e;
            color: #166534;
        }}
        .sev-none, .sev-unknown {{
            background: rgba(148, 163, 184, 0.15);
            border: 1px solid #94a3b8;
            color: #374151;
        }}
        .code-pill {{
            background: {"rgba(15, 23, 42, 0.8)" if dark_mode else "rgba(229,231,235,0.9)"};
            border-radius: 999px;
            padding: 3px 10px;
            border: 1px solid rgba(148, 163, 184, 0.6);
            font-size: 12px;
            color: {"#e5e7eb" if dark_mode else "#111827"};
        }}
        </style>
        """,
        unsafe_allow_html=True,
    )

    header_col1, header_col2 = st.columns([3, 1])
    with header_col1:
        st.markdown(
            '<div class="neon-title">🕸️ ZeroDay Visualizer</div>',
            unsafe_allow_html=True,
        )
        st.markdown(
            '<div class="neon-subtitle">Type a CVE ID → see attack paths, EPSS-style risk, KEV status, PoCs & analytics in one dashboard.</div>',
            unsafe_allow_html=True,
        )
    with header_col2:
        st.markdown(
            """
            <div style="text-align:right; margin-top:10px;">
                <span class="code-pill">Created by Dip Kar (HackerBlazeX)</span><br><br>
                <span class="code-pill">Sources: MITRE · CISA KEV · GitHub · Exploit-DB</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("")

    # Search bar
    st.markdown("### 🔍 CVE Search")
    prefix_col, _, _ = st.columns([2, 1, 1])
    with prefix_col:
        raw_input = st.text_input(
            "Type CVE ID (with or without 'CVE-'):",
            value="",
            placeholder="Example: 2021-44228 or CVE-2021-44228",
            max_chars=40,
        )

    normalized_preview = normalize_cve_id(raw_input) if raw_input else ""
    suggestions = []
    if normalized_preview:
        suggestions = [c for c in POPULAR_CVES if c.startswith(normalized_preview.upper())]

    sug_col1, sug_col2 = st.columns([2, 1])
    with sug_col1:
        if suggestions:
            st.markdown("**Suggestions:**")
            st.write(", ".join(suggestions))
        elif normalized_preview:
            st.caption(f"Will query: `{normalized_preview}`")
    with sug_col2:
        analyze_btn = st.button("Analyze CVE ⚡", use_container_width=True)

    st.info(
        "Type partial ID like `2021-44` or full `CVE-2021-44228`. "
        "Suggestions are shown for some popular CVEs.",
        icon="💡",
    )

    if not analyze_btn:
        st.stop()

    cve_id = normalize_cve_id(raw_input)
    if not cve_id or not re.match(r"^CVE-\d{4}-\d{3,}$", cve_id):
        st.error("Please enter a valid CVE ID, e.g. CVE-2021-44228")
        st.stop()

    with st.spinner(f"Fetching details for {cve_id} from MITRE..."):
        cve_data, err = fetch_cve_mitre(cve_id)

    if err or not cve_data:
        st.error(f"Error fetching CVE details: {err}")
        st.stop()

    kev_set, kev_list, kev_err = load_kev_catalog()

    cna = cve_data.get("containers", {}).get("cna", {})
    descs = cna.get("descriptions", []) or []
    summary = "No summary available."
    for d in descs:
        if d.get("lang") == "en":
            summary = d.get("value", summary)
            break
    if summary == "No summary available." and descs:
        summary = descs[0].get("value", summary)

    metrics = cna.get("metrics", []) or []
    cvss = None
    for m in metrics:
        for key in ("cvssV3_1", "cvssV3_0", "cvssV2_0"):
            if key in m:
                cvss = m[key].get("baseScore", None)
                if cvss is not None:
                    break
        if cvss is not None:
            break

    meta = cve_data.get("cveMetadata", {}) or {}
    published = meta.get("datePublished", "") or meta.get("dateReserved", "")
    modified = meta.get("dateUpdated", "") or ""

    refs_raw = cna.get("references", []) or []
    refs = [r.get("url") for r in refs_raw if isinstance(r, dict) and r.get("url")]

    affected = cna.get("affected", []) or []
    vendors = []
    products = []

    for a in affected:
        vendor = a.get("vendor", "") or a.get("provider", "")
        product = a.get("product", "")
        if vendor:
            vendors.append(vendor)

        versions = a.get("versions", []) or []
        base_name = ""
        if vendor and product:
            base_name = f"{vendor}:{product}"
        elif vendor:
            base_name = vendor
        elif product:
            base_name = product

        if not versions:
            if base_name:
                products.append(base_name)
        else:
            for v in versions:
                ver = v.get("version", "") or v.get("versionAffected", "")
                ver = str(ver or "").strip()
                if not ver:
                    if base_name:
                        products.append(base_name)
                    continue

                if product and ver.lower().startswith(product.lower()):
                    products.append(f"{vendor}:{ver}" if vendor else ver)
                else:
                    if base_name:
                        products.append(f"{base_name}:{ver}")
                    else:
                        products.append(ver)

    primary_vendor = vendors[0] if vendors else "Unknown"

    in_kev = cve_id.upper() in kev_set if kev_set else False

    if cvss is not None:
        sev_label, sev_icon, sev_class = get_severity_label(cvss)
        sev_origin = "From CVSS"
        display_score = cvss
    else:
        score_pred, sev_label, sev_icon, sev_class, sev_origin = predict_severity_from_text(summary)
        display_score = score_pred

    epss_score = predict_epss_score(display_score, in_kev)

    add_to_history(cve_id, published, primary_vendor, display_score, in_kev)

    st.markdown("---")

    # Top metric cards
    top_cards = st.columns(5)
    with top_cards[0]:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.markdown("**CVE ID**")
        st.markdown(f"<span class='code-pill'>{cve_id}</span>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with top_cards[1]:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.markdown("**CVSS / Severity Score**")
        if isinstance(display_score, (int, float)):
            score_txt = f"{float(display_score):.1f}"
        else:
            score_txt = "N/A"
        st.markdown(
            f"<span class='code-pill'>{score_txt}</span><br>"
            f"<span style='font-size:11px;opacity:0.7;'>{sev_origin}</span>",
            unsafe_allow_html=True,
        )
        st.markdown("</div>", unsafe_allow_html=True)

    with top_cards[2]:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.markdown("**Severity Class**")
        st.markdown(
            f"<span class='sev-pill {sev_class}'>{sev_icon} {sev_label}</span>",
            unsafe_allow_html=True,
        )
        st.markdown("</div>", unsafe_allow_html=True)

    with top_cards[3]:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.markdown("**EPSS-style Risk (estimated)**")
        st.markdown(
            f"<span class='code-pill'>{epss_score}</span>",
            unsafe_allow_html=True,
        )
        hint = "High likelihood of exploitation" if epss_score >= 0.8 else (
            "Moderate likelihood of exploitation" if epss_score >= 0.4 else
            "Lower likelihood of exploitation"
        )
        st.caption(hint)
        st.markdown("</div>", unsafe_allow_html=True)

    with top_cards[4]:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.markdown("**Known Exploited? (CISA KEV)**")
        if kev_err:
            st.markdown(
                "<span class='code-pill'>KEV load error</span>",
                unsafe_allow_html=True,
            )
        else:
            if in_kev:
                st.markdown(
                    "<span class='sev-pill sev-critical'>⚠ Listed in CISA KEV</span>",
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    "<span class='sev-pill sev-low'>🟢 Not listed in KEV</span>",
                    unsafe_allow_html=True,
                )
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("")

    upper_left, upper_right = st.columns([2.2, 1.3])

    # LEFT: summary + products + timeline
    with upper_left:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.subheader("📌 CVE Summary")
        st.write(wrap_text(summary))

        st.subheader("🧬 Affected Products / Components")
        if products:
            for p in products[:35]:
                st.markdown(f"- `{p}`")
            if len(products) > 35:
                st.info(f"+ {len(products) - 35} more products hidden for readability.")
        else:
            st.write("No affected products listed for this CVE.")

        if published or modified:
            st.subheader("🕒 Timeline")
            pub_txt = published if published else "Unknown"
            mod_txt = modified if modified else "Unknown"
            st.write(f"- Published: `{pub_txt}`")
            st.write(f"- Last Modified: `{mod_txt}`")

        st.markdown("</div>", unsafe_allow_html=True)

    # RIGHT: refs, patch links, PoCs, Exploit-DB
    with upper_right:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.subheader("🔗 References")
        if refs:
            for r in refs[:18]:
                st.markdown(f"- [{r}]({r})")
        else:
            st.write("No reference URLs available.")

        patch_links = []
        for r in refs:
            if any(k in r for k in PATCH_VENDOR_KEYWORDS):
                patch_links.append(r)

        st.subheader("🛠 Patch / Advisory Links (Guessed)")
        if patch_links:
            for r in patch_links[:10]:
                st.markdown(f"- [{r}]({r})")
        else:
            st.write("No clear vendor advisory URLs detected. Check references manually.")

        st.subheader("🧪 PoC / Exploit Repositories (GitHub)")
        with st.spinner("Searching public PoCs on GitHub..."):
            poc_repos, poc_err = search_github_pocs(cve_id)

        if poc_err:
            st.warning(poc_err)
        elif not poc_repos:
            st.write("No PoC repositories found (or none matching this search pattern).")
        else:
            for repo in poc_repos:
                name = repo["name"]
                url = repo["url"]
                desc = repo["description"] or ""
                stars = repo["stars"]
                lang = repo["language"] or "Unknown"
                st.markdown(
                    f"- ⭐ **[{name}]({url})**  \n"
                    f"  _{desc}_  \n"
                    f"  Stars: `{stars}` • Language: `{lang}`"
                )

        st.subheader("💣 Exploit-DB Search")
        edb_url = f"https://www.exploit-db.com/search?cve={cve_id}"
        st.markdown(f"[Open Exploit-DB search for {cve_id}]({edb_url})")

        st.caption(
            "⚠️ All exploit links are for **defensive research and authorized lab testing only**."
        )
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("---")

    # LOWER: attack graph + steps + PDF export
    lower_left, lower_right = st.columns([1.8, 1.2])

    attack_category = detect_category(summary, refs, cve_id)
    template = build_attack_template(attack_category, summary)

    with lower_left:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.subheader(f"🕸️ Attack Flow Diagram – {attack_category}")
        st.caption(
            "Automatically estimated high-level attack path. "
            "The exact kill-chain may differ between environments."
        )
        render_attack_graph(template, cve_id)
        st.markdown("</div>", unsafe_allow_html=True)

    with lower_right:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.subheader("📜 Exploitation Steps (High-Level)")
        for idx, step in enumerate(template["steps"], start=1):
            st.markdown(f"**Step {idx}.** {step}")

        st.subheader("🛡️ Defensive Notes (Generic)")
        st.markdown(
            """
            - **Patch / Update:** Apply the vendor patch or upgrade to the fixed version.
            - **Reduce Exposure:** Minimize internet-facing services and enforce strong segmentation.
            - **Hardening & Monitoring:** Enable logging, alerting, and anomaly detection around the vulnerable component.
            - **Compensating Controls:** Use WAF / IDS / IPS rules where applicable to mitigate exploitation attempts.
            """
        )

        st.subheader("📄 Export Report (PDF)")
        pdf_bytes = generate_pdf_report(
            cve_id=cve_id,
            summary=summary,
            sev_label=sev_label,
            display_score=display_score,
            sev_origin=sev_origin,
            epss_score=epss_score,
            primary_vendor=primary_vendor,
            published=published,
            modified=modified,
            in_kev=in_kev,
            products=products,
            refs=refs,
            attack_category=attack_category,
            steps=template["steps"],
        )
        st.download_button(
            label="Download PDF Report",
            data=pdf_bytes,
            file_name=f"{cve_id}_zeroday_report.pdf",
            mime="application/pdf",
        )

        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("### 📊 Session Analytics & Live Threat Intel")

    a1, a2, a3 = st.columns(3)
    with a1:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.subheader("📈 CVE Trending by Year")
        render_trending_chart()
        st.markdown("</div>", unsafe_allow_html=True)

    with a2:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.subheader("🏢 Vendor-wise CVE Count")
        render_vendor_chart()
        st.markdown("</div>", unsafe_allow_html=True)

    with a3:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.subheader("🌍 Country-wise Overview")
        render_country_heatmap()
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("### 🔥 Live Threat Feed Snapshot (CISA KEV)")
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    if kev_err:
        st.warning(f"Could not load KEV feed: {kev_err}")
    else:
        render_live_threat_feed(kev_list)
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("---")
    st.caption(
        "ZeroDay Visualizer – research-focused CVE attack path & intel dashboard. "
        "Always use only in authorized, controlled environments."
    )


if __name__ == "__main__":
    main()
