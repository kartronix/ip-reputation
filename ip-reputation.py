"""
IP Reputation Dashboard (Streamlit)
- WHOIS (local ipwhois fallback or WhoisXML if key provided) -> clean tabular output
- AbuseIPDB (reputation & reports) -> focused output
- VirusTotal (optional) -> attributes table
- SecurityTrails (optional) -> historical DNS table

Secrets:
- Put keys in Streamlit secrets or environment variables:
  ABUSEIPDB_API_KEY, VT_API_KEY, SECURITYTRAILS_API_KEY, WHOISXML_API_KEY
"""

import os
import requests
import streamlit as st
import pandas as pd
from ipwhois import IPWhois

# ---------------------------
# Config / Keys
# ---------------------------
# Prefer Streamlit secrets, fallback to environment variables
ABUSEIPDB_API_KEY = st.secrets.get("ABUSEIPDB_API_KEY", os.getenv("ABUSEIPDB_API_KEY", ""))
VT_API_KEY = st.secrets.get("VT_API_KEY", os.getenv("VT_API_KEY", ""))
SECURITYTRAILS_API_KEY = st.secrets.get("SECURITYTRAILS_API_KEY", os.getenv("SECURITYTRAILS_API_KEY", ""))
WHOISXML_API_KEY = st.secrets.get("WHOISXML_API_KEY", os.getenv("WHOISXML_API_KEY", ""))

# ---------------------------
# Helpers: clean & format
# ---------------------------
def df_from_dict(d: dict, keep_empty: bool = False) -> pd.DataFrame:
    """Convert dict to two-column DataFrame, dropping empty values by default."""
    if not isinstance(d, dict):
        return pd.DataFrame([["value", str(d)]], columns=["Field", "Value"])
    items = [(k, v) for k, v in d.items() if (keep_empty or (v is not None and v != ""))]
    if not items:
        return pd.DataFrame([["Note", "No data"]], columns=["Field", "Value"])
    return pd.DataFrame(items, columns=["Field", "Value"])

def df_from_kv_pairs(pairs):
    return pd.DataFrame(pairs, columns=["Field", "Value"])

# ---------------------------
# WHOIS (clean extraction)
# ---------------------------
def get_whois_clean(ip: str) -> pd.DataFrame:
    """
    Returns a DataFrame containing cleaned WHOIS fields.
    Tries WhoisXML API if key is set; otherwise uses ipwhois.lookup_rdap().
    """
    try:
        # Attempt WhoisXML/API style if key provided (different vendors have different JSON shapes,
        # so we defensively search for common fields).
        if WHOISXML_API_KEY:
            # Many WHOIS JSON APIs differ. We'll attempt WhoisXML-style endpoint (adjust if needed).
            url = f"https://whoisxmlapi.com/whoisserver/Whois?apiKey={WHOISXML_API_KEY}&domainName={ip}&outputFormat=JSON"
            r = requests.get(url, timeout=20)
            r.raise_for_status()
            j = r.json()
            # WhoisXML returns WhoisRecord -> registryData usually
            rec = j.get("WhoisRecord") or j.get("whoisRecord") or {}
            reg = rec.get("registryData") or rec
            # Extract useful fields defensively
            items = []
            # ASN-like fields (some APIs include them)
            items.append(("Query", ip))
            items.append(("Registrar", rec.get("registrarName") or reg.get("registrarName")))
            items.append(("Registrant Name", reg.get("registrant", {}).get("name") if isinstance(reg.get("registrant"), dict) else reg.get("registrant")))
            items.append(("Registrant Org", reg.get("registrant", {}).get("organization") if isinstance(reg.get("registrant"), dict) else None))
            items.append(("Creation Date", reg.get("createdDate") or rec.get("createdDate")))
            items.append(("Updated Date", reg.get("updatedDate") or rec.get("updatedDate")))
            items.append(("Expiration Date", reg.get("expiresDate") or rec.get("expiresDate")))
            # name servers
            ns = reg.get("nameServers", {}).get("hostNames") if isinstance(reg.get("nameServers"), dict) else reg.get("nameServers")
            if isinstance(ns, list):
                items.append(("Name Servers", ", ".join(ns)))
            elif isinstance(ns, str):
                items.append(("Name Servers", ns))
            # return cleaned df
            df = df_from_kv_pairs([(k, v) for k, v in items if v not in (None, "", [])])
            return df

        # Fallback: ipwhois.lookup_rdap (works for IP WHOIS)
        obj = IPWhois(ip)
        rdap = obj.lookup_rdap(retry_count=1, depth=1)
        # rdap is nested; extract the most useful, consistent fields
        asn = rdap.get("asn")
        asn_registry = rdap.get("asn_registry") or rdap.get("asn_country_code")
        asn_cidr = rdap.get("asn_cidr")
        asn_description = rdap.get("asn_description")
        network = rdap.get("network", {}) or {}
        nets = rdap.get("nets") or rdap.get("objects") or []

        items = [
            ("Query", ip),
            ("ASN", asn),
            ("ASN Registry", asn_registry),
            ("ASN CIDR", asn_cidr),
            ("ASN Description", asn_description),
            ("Network Name", network.get("name") if isinstance(network, dict) else None),
            ("Network Handle", network.get("handle") if isinstance(network, dict) else None),
            ("Network Country", network.get("country") if isinstance(network, dict) else None),
            ("Start Address", network.get("start_address") if isinstance(network, dict) else None),
            ("End Address", network.get("end_address") if isinstance(network, dict) else None),
        ]

        # If nets is a list with dicts, try to extract first contact/org info
        if isinstance(nets, list) and nets:
            first = nets[0]
            # ipwhois 'nets' entries often have 'name', 'description', 'cidr'
            items.extend([
                ("Net Name (first)", first.get("name")),
                ("Net Description (first)", first.get("description") or first.get("remarks")),
                ("Net CIDR (first)", first.get("cidr") or first.get("prefixlen")),
                ("Net Country (first)", first.get("country")),
                ("Net Handle/Object (first)", first.get("handle") or first.get("object")),
            ])

        df = df_from_kv_pairs([(k, v) for k, v in items if v not in (None, "", [])])
        return df

    except Exception as e:
        return pd.DataFrame([["Error", str(e)]], columns=["Field", "Value"])


# ---------------------------
# AbuseIPDB (reputation & recent reports)
# ---------------------------
def get_abuseipdb(ip: str) -> pd.DataFrame:
    if not ABUSEIPDB_API_KEY:
        return pd.DataFrame([["Note", "No AbuseIPDB API key configured."]], columns=["Metric", "Value"])

    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
        r = requests.get(url, headers=headers, params=params, timeout=15)
        r.raise_for_status()
        j = r.json().get("data", {})
        # Extract the important reputation metrics
        rows = []
        rows.append(("IP Address", j.get("ipAddress")))
        rows.append(("Abuse Confidence Score", j.get("abuseConfidenceScore")))
        rows.append(("Total Reports", j.get("totalReports")))
        rows.append(("Last Reported At", j.get("lastReportedAt")))
        # Provide counts of categories and the top reports if any
        reports = j.get("reports") or []
        rows.append(("Recent Reports Count (returned)", len(reports)))
        # For convenience, also return a short list of up to 5 recent report summaries
        if reports:
            for idx, rep in enumerate(reports[:5], 1):
                info = f"{rep.get('reporterId', '')} | {rep.get('comment', '')} | {rep.get('reportedAt', '')}"
                rows.append((f"Report {idx}", info))
        return pd.DataFrame(rows, columns=["Metric", "Value"])
    except Exception as e:
        return pd.DataFrame([["Error", str(e)]], columns=["Metric", "Value"])


# ---------------------------
# VirusTotal (attributes)
# ---------------------------
def get_virustotal(ip: str) -> pd.DataFrame:
    if not VT_API_KEY:
        return pd.DataFrame([["Note", "No VirusTotal API key configured."]], columns=["Field", "Value"])
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VT_API_KEY}
        r = requests.get(url, headers=headers, timeout=15)
        r.raise_for_status()
        j = r.json().get("data", {}).get("attributes", {})
        # Flatten top-level simple attributes and also expand last_analysis_stats if present
        rows = []
        for k in ["country", "asn", "as_owner", "last_analysis_stats", "reputation", "tags"]:
            if k in j:
                if k == "last_analysis_stats" and isinstance(j[k], dict):
                    # expand stats (malicious/undetected/etc.)
                    for stat_k, stat_v in j[k].items():
                        rows.append((f"analysis_{stat_k}", stat_v))
                else:
                    rows.append((k, j[k]))
        # add any other useful attributes not in default list
        for k, v in j.items():
            if k not in ["country", "asn", "as_owner", "last_analysis_stats", "reputation", "tags"]:
                # keep only simple values (avoid huge nested dumps)
                if isinstance(v, (str, int, float, bool)) or v is None:
                    rows.append((k, v))
        return pd.DataFrame(rows, columns=["Field", "Value"])
    except Exception as e:
        return pd.DataFrame([["Error", str(e)]], columns=["Field", "Value"])


# ---------------------------
# SecurityTrails (historical DNS)
# ---------------------------
def get_securitytrails(ip: str) -> pd.DataFrame:
    if not SECURITYTRAILS_API_KEY:
        return pd.DataFrame([["Note", "No SecurityTrails API key configured."]], columns=["Result", "Value"])
    try:
        # SecurityTrails API endpoints differ for IP vs domain; try IP route first:
        url_ip = f"https://api.securitytrails.com/v1/history/ip/{ip}/dns/a"
        headers = {"APIKEY": SECURITYTRAILS_API_KEY}
        r = requests.get(url_ip, headers=headers, timeout=20)
        if r.status_code == 200:
            j = r.json()
            recs = j.get("records", []) or j.get("data", [])
            if isinstance(recs, list) and recs:
                return pd.DataFrame(recs)
            return pd.DataFrame([["No records found"]], columns=["Result"])
        # fallback to domain-style route (some users pass domain)
        url_dom = f"https://api.securitytrails.com/v1/history/{ip}/dns/a"
        r2 = requests.get(url_dom, headers=headers, timeout=20)
        r2.raise_for_status()
        j2 = r2.json()
        recs2 = j2.get("records", []) or j2.get("data", [])
        if isinstance(recs2, list) and recs2:
            return pd.DataFrame(recs2)
        return pd.DataFrame([["No records found"]], columns=["Result"])
    except Exception as e:
        return pd.DataFrame([["Error", str(e)]], columns=["Result"])


# ---------------------------
# Streamlit layout
# ---------------------------
st.set_page_config(page_title="IP Reputation Dashboard", layout="wide")
st.title("🌍 IP Reputation Dashboard")

st.markdown(
    "Enter an IP address below and click **Check**. WHOIS (unlimited via local lookup) is shown "
    "in a neat table. Reputation uses AbuseIPDB (if configured)."
)

ip = st.text_input("IP address (or domain)", value="8.8.8.8")
check = st.button("Check")

if check and ip:
    # Basic validation
    with st.spinner("Fetching data..."):
        whois_df = get_whois_clean(ip)
        abuse_df = get_abuseipdb(ip)
        vt_df = get_virustotal(ip)
        st_df = get_securitytrails(ip)

    # Present in a 2-column layout
    col1, col2 = st.columns([1, 1])

    with col1:
        st.subheader("WHOIS Information")
        st.table(whois_df)

        st.subheader("AbuseIPDB (Reputation & Reports)")
        st.table(abuse_df)

    with col2:
        st.subheader("VirusTotal Summary")
        st.table(vt_df)

        st.subheader("SecurityTrails (Historical DNS)")
        # For securitytrails, it may be a wide table - use dataframe
        st.dataframe(st_df)

    # Raw JSON / troubleshooting expandable
    with st.expander("Show raw API responses / debug info"):
        st.markdown("**Keys present**")
        st.write({
            "WHOISXML_key_set": bool(WHOISXML_API_KEY),
            "AbuseIPDB_key_set": bool(ABUSEIPDB_API_KEY),
            "VirusTotal_key_set": bool(VT_API_KEY),
            "SecurityTrails_key_set": bool(SECURITYTRAILS_API_KEY),
        })
        st.markdown("**WHOIS table (preview)**")
        st.write(whois_df.head(30))

else:
    st.info("Enter an IP and click Check to start. If you don't have API keys, WHOIS will still work via local lookup.")
