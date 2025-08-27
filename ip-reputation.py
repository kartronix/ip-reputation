import streamlit as st
import requests
import whois
import pandas as pd
from ipwhois import IPWhois

# -------------------------------
# Load API Keys from Secrets
# -------------------------------
VT_API_KEY = st.secrets.get("virustotal", "")
ABUSE_API_KEY = st.secrets.get("abuseipdb", "")
SECURITYTRAILS_KEY = st.secrets.get("securitytrails", "")

# -------------------------------
# Helper: Safe API request
# -------------------------------
def safe_request(url, headers=None, params=None):
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=15)
        if resp.status_code == 200:
            return resp.json()
        return None
    except Exception:
        return None

# -------------------------------
# WHOIS Info
# -------------------------------
def get_whois_info(ip_or_domain):
    try:
        w = whois.whois(ip_or_domain)
        whois_data = {
            "Domain": w.domain_name if w.domain_name else "Not available",
            "Registrar": w.registrar if w.registrar else "Not available",
            "Org": w.org if w.org else "Not available",
            "Country": w.country if w.country else "Not available",
            "Creation Date": str(w.creation_date) if w.creation_date else "Not available",
            "Expiration Date": str(w.expiration_date) if w.expiration_date else "Not available",
            "Emails": "\n".join(w.emails) if w.emails else "Not available"
        }
    except Exception:
        # fallback with ipwhois
        try:
            obj = IPWhois(ip_or_domain)
            res = obj.lookup_rdap()
            whois_data = {
                "ASN": res.get("asn", "Not available"),
                "Org": res.get("network", {}).get("name", "Not available"),
                "Country": res.get("asn_country_code", "Not available"),
                "CIDR": res.get("network", {}).get("cidr", "Not available"),
                "Emails": "\n".join(res.get("network", {}).get("emails", [])) if res.get("network", {}).get("emails") else "Not available"
            }
        except Exception:
            whois_data = {"Error": "Error obtaining data"}
    return pd.DataFrame(list(whois_data.items()), columns=["Field", "Value"])

# -------------------------------
# AbuseIPDB
# -------------------------------
def get_abuseip_info(ip):
    if not ABUSE_API_KEY:
        return pd.DataFrame([["Error", "API key missing"]], columns=["Field", "Value"])
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSE_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        data = safe_request(url, headers=headers, params=params)
        if not data:
            return pd.DataFrame([["Error", "Error obtaining data"]], columns=["Field", "Value"])
        d = data.get("data", {})
        abuse_data = {
            "IP Address": d.get("ipAddress", "Not available"),
            "Abuse Confidence": d.get("abuseConfidenceScore", "Not available"),
            "Country": d.get("countryCode", "Not available"),
            "Domain": d.get("domain", "Not available"),
            "ISP": d.get("isp", "Not available"),
            "Usage Type": d.get("usageType", "Not available"),
            "Total Reports": d.get("totalReports", "Not available"),
        }
        return pd.DataFrame(list(abuse_data.items()), columns=["Field", "Value"])
    except Exception:
        return pd.DataFrame([["Error", "Error obtaining data"]], columns=["Field", "Value"])

# -------------------------------
# VirusTotal
# -------------------------------
def get_virustotal_info(ip):
    if not VT_API_KEY:
        return pd.DataFrame([["Error", "API key missing"]], columns=["Field", "Value"])
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VT_API_KEY}
        data = safe_request(url, headers=headers)
        if not data:
            return pd.DataFrame([["Error", "Error obtaining data"]], columns=["Field", "Value"])
        attr = data.get("data", {}).get("attributes", {})
        vt_data = {
            "Country": attr.get("country", "Not available"),
            "ASN": attr.get("asn", "Not available"),
            "Org": attr.get("as_owner", "Not available"),
            "Reputation": attr.get("reputation", "Not available"),
            "Harmless Votes": attr.get("last_analysis_stats", {}).get("harmless", "Not available"),
            "Malicious Votes": attr.get("last_analysis_stats", {}).get("malicious", "Not available"),
        }
        return pd.DataFrame(list(vt_data.items()), columns=["Field", "Value"])
    except Exception:
        return pd.DataFrame([["Error", "Error obtaining data"]], columns=["Field", "Value"])

# -------------------------------
# SecurityTrails
# -------------------------------
def get_securitytrails(ip):
    if not SECURITYTRAILS_KEY:
        return pd.DataFrame([["Error", "API key missing"]], columns=["Field", "Value"])
    try:
        url = f"https://api.securitytrails.com/v1/ips/{ip}"
        headers = {"APIKEY": SECURITYTRAILS_KEY}
        data = safe_request(url, headers=headers)
        if not data:
            return pd.DataFrame([["Error", "Error obtaining data"]], columns=["Field", "Value"])
        st_data = {
            "Hostname": ", ".join(data.get("hostnames", [])) if data.get("hostnames") else "Not available",
            "PTR Record": data.get("ptr", "Not available"),
        }
        return pd.DataFrame(list(st_data.items()), columns=["Field", "Value"])
    except Exception:
        return pd.DataFrame([["Error", "Error obtaining data"]], columns=["Field", "Value"])

# -------------------------------
# Streamlit UI
# -------------------------------
st.title("🔍 IP Reputation & WHOIS Lookup")

ip = st.text_input("Enter an IP address or domain:")

if ip:
    st.subheader("WHOIS Information")
    st.table(get_whois_info(ip))

    st.subheader("AbuseIPDB Information")
    st.table(get_abuseip_info(ip))

    st.subheader("VirusTotal Information")
    st.table(get_virustotal_info(ip))

    st.subheader("SecurityTrails Information")
    st.table(get_securitytrails(ip))
