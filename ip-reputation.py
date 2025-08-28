import streamlit as st
import requests
import pandas as pd
import ipaddress
from ipwhois import IPWhois

# -------------------------------
# Load API Keys from Secrets
# -------------------------------
VT_API_KEY = st.secrets.get("virustotal", "")
ABUSE_API_KEY = st.secrets.get("abuseipdb", "")
SECURITYTRAILS_KEY = st.secrets.get("securitytrails", "")

# -------------------------------
# Sidebar: Diagnostics
# -------------------------------
st.sidebar.title("🔑 API Diagnostics")
st.sidebar.write("VirusTotal Key:", "✅ Loaded" if VT_API_KEY else "❌ Missing")
st.sidebar.write("AbuseIPDB Key:", "✅ Loaded" if ABUSE_API_KEY else "❌ Missing")
st.sidebar.write("SecurityTrails Key:", "✅ Loaded" if SECURITYTRAILS_KEY else "❌ Missing")

# -------------------------------
# Helper: Validate IP
# -------------------------------
def is_valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

# -------------------------------
# Helper: Safe API request
# -------------------------------
def safe_request(url, headers=None, params=None):
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=15)
        if resp.status_code == 200:
            return resp.json()
        else:
            st.warning(f"API call failed: {resp.status_code} {resp.text}")
            return None
    except Exception as e:
        st.error(f"Request error: {e}")
        return None

# -------------------------------
# IP WHOIS Info
# -------------------------------
def get_ip_whois_info(ip):
    try:
        obj = IPWhois(ip)
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
    fields = ["IP Address", "Abuse Confidence", "Country", "Domain", "ISP", "Usage Type", "Total Reports"]

    if not ABUSE_API_KEY:
        return pd.DataFrame([(f, "Not available (API key missing)") for f in fields], columns=["Field", "Value"])
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSE_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        data = safe_request(url, headers=headers, params=params)
        if not data:
            return pd.DataFrame([(f, "Error obtaining data") for f in fields], columns=["Field", "Value"])
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
        return pd.DataFrame([(f, "Error obtaining data") for f in fields], columns=["Field", "Value"])

# -------------------------------
# VirusTotal
# -------------------------------
def get_virustotal_info(ip):
    fields = ["Country", "ASN", "Org", "Reputation", "Harmless Votes", "Malicious Votes"]

    if not VT_API_KEY:
        return pd.DataFrame([(f, "Not available (API key missing)") for f in fields], columns=["Field", "Value"])
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VT_API_KEY}
        data = safe_request(url, headers=headers)
        if not data:
            return pd.DataFrame([(f, "Error obtaining data") for f in fields], columns=["Field", "Value"])
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
        return pd.DataFrame([(f, "Error obtaining data") for f in fields], columns=["Field", "Value"])

# -------------------------------
# SecurityTrails
# -------------------------------
def get_securitytrails(ip):
    fields = ["Hostname", "PTR Record"]

    if not SECURITYTRAILS_KEY:
        return pd.DataFrame([(f, "Not available (API key missing)") for f in fields], columns=["Field", "Value"])
    try:
        url = f"https://api.securitytrails.com/v1/ips/{ip}"
        headers = {"APIKEY": SECURITYTRAILS_KEY}
        data = safe_request(url, headers=headers)
        if not data:
            return pd.DataFrame([(f, "Error obtaining data") for f in fields], columns=["Field", "Value"])
        st_data = {
            "Hostname": ", ".join(data.get("hostnames", [])) if data.get("hostnames") else "Not available",
            "PTR Record": data.get("ptr", "Not available"),
        }
        return pd.DataFrame(list(st_data.items()), columns=["Field", "Value"])
    except Exception:
        return pd.DataFrame([(f, "Error obtaining data") for f in fields], columns=["Field", "Value"])

# -------------------------------
# Streamlit UI
# -------------------------------
st.title("🔍 IP Reputation & Lookup Tool")

ip = st.text_input("Enter an IPv4 or IPv6 address:")

if ip:
    if is_valid_ip(ip):
        st.subheader("IP WHOIS Information")
        st.table(get_ip_whois_info(ip))

        st.subheader("AbuseIPDB Information")
        st.table(get_abuseip_info(ip))

        st.subheader("VirusTotal Information")
        st.table(get_virustotal_info(ip))

        st.subheader("SecurityTrails Information")
        st.table(get_securitytrails(ip))
    else:
        st.error("❌ Please enter a valid IPv4 or IPv6 address")
