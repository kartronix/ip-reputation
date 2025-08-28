import streamlit as st
import requests
import pandas as pd
import ipaddress
from ipwhois import IPWhois

# -------------------------------
# Load API Keys from Secrets (optional)
# -------------------------------
VT_API_KEY = st.secrets.get("virustotal", "")
ABUSE_API_KEY = st.secrets.get("abuseipdb", "")
SECURITYTRAILS_KEY = st.secrets.get("securitytrails", "")
ALIENVAULT_KEY = st.secrets.get("alienvault", "")
IPQS_KEY = st.secrets.get("ipqs", "")
CENSYS_UID = st.secrets.get("censys_uid", "")
CENSYS_SECRET = st.secrets.get("censys_secret", "")
SHODAN_KEY = st.secrets.get("shodan", "")
GREYNOISE_KEY = st.secrets.get("greynoise", "")

# -------------------------------
# Sidebar: Diagnostics
# -------------------------------
st.sidebar.title("🔑 API Diagnostics")
st.sidebar.write("VirusTotal Key:", "✅ Loaded" if VT_API_KEY else "❌ Missing")
st.sidebar.write("AbuseIPDB Key:", "✅ Loaded" if ABUSE_API_KEY else "❌ Missing")
st.sidebar.write("SecurityTrails Key:", "✅ Loaded" if SECURITYTRAILS_KEY else "❌ Missing")
st.sidebar.write("AlienVault Key:", "✅ Loaded" if ALIENVAULT_KEY else "❌ Missing")
st.sidebar.write("IPQS Key:", "✅ Loaded" if IPQS_KEY else "❌ Missing")
st.sidebar.write("Censys Key:", "✅ Loaded" if CENSYS_UID and CENSYS_SECRET else "❌ Missing")
st.sidebar.write("Shodan Key:", "✅ Loaded" if SHODAN_KEY else "❌ Missing")
st.sidebar.write("GreyNoise Key:", "✅ Loaded" if GREYNOISE_KEY else "❌ Missing")

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
def safe_request(url, headers=None, params=None, auth=None):
    try:
        resp = requests.get(url, headers=headers, params=params, auth=auth, timeout=15)
        if resp.status_code == 200:
            return resp.json()
        else:
            st.warning(f"API call failed: {resp.status_code} {resp.text}")
            return None
    except Exception as e:
        st.error(f"Request error: {e}")
        return None

# -------------------------------
# Caching decorator
# -------------------------------
def cached_api(func):
    return st.cache_data(ttl=3600)(func)  # Cache for 1 hour

# -------------------------------
# IPWhois Lookup
# -------------------------------
@cached_api
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
@cached_api
def get_abuseip_info(ip):
    fields = ["IP Address", "Abuse Confidence", "Country", "Domain", "ISP", "Usage Type", "Total Reports"]
    if not ABUSE_API_KEY:
        return pd.DataFrame([(f, "Not available (API key missing)") for f in fields], columns=["Field", "Value"])
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

# -------------------------------
# IPQualityScore fallback
# -------------------------------
@cached_api
def get_ipqs_info(ip):
    fields = ["Fraud Score", "VPN/Proxy", "TOR", "Bot Status"]
    if not IPQS_KEY:
        return pd.DataFrame([(f, "Not available (API key missing)") for f in fields], columns=["Field", "Value"])
    url = f"https://ipqualityscore.com/api/json/ip/{IPQS_KEY}/{ip}"
    data = safe_request(url)
    if not data:
        return pd.DataFrame([(f, "Error obtaining data") for f in fields], columns=["Field", "Value"])
    ipqs_data = {
        "Fraud Score": data.get("fraud_score", "Not available"),
        "VPN/Proxy": data.get("vpn", "Not available"),
        "TOR": data.get("tor", "Not available"),
        "Bot Status": data.get("bot_status", "Not available")
    }
    return pd.DataFrame(list(ipqs_data.items()), columns=["Field", "Value"])

# -------------------------------
# VirusTotal
# -------------------------------
@cached_api
def get_virustotal_info(ip):
    fields = ["Country", "ASN", "Org", "Reputation", "Harmless Votes", "Malicious Votes"]
    if not VT_API_KEY:
        return pd.DataFrame([(f, "Not available (API key missing)") for f in fields], columns=["Field", "Value"])
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

# -------------------------------
# AlienVault OTX fallback
# -------------------------------
@cached_api
def get_alienvault_info(ip):
    fields = ["Reputation", "Malicious Indicator Count"]
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    data = safe_request(url)
    if not data:
        return pd.DataFrame([(f, "Error obtaining data") for f in fields], columns=["Field", "Value"])
    av_data = {
        "Reputation": data.get("reputation", "Not available"),
        "Malicious Indicator Count": len(data.get("malware", [])) if "malware" in data else 0
    }
    return pd.DataFrame(list(av_data.items()), columns=["Field", "Value"])

# -------------------------------
# SecurityTrails
# -------------------------------
@cached_api
def get_securitytrails(ip):
    fields = ["Hostname", "PTR Record"]
    if not SECURITYTRAILS_KEY:
        return pd.DataFrame([(f, "Not available (API key missing)") for f in fields], columns=["Field", "Value"])
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

# -------------------------------
# Censys fallback
# -------------------------------
@cached_api
def get_censys_info(ip):
    fields = ["Observed Ports", "Services"]
    if not CENSYS_UID or not CENSYS_SECRET:
        return pd.DataFrame([(f, "Not available (API key missing)") for f in fields], columns=["Field", "Value"])
    url = f"https://search.censys.io/api/v2/hosts/{ip}"
    data = safe_request(url, auth=(CENSYS_UID, CENSYS_SECRET))
    if not data:
        return pd.DataFrame([(f, "Error obtaining data") for f in fields], columns=["Field", "Value"])
    services = data.get("services", [])
    censys_data = {
        "Observed Ports": ", ".join([str(s.get("port")) for s in services]) if services else "Not available",
        "Services": ", ".join([s.get("service_name", "N/A") for s in services]) if services else "Not available"
    }
    return pd.DataFrame(list(censys_data.items()), columns=["Field", "Value"])

# -------------------------------
# GreyNoise Lookup
# -------------------------------
@cached_api
def get_greynoise_info(ip):
    fields = ["Classification", "Name", "Noise"]
    headers = {"key": GREYNOISE_KEY} if GREYNOISE_KEY else {}
    url = f"https://api.greynoise.io/v3/community/{ip}"  # Community feed (no key needed)
    data = safe_request(url, headers=headers)
    if not data:
        return pd.DataFrame([(f, "Error obtaining data") for f in fields], columns=["Field", "Value"])
    gn_data = {
        "Classification": data.get("classification", "Not available"),
        "Name": data.get("name", "Not available"),
        "Noise": data.get("noise", "Not available")
    }
    return pd.DataFrame(list(gn_data.items()), columns=["Field", "Value"])

# -------------------------------
# Shodan Lookup (limited free)
# -------------------------------
@cached_api
def get_shodan_info(ip):
    fields = ["IP", "Ports", "Hostnames"]
    if not SHODAN_KEY:
        return pd.DataFrame([(f, "Not available (API key missing)") for f in fields], columns=["Field", "Value"])
    url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_KEY}"
    data = safe_request(url)
    if not data:
        return pd.DataFrame([(f, "Error obtaining data") for f in fields], columns=["Field", "Value"])
    sh_data = {
        "IP": data.get("ip_str", "Not available"),
        "Ports": ", ".join(map(str, data.get("ports", []))) if "ports" in data else "Not available",
        "Hostnames": ", ".join(data.get("hostnames", [])) if "hostnames" in data else "Not available"
    }
    return pd.DataFrame(list(sh_data.items()), columns=["Field", "Value"])

# -------------------------------
# Streamlit UI
# -------------------------------
st.title("🔍 Advanced IP Reputation & Lookup Tool")

ip = st.text_input("Enter an IPv4 or IPv6 address:")

if ip:
    if is_valid_ip(ip):
        st.subheader("IPWhois Information")
        st.table(get_ip_whois_info(ip))

        st.subheader("AbuseIPDB Information")
        st.table(get_abuseip_info(ip))

        st.subheader("IPQualityScore Fallback")
        st.table(get_ipqs_info(ip))

        st.subheader("VirusTotal Information")
        st.table(get_virustotal_info(ip))

        st.subheader("AlienVault OTX Fallback")
        st.table(get_alienvault_info(ip))

        st.subheader("SecurityTrails Information")
        st.table(get_securitytrails(ip))

        st.subheader("Censys Fallback")
        st.table(get_censys_info(ip))

        st.subheader("GreyNoise Community Lookup")
        st.table(get_greynoise_info(ip))

        st.subheader("Shodan Lookup (limited free)")
        st.table(get_shodan_info(ip))

    else:
        st.error("❌ Please enter a valid IPv4 or IPv6 address")
