import streamlit as st
import requests
import pandas as pd

# Title
st.set_page_config(page_title="IP Reputation Dashboard", layout="wide")
st.title("🔍 IP Reputation Dashboard")

# Input
ip = st.text_input("Enter an IP Address:", placeholder="e.g. 8.8.8.8")

# Load API keys from Streamlit secrets
VT_API_KEY = st.secrets.get("VT_API_KEY", "")
ABUSEIPDB_API_KEY = st.secrets.get("ABUSEIPDB_API_KEY", "")
WHOISXML_API_KEY = st.secrets.get("WHOISXML_API_KEY", "")
SECURITYTRAILS_API_KEY = st.secrets.get("SECURITYTRAILS_API_KEY", "")

def dict_to_table(data: dict, title: str):
    """Utility to convert dictionary to a table"""
    if not data:
        st.warning(f"No data found for {title}")
        return
    df = pd.DataFrame(data.items(), columns=["Field", "Value"])
    st.subheader(title)
    st.table(df)

def list_to_table(data: list, title: str):
    """Utility to convert list of records to a dataframe table"""
    if not data:
        st.warning(f"No records found for {title}")
        return
    df = pd.DataFrame(data)
    st.subheader(title)
    st.dataframe(df)

if ip:
    st.markdown("---")

    # 1. WHOIS Lookup
    if WHOISXML_API_KEY:
        st.info("Fetching WHOIS data...")
        url = f"https://whoisxmlapi.com/whoisserver/Whois?apiKey={WHOISXML_API_KEY}&domainName={ip}&outputFormat=JSON"
        try:
            res = requests.get(url, timeout=20).json()
            whois_data = res.get("WhoisRecord", {}).get("registryData", {})
            dict_to_table(whois_data, "WHOIS Information")
        except Exception as e:
            st.error(f"WHOIS Error: {e}")

    # 2. VirusTotal
    if VT_API_KEY:
        st.info("Fetching VirusTotal data...")
        headers = {"x-apikey": VT_API_KEY}
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        try:
            res = requests.get(url, headers=headers, timeout=20).json()
            data = res.get("data", {}).get("attributes", {})
            dict_to_table(data, "VirusTotal Results")
        except Exception as e:
            st.error(f"VirusTotal Error: {e}")

    # 3. AbuseIPDB
    if ABUSEIPDB_API_KEY:
        st.info("Fetching AbuseIPDB data...")
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        try:
            res = requests.get(url, headers=headers, timeout=20).json()
            data = res.get("data", {})
            dict_to_table(data, "AbuseIPDB Results")
        except Exception as e:
            st.error(f"AbuseIPDB Error: {e}")

    # 4. SecurityTrails (Historical DNS)
    if SECURITYTRAILS_API_KEY:
        st.info("Fetching SecurityTrails data...")
        headers = {"APIKEY": SECURITYTRAILS_API_KEY}
        url = f"https://api.securitytrails.com/v1/history/{ip}/dns/a"
        try:
            res = requests.get(url, headers=headers, timeout=20).json()
            records = res.get("records", [])
            list_to_table(records, "Historical DNS Records")
        except Exception as e:
            st.error(f"SecurityTrails Error: {e}")
