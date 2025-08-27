import os
import requests
import streamlit as st
import pandas as pd
from ipwhois import IPWhois

# Load API Keys from environment variables
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
WHOISXML_API_KEY = os.getenv("WHOISXML_API_KEY", "")
VT_API_KEY = os.getenv("VT_API_KEY", "")
SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY", "")

# ------------------- WHOIS LOOKUP -------------------
def get_whois_data(ip):
    try:
        if WHOISXML_API_KEY:  # Use API if key is available
            url = f"https://whoisapi.com/api/v1?apiKey={WHOISXML_API_KEY}&ipAddress={ip}&outputFormat=JSON"
            response = requests.get(url, timeout=15)
            data = response.json().get("registryData", {})
            return pd.DataFrame(data.items(), columns=["Field", "Value"])
        else:  # Fallback to local ipwhois
            obj = IPWhois(ip)
            data = obj.lookup_rdap()
            return pd.DataFrame(data.items(), columns=["Field", "Value"])
    except Exception as e:
        return pd.DataFrame([["Error", str(e)]], columns=["Field", "Value"])

# ------------------- ABUSEIPDB -------------------
def get_abuseipdb_data(ip):
    try:
        if not ABUSEIPDB_API_KEY:
            return pd.DataFrame([["Error", "No API key set"]], columns=["Field", "Value"])

        url = "https://api.abuseipdb.com/api/v2/check"
        querystring = {"ipAddress": ip, "maxAgeInDays": "90"}
        headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
        response = requests.get(url, headers=headers, params=querystring, timeout=15)
        data = response.json().get("data", {})
        return pd.DataFrame(data.items(), columns=["Metric", "Value"])
    except Exception as e:
        return pd.DataFrame([["Error", str(e)]], columns=["Metric", "Value"])

# ------------------- VIRUSTOTAL -------------------
def get_virustotal_data(ip):
    try:
        if not VT_API_KEY:
            return pd.DataFrame([["Error", "No API key set"]], columns=["Field", "Value"])

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VT_API_KEY}
        response = requests.get(url, headers=headers, timeout=15)
        data = response.json().get("data", {}).get("attributes", {})
        return pd.DataFrame(data.items(), columns=["Field", "Value"])
    except Exception as e:
        return pd.DataFrame([["Error", str(e)]], columns=["Field", "Value"])

# ------------------- SECURITYTRAILS -------------------
def get_securitytrails_data(ip):
    try:
        if not SECURITYTRAILS_API_KEY:
            return pd.DataFrame([["Error", "No API key set"]], columns=["Field", "Value"])

        url = f"https://api.securitytrails.com/v1/history/ip/{ip}/dns/a"
        headers = {"APIKEY": SECURITYTRAILS_API_KEY}
        response = requests.get(url, headers=headers, timeout=15)
        records = response.json().get("records", [])
        if records:
            return pd.DataFrame(records)
        return pd.DataFrame([["No records found"]], columns=["Result"])
    except Exception as e:
        return pd.DataFrame([["Error", str(e)]], columns=["Result"])

# ------------------- STREAMLIT APP -------------------
st.set_page_config(page_title="IP Reputation Dashboard", layout="wide")
st.title("🌍 IP Reputation Dashboard")

ip = st.text_input("Enter IP Address", "8.8.8.8")

if st.button("Check Reputation"):
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("WHOIS Information")
        st.table(get_whois_data(ip))

        st.subheader("VirusTotal Report")
        st.table(get_virustotal_data(ip))

    with col2:
        st.subheader("AbuseIPDB Reputation")
        st.table(get_abuseipdb_data(ip))

        st.subheader("Historical DNS (SecurityTrails)")
        st.dataframe(get_securitytrails_data(ip))
