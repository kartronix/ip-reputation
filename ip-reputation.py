import streamlit as st
import pandas as pd
import requests
import os
from ipwhois import IPWhois

# =============== Utility Functions =================

def get_whois(ip):
    """Retrieve WHOIS info using ipwhois (no API keys needed)."""
    try:
        obj = IPWhois(ip)
        results = obj.lookup_rdap(asn_methods=["whois"])
        whois_data = []

        for k, v in results.items():
            if isinstance(v, dict):
                for subk, subv in v.items():
                    whois_data.append([f"{k}.{subk}", subv])
            elif isinstance(v, list):
                for i, item in enumerate(v):
                    whois_data.append([f"{k}[{i}]", item])
            else:
                whois_data.append([k, v])

        return pd.DataFrame(whois_data, columns=["Field", "Value"])
    except Exception as e:
        return pd.DataFrame([["Error", str(e)]], columns=["Field", "Value"])


def get_abuseipdb(ip, api_key):
    """Check reputation of IP from AbuseIPDB."""
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        querystring = {
            "ipAddress": ip,
            "maxAgeInDays": "90"
        }
        headers = {
            "Accept": "application/json",
            "Key": api_key
        }
        resp = requests.get(url, headers=headers, params=querystring)
        data = resp.json().get("data", {})

        abuse_data = [
            ["IP Address", data.get("ipAddress")],
            ["Abuse Confidence Score", data.get("abuseConfidenceScore")],
            ["Country Code", data.get("countryCode")],
            ["Domain", data.get("domain")],
            ["ISP", data.get("isp")],
            ["Total Reports", data.get("totalReports")],
            ["Last Reported At", data.get("lastReportedAt")],
        ]

        return pd.DataFrame(abuse_data, columns=["Field", "Value"])
    except Exception as e:
        return pd.DataFrame([["Error", str(e)]], columns=["Field", "Value"])


def get_securitytrails(ip, api_key):
    """Fetch DNS history data from SecurityTrails."""
    try:
        url = f"https://api.securitytrails.com/v1/history/{ip}/dns/a"
        headers = {"APIKEY": api_key}
        resp = requests.get(url, headers=headers)
        data = resp.json()
        return pd.DataFrame(data.get("records", []))
    except Exception as e:
        return pd.DataFrame([["Error", str(e)]], columns=["Field", "Value"])


# =============== Streamlit UI =================

st.set_page_config(page_title="IP Reputation Checker", layout="wide")
st.title("🔍 IP Reputation & WHOIS Lookup")

# Sidebar for inputs
st.sidebar.header("Configuration")
ip = st.sidebar.text_input("Enter IP Address", "8.8.8.8")
abuseipdb_key = st.sidebar.text_input("AbuseIPDB API Key", type="password")
securitytrails_key = st.sidebar.text_input("SecurityTrails API Key", type="password")

if st.sidebar.button("Check IP"):
    st.subheader(f"Results for IP: {ip}")

    # WHOIS Section
    st.markdown("### 📜 WHOIS Information")
    whois_df = get_whois(ip)
    st.dataframe(whois_df, use_container_width=True)

    # AbuseIPDB Section
    if abuseipdb_key:
        st.markdown("### 🚨 AbuseIPDB Reputation")
        abuse_df = get_abuseipdb(ip, abuseipdb_key)
        st.dataframe(abuse_df, use_container_width=True)
    else:
        st.info("Provide AbuseIPDB API key in sidebar to check reputation.")

    # SecurityTrails Section
    if securitytrails_key:
        st.markdown("### 🌐 SecurityTrails DNS History")
        st_df = get_securitytrails(ip, securitytrails_key)
        st.dataframe(st_df, use_container_width=True)
    else:
        st.info("Provide SecurityTrails API key in sidebar to fetch DNS history.")
