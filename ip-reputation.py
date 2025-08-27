import streamlit as st
import requests
import socket
import whois
import pandas as pd

st.set_page_config(page_title="IP Reputation Dashboard", layout="wide")

st.title("🔍 IP Reputation Dashboard")

# ---------------------------
# WHOIS
# ---------------------------
def get_whois(ip):
    try:
        w = whois.whois(ip)
        data = {k: (", ".join(v) if isinstance(v, list) else str(v)) for k, v in w.items() if v}
        if not data:
            return {"Error": "No WHOIS data found"}
        return data
    except Exception as e:
        return {"Error": f"Exception: {str(e)}"}


# ---------------------------
# AbuseIPDB
# ---------------------------
def get_abuseipdb(ip):
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        querystring = {"ipAddress": ip, "maxAgeInDays": "90"}
        headers = {
            "Accept": "application/json",
            "Key": st.secrets["ABUSEIPDB_API_KEY"]
        }
        resp = requests.get(url, headers=headers, params=querystring)
        data = resp.json()

        if "errors" in data:
            return {"Error": data["errors"][0].get("detail", "Error obtaining data")}

        if "data" not in data:
            return {"Error": "Unexpected response from AbuseIPDB"}

        d = data["data"]
        return {
            "IP Address": d.get("ipAddress"),
            "Abuse Confidence Score": d.get("abuseConfidenceScore"),
            "Country Code": d.get("countryCode"),
            "Domain": d.get("domain"),
            "ISP": d.get("isp"),
            "Usage Type": d.get("usageType"),
            "Hostnames": ", ".join(d.get("hostnames", [])) if d.get("hostnames") else None,
            "Total Reports": d.get("totalReports"),
            "Last Reported At": d.get("lastReportedAt"),
        }

    except Exception as e:
        return {"Error": f"Exception: {str(e)}"}


# ---------------------------
# VirusTotal
# ---------------------------
def get_virustotal(ip):
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": st.secrets["VT_API_KEY"]}
        resp = requests.get(url, headers=headers)
        data = resp.json()

        if "error" in data:
            return {"Error": data["error"].get("message", "Error obtaining data")}

        if "data" not in data:
            return {"Error": "Unexpected response from VirusTotal"}

        d = data["data"]["attributes"]
        return {
            "IP Address": ip,
            "AS Owner": d.get("as_owner"),
            "Country": d.get("country"),
            "Reputation": d.get("reputation"),
            "Harmless Votes": d.get("total_votes", {}).get("harmless"),
            "Malicious Votes": d.get("total_votes", {}).get("malicious"),
            "Last Analysis Stats": str(d.get("last_analysis_stats")),
        }
    except Exception as e:
        return {"Error": f"Exception: {str(e)}"}


# ---------------------------
# SecurityTrails (Historical DNS)
# ---------------------------
def get_securitytrails(ip):
    try:
        url = f"https://api.securitytrails.com/v1/history/{ip}/dns/a"
        headers = {"APIKEY": st.secrets["SECURITYTRAILS_API_KEY"]}
        resp = requests.get(url, headers=headers)
        data = resp.json()

        if "error" in data:
            return {"Error": data["error"].get("message", "Error obtaining data")}

        records = data.get("records", [])
        if not records:
            return {"Error": "No DNS history available"}

        output = []
        for r in records:
            values = r.get("values", [])
            for v in values:
                output.append({
                    "IP": v.get("ip"),
                    "First Seen": v.get("first_seen"),
                    "Last Seen": v.get("last_seen")
                })

        if not output:
            return {"Error": "No valid DNS records found"}

        return output
    except Exception as e:
        return {"Error": f"Exception: {str(e)}"}


# ---------------------------
# Display Table Helper
# ---------------------------
def display_table(title, data):
    st.subheader(title)
    if isinstance(data, dict):
        df = pd.DataFrame(list(data.items()), columns=["Field", "Value"])
        st.table(df)
    elif isinstance(data, list) and data and isinstance(data[0], dict):
        df = pd.DataFrame(data)
        st.table(df)
    else:
        st.write("Error obtaining data")


# ---------------------------
# MAIN
# ---------------------------
ip = st.text_input("Enter an IP address", "")

if ip:
    col1, col2 = st.columns(2)

    with col1:
        whois_data = get_whois(ip)
        display_table("WHOIS Information", whois_data)

        abuse_data = get_abuseipdb(ip)
        display_table("AbuseIPDB Reputation", abuse_data)

    with col2:
        vt_data = get_virustotal(ip)
        display_table("VirusTotal Analysis", vt_data)

        st_data = get_securitytrails(ip)
        display_table("SecurityTrails Historical DNS", st_data)
