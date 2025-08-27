import streamlit as st
import requests
import whois
import socket
import pandas as pd

# ---------------------------
# Helper: Format dict to DataFrame
# ---------------------------
def dict_to_table(data_dict, title="Details"):
    if not data_dict:
        return pd.DataFrame([["Error obtaining data"]], columns=[title])
    rows = [[k, v] for k, v in data_dict.items()]
    return pd.DataFrame(rows, columns=["Field", "Value"])

# ---------------------------
# WHOIS Lookup
# ---------------------------
def get_whois(ip):
    try:
        w = whois.whois(ip)
        if not w or all(v is None for v in w.values()):
            # Fallback: ipwhois.io
            url = f"https://ipwhois.app/json/{ip}"
            resp = requests.get(url)
            data = resp.json()
            if "success" in data and data["success"] is False:
                return {"Error": "Error obtaining data"}
            return {
                "IP": data.get("ip"),
                "Country": data.get("country"),
                "ASN": data.get("asn"),
                "Org": data.get("org"),
                "ISP": data.get("isp"),
                "Region": data.get("region"),
            }
        else:
            return {
                "Domain": w.domain_name,
                "Registrar": w.registrar,
                "Creation Date": str(w.creation_date),
                "Expiration Date": str(w.expiration_date),
                "Name Servers": ", ".join(w.name_servers) if w.name_servers else None,
                "Org": w.org,
                "Country": w.country,
            }
    except Exception:
        return {"Error": "Error obtaining data"}

# ---------------------------
# AbuseIPDB
# ---------------------------
def get_abuseipdb(ip):
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        querystring = {"ipAddress": ip, "maxAgeInDays": "90"}
        headers = {"Accept": "application/json", "Key": st.secrets["ABUSEIPDB_API_KEY"]}
        resp = requests.get(url, headers=headers)
        data = resp.json()
        if "data" not in data:
            return {"Error": "Error obtaining data"}
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
    except Exception:
        return {"Error": "Error obtaining data"}

# ---------------------------
# VirusTotal
# ---------------------------
def get_virustotal(ip):
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": st.secrets["VT_API_KEY"]}
        resp = requests.get(url, headers=headers)
        data = resp.json()
        if "data" not in data:
            return {"Error": "Error obtaining data"}
        attr = data["data"]["attributes"]
        return {
            "IP Address": ip,
            "ASN": attr.get("asn"),
            "ISP": attr.get("as_owner"),
            "Country": attr.get("country"),
            "Reputation": attr.get("reputation"),
            "Last Analysis Stats": attr.get("last_analysis_stats"),
        }
    except Exception:
        return {"Error": "Error obtaining data"}

# ---------------------------
# SecurityTrails (Historical DNS)
# ---------------------------
def get_securitytrails(ip):
    try:
        url = f"https://api.securitytrails.com/v1/history/{ip}/dns/a"
        headers = {"APIKEY": st.secrets["SECURITYTRAILS_API_KEY"]}
        resp = requests.get(url, headers=headers)
        data = resp.json()
        if "records" not in data:
            return {"Error": "Error obtaining data"}
        return {"Total DNS Records": len(data["records"])}
    except Exception:
        return {"Error": "Error obtaining data"}

# ---------------------------
# Streamlit App
# ---------------------------
st.set_page_config(page_title="IP Reputation Dashboard", layout="wide")
st.title("🔎 IP Reputation & WHOIS Dashboard")

ip = st.text_input("Enter an IP address", "8.8.8.8")

if st.button("Lookup"):
    # WHOIS
    whois_data = get_whois(ip)
    st.subheader("📌 WHOIS Information")
    st.table(dict_to_table(whois_data, "WHOIS"))

    # AbuseIPDB
    abuse_data = get_abuseipdb(ip)
    st.subheader("🚨 AbuseIPDB Reputation")
    st.table(dict_to_table(abuse_data, "AbuseIPDB"))

    # VirusTotal
    vt_data = get_virustotal(ip)
    st.subheader("🦠 VirusTotal Intelligence")
    st.table(dict_to_table(vt_data, "VirusTotal"))

    # SecurityTrails
    sec_data = get_securitytrails(ip)
    st.subheader("🌐 SecurityTrails Historical DNS")
    st.table(dict_to_table(sec_data, "SecurityTrails"))
