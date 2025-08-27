# 🛰️ IP Reputation + WHOIS + DNS History Dashboard

This is a Streamlit-based OSINT dashboard that enriches an IP or domain with:

- Geolocation (ip-api)
- WHOIS (ipwhois + python-whois)
- Reputation (AbuseIPDB, VirusTotal)
- Historical DNS (SecurityTrails)
- Related domains via crt.sh
- JSON/CSV export
- Diagnostics for API keys and dependencies

## 🚀 Quickstart

```bash
git clone https://github.com/yourusername/ip-reputation-dashboard.git
cd ip-reputation-dashboard

# install deps
pip install -r requirements.txt

# run app
streamlit run app.py
```

## 🔑 API Keys

Create a file `.streamlit/secrets.toml`:

```toml
ABUSEIPDB_API_KEY = "your_abuseipdb_key"
VT_API_KEY = "your_virustotal_key"
SECURITYTRAILS_API_KEY = "your_securitytrails_key"
```

Or paste keys directly in the sidebar at runtime.

## 🛠 Requirements

- Python 3.8+
- Dependencies in `requirements.txt`

## 📦 Docker

Build and run with Docker:

```bash
docker build -t ip-reputation-dashboard .
docker run -p 8501:8501 ip-reputation-dashboard
```

## ⚠️ Disclaimer

This tool is for educational and research purposes only. Respect API rate limits and terms of service.
