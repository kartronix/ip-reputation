# WHOIS Section
if WHOISXML_API_KEY:
    st.info("Fetching WHOIS data from WhoisXML API...")
    url = f"https://whoisxmlapi.com/whoisserver/Whois?apiKey={WHOISXML_API_KEY}&domainName={ip}&outputFormat=JSON"
    try:
        res = requests.get(url, timeout=20).json()
        whois_record = res.get("WhoisRecord", {})

        st.subheader("📄 WHOIS Information")

        # General
        reg_data = whois_record.get("registryData", {}).get("registrant", {})
        reg_name = reg_data.get("name")
        reg_org = reg_data.get("organization")
        reg_country = reg_data.get("country")
        reg_email = reg_data.get("email")
        reg_phone = reg_data.get("telephone")

        registrar = whois_record.get("registrarName", "N/A")

        important_dates = {
            "Created": whois_record.get("registryData", {}).get("createdDate"),
            "Updated": whois_record.get("registryData", {}).get("updatedDate"),
            "Expires": whois_record.get("registryData", {}).get("expiresDate")
        }

        # Show Registrant
        st.markdown("**Registrant Details**")
        st.table(pd.DataFrame([
            ["Name", reg_name],
            ["Organization", reg_org],
            ["Country", reg_country],
            ["Email", reg_email],
            ["Phone", reg_phone]
        ], columns=["Field", "Value"]))

        # Registrar Info
        st.markdown("**Registrar Details**")
        st.table(pd.DataFrame([
            ["Registrar", registrar],
            ["IANA ID", whois_record.get("registrarIANAID")],
            ["WHOIS Server", whois_record.get("registryData", {}).get("whoisServer")]
        ], columns=["Field", "Value"]))

        # Important Dates
        st.markdown("**Important Dates**")
        st.table(pd.DataFrame(important_dates.items(), columns=["Field", "Value"]))

        # Name Servers
        ns = whois_record.get("registryData", {}).get("nameServers", {}).get("hostNames", [])
        if ns:
            st.markdown("**Name Servers**")
            st.table(pd.DataFrame(ns, columns=["Name Server"]))

    except Exception as e:
        st.error(f"WHOIS API Error: {e}")
else:
    st.info("Fetching WHOIS data locally (ipwhois)...")
    try:
        obj = IPWhois(ip)
        whois_result = obj.lookup_whois()

        st.subheader("📄 WHOIS Information (Local)")

        # Registrant
        contacts = whois_result.get("nets", [{}])[0]
        st.markdown("**Registrant Details**")
        st.table(pd.DataFrame([
            ["Name", contacts.get("name")],
            ["Description", contacts.get("description")],
            ["Country", contacts.get("country")]
        ], columns=["Field", "Value"]))

        # Dates
        st.markdown("**Important Dates**")
        st.table(pd.DataFrame([
            ["CIDR", contacts.get("cidr")],
            ["Start", contacts.get("start_address")],
            ["End", contacts.get("end_address")]
        ], columns=["Field", "Value"]))

    except Exception as e:
        st.error(f"Local WHOIS Error: {e}")
