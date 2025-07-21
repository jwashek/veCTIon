import requests

OTX_API_BASE = "https://otx.alienvault.com/api/v1/indicators"

def query_otx(ioc, apikey=None):
    """
    Query OTX for an IOC and extract relevant enrichment fields:
    - APT groups (via pulse tags)
    - Malware families (via pulse names/tags)
    - MITRE TTPs (ATT&CK technique IDs)

    Returns a dict: {"actors": [...], "malware": [...], "ttps": [...]}
    """
    if not apikey:
        print("⚠️  Skipping OTX enrichment (no API key provided)")
        return {"actors": [], "malware": [], "ttps": []}

    ioc_type = determine_ioc_type(ioc)
    if not ioc_type:
        print("❌ Unsupported IOC type for OTX.")
        return {"actors": [], "malware": [], "ttps": []}

    url = f"{OTX_API_BASE}/{ioc_type}/{ioc}/general"
    headers = {"X-OTX-API-KEY": apikey}
    try:
        r = requests.get(url, headers=headers)
        if r.status_code != 200:
            print(f"❌ OTX error: {r.status_code}")
            return {"actors": [], "malware": [], "ttps": []}
        data = r.json()
    except Exception as e:
        print(f"❌ Failed to query OTX: {e}")
        return {"actors": [], "malware": [], "ttps": []}

    # Extract from pulses
    actors = set()
    malware = set()
    ttps = set()

    for pulse in data.get("pulse_info", {}).get("pulses", []):
        tags = pulse.get("tags", [])
        name = pulse.get("name", "")
        for tag in tags:
            if "apt" in tag.lower() or "group" in tag.lower():
                actors.add(tag)
            if "trojan" in tag.lower() or "ransom" in tag.lower() or "botnet" in tag.lower():
                malware.add(tag)
            if tag.upper().startswith("T") and "." in tag:
                ttps.add(tag.upper())
        if name:
            malware.add(name)

    return {
        "actors": sorted(actors),
        "malware": sorted(malware),
        "ttps": sorted(ttps)
    }

def determine_ioc_type(ioc):
    if "." in ioc and ":" not in ioc:
        if all(part.isdigit() for part in ioc.split(".") if part.isdigit()):
            return "IPv4"
        elif "." in ioc:
            return "domain"
    elif len(ioc) in [32, 40, 64]:  # MD5/SHA1/SHA256
        return "file"
    return None
