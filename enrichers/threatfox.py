import requests

THREATFOX_API_URL = "https://threatfox.abuse.ch/api/v1/"

def query_threatfox(ioc):
    """
    Query ThreatFox for an IOC and return related tags, malware names, and fake TTP tags if present.

    Returns a dict: {"actors": [...], "malware": [...], "ttps": [...]}
    """
    try:
        response = requests.post(
        THREATFOX_API_URL,
        data={"query": "search_ioc", "search_term": ioc},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        if response.status_code != 200:
            print(f"❌ ThreatFox query failed: {response.status_code}")
            return {"actors": [], "malware": [], "ttps": []}
        results = response.json().get("data", [])
    except Exception as e:
        print(f"❌ ThreatFox error: {e}")
        return {"actors": [], "malware": [], "ttps": []}

    actors = set()
    malware = set()
    ttps = set()

    for entry in results:
        malware_family = entry.get("malware", "")
        threat_type = entry.get("threat_type", "")
        tags = entry.get("tags", [])

        if malware_family:
            malware.add(malware_family)

        for tag in tags:
            tag_lower = tag.lower()
            if "apt" in tag_lower or "group" in tag_lower:
                actors.add(tag)
            elif tag.upper().startswith("T") and "." in tag:
                ttps.add(tag.upper())
            elif any(keyword in tag_lower for keyword in ["ransom", "trojan", "stealer", "loader"]):
                malware.add(tag)

    return {
        "actors": sorted(actors),
        "malware": sorted(malware),
        "ttps": sorted(ttps)
    }
