import argparse
from enrichers.otx import query_otx
from enrichers.threatfox import query_threatfox
from enrichers.mitre_attack import load_mitre_attack, map_ttps

def main():
    parser = argparse.ArgumentParser(description="IOC-to-APT enrichment CLI tool")
    parser.add_argument("--ioc", required=True, help="The IOC to enrich (IP, domain, hash)")
    parser.add_argument("--otx_key", help="AlienVault OTX API key")
    args = parser.parse_args()

    print(f"\n🔎 IOC: {args.ioc}")

    # Enrich via OTX
    otx_results = query_otx(args.ioc, args.otx_key)

    # Enrich via ThreatFox
    tf_results = query_threatfox(args.ioc)

    # Collect all TTPs and normalize
    all_ttps = set(otx_results.get("ttps", []) + tf_results.get("ttps", []))

    # Map TTPs to tactics and descriptions
    mitre_map = load_mitre_attack()
    mapped_ttps = map_ttps(all_ttps, mitre_map)

    print("\n🧠 MITRE ATT&CK Mapping:")
    for tid, data in mapped_ttps.items():
        print(f"{tid} - {data['name']}\t[{', '.join(data['tactics'])}]")

if __name__ == "__main__":
    main()
