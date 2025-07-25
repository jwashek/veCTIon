import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.enrichment_engine import EnrichmentEngine
from core.config_manager import ConfigManager
from enrichers.threatfox_enricher import ThreatFoxEnricher
from enrichers.malwarebazaar_enricher import MalwareBazaarEnricher
from enrichers.urlhaus_enricher import URLhausEnricher
from enrichers.mhr_enricher import MHREnricher
from enrichers.hybrid_analysis_enricher import HybridAnalysisEnricher
from enrichers.otx_enricher import OTXEnricher
from enrichers.virustotal_enricher import VirusTotalEnricher
from enrichers.virusshare_enricher import VirusShareEnricher

ASCII_BANNER = """
                        ░██████  ░██████████░██████
                       ░██   ░██     ░██      ░██
░██    ░██  ░███████  ░██            ░██      ░██   ░███████  ░████████
░██    ░██ ░██    ░██ ░██            ░██      ░██  ░██    ░██ ░██    ░██
 ░██  ░██  ░█████████ ░██            ░██      ░██  ░██    ░██ ░██    ░██
  ░██░██   ░██         ░██   ░██     ░██      ░██  ░██    ░██ ░██    ░██
   ░███     ░███████    ░██████      ░██    ░██████ ░███████  ░██    ░██

         Follow the vector. Unveil the threat.
"""

def main():
    parser = argparse.ArgumentParser(description="veCTIon: Follow the vector. Unveil the threat.")
    parser.add_argument("--ioc", "-i", required=True, help="Indicator of Compromise (IP, domain, URL, hash)")
    parser.add_argument("--debug", "-d", action="store_true", help="Enable debug output")

    # API key overrides (will override config file values)
    parser.add_argument("--vt-key", help="VirusTotal API key (overrides config)")
    parser.add_argument("--ha-key", help="Hybrid Analysis API key (overrides config)")
    parser.add_argument("--otx-key", help="AlienVault OTX API key (overrides config)")
    parser.add_argument("--urlhaus-key", help="URLhaus API key (overrides config)")

    args = parser.parse_args()

    print(ASCII_BANNER)

    # Load configuration
    config_mgr = ConfigManager()

    # Initialize enrichment engine
    engine = EnrichmentEngine(debug=args.debug)

    # Helper function to get API key (CLI args override config file)
    def get_key(cli_arg, config_key):
        return cli_arg or config_mgr.get_api_key(config_key)

    # Register enrichers with API keys from config or CLI
    engine.register_enricher(ThreatFoxEnricher(debug=args.debug))
    engine.register_enricher(MalwareBazaarEnricher(debug=args.debug))

    urlhaus_key = get_key(args.urlhaus_key, 'urlhaus-key')
    engine.register_enricher(URLhausEnricher(api_key=urlhaus_key, debug=args.debug))

    engine.register_enricher(MHREnricher(debug=args.debug))

    vt_key = get_key(args.vt_key, 'vt-key')
    if vt_key:
        engine.register_enricher(VirusTotalEnricher(api_key=vt_key, debug=args.debug))

    ha_key = get_key(args.ha_key, 'ha-key')
    if ha_key:
        engine.register_enricher(HybridAnalysisEnricher(api_key=ha_key, debug=args.debug))

    otx_key = get_key(args.otx_key, 'otx-key')
    if otx_key:
        engine.register_enricher(OTXEnricher(api_key=otx_key, debug=args.debug))

    virusshare_enricher = VirusShareEnricher(debug=args.debug)
    engine.register_enricher(virusshare_enricher)

    if args.debug:
        print(f"[INFO] Registered {len(engine.enrichers)} enrichers")
        if urlhaus_key:
            print("[INFO] Using URLhaus with API key")
        else:
            print("[INFO] Using URLhaus without API key (limited rate)")

    # Enrich the IOC
    result = engine.enrich_ioc(args.ioc)

    # Check if we found anything
    has_results = (result.get('malware') or
                  result.get('apt_group') or
                  result.get('ttps'))

    # Display results with updated label
    print(f"\n📍 IOC: {args.ioc}")

    # Always show malware if found
    malware_list = result.get('malware', [])
    if malware_list:
        print(f"🦠 Malware: {', '.join(malware_list)}")
    else:
        print("🦠 Malware: Unknown")

    # Show Threat Actor instead of APT Group
    threat_actors = result.get('apt_group', [])
    if threat_actors:
        print(f"👤 Threat Actor: {', '.join(threat_actors)}")
    else:
        print("👤 Threat Actor: Unknown")

    # Debug output for TTP structure
    if args.debug:
        ttps_by_actor = result.get("ttps", {})
        print(f"[DEBUG] TTPs structure: {ttps_by_actor}")
        print(f"[DEBUG] TTPs type: {type(ttps_by_actor)}")
        if ttps_by_actor:
            for actor, data in ttps_by_actor.items():
                print(f"[DEBUG] Actor '{actor}' has data type: {type(data)}")
                if isinstance(data, dict):
                    print(f"[DEBUG] Actor '{actor}' tactics: {list(data.keys())}")

    # Display TTPs grouped by threat actor
    ttps_by_actor = result.get("ttps", {})
    if ttps_by_actor:
        print("⚔️  TTPs by Threat Actor:")
        for actor, ttps_by_tactic in sorted(ttps_by_actor.items()):
            print(f"    👤 {actor}:")

            # Check if ttps_by_tactic is actually a dict of tactics
            if isinstance(ttps_by_tactic, dict):
                for tactic, ttp_list in sorted(ttps_by_tactic.items()):
                    print(f"      📋 {tactic.title().replace('-', ' ')}:")
                    # Remove duplicates and handle different data types
                    seen = set()
                    for ttp in ttp_list:
                        # Handle both dict and string formats
                        if isinstance(ttp, dict):
                            ttp_id = ttp.get('id', 'Unknown')
                            ttp_name = ttp.get('name', 'Unknown Technique')
                        elif isinstance(ttp, str):
                            ttp_id = ttp
                            ttp_name = ttp
                        else:
                            continue

                        if ttp_id not in seen:
                            print(f"        • {ttp_id}: {ttp_name}")
                            seen.add(ttp_id)
            else:
                print(f"      [DEBUG] Unexpected data type for {actor}: {type(ttps_by_tactic)}")
    else:
        print("⚔️  TTPs: Unknown")

    # Summary for clean IOCs
    if not has_results:
        print(f"\n❌ IOC '{args.ioc}' is not known to be tied to any malware or threat campaigns.")
        print("   This could mean:")
        print("   • The IOC is benign")
        print("   • It's too new to be catalogued")
        print("   • It's not covered by the current threat intelligence sources")
        print(f"   • The confidence level is less than 80%")
        if not any([vt_key, ha_key, otx_key]):
            print("   • No API keys are being loaded from your 'api_config' file. Try adding keys for better coverage")
    elif malware_list and not threat_actors and not ttps_by_actor:
        print(f"\n⚠️  IOC '{args.ioc}' is associated with malware but no specific threat actor attribution found.")

if __name__ == "__main__":
    main()
