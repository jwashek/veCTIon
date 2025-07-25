import json
import re
from typing import Dict, List, Set

# Path to MITRE ATT&CK STIX data
MITRE_STIX_FILE = "data/enterprise-attack.json"

# APT group aliases - maps common names to their MITRE identifiers
APT_ALIASES = {
    "Sharp Panda": "APT19",         # Sharp Panda maps to APT19 in MITRE
    "Emissary Panda": "APT19",     
    "Bronze President": "APT19",    
    "Iron Tiger": "APT19",        
    "Sharp Dragon": "APT41",        
    "APT 1": "APT1",
    "APT 28": "APT28",
    "APT 29": "APT29",
    "Fancy Bear": "APT28",
    "Cozy Bear": "APT29",
    "Lazarus": "Lazarus Group",
    "HIDDEN COBRA": "Lazarus Group",
    "Guardians of Peace": "Lazarus Group",
    "APT41": "APT41",
    "Barium": "APT41",
    "Winnti": "APT41",
    "Winnti Group": "APT41"
}

def load_mitre_data(debug: bool = False) -> dict:
    """
    Load MITRE ATT&CK data from the STIX file
    """
    try:
        with open(MITRE_STIX_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if debug:
                print(f"[DEBUG] Loaded MITRE ATT&CK data from {MITRE_STIX_FILE}")
                print(f"[DEBUG] Found {len(data.get('objects', []))} MITRE objects")
            return data
    except FileNotFoundError:
        if debug:
            print(f"[ERROR] MITRE data file not found: {MITRE_STIX_FILE}")
        return {}
    except Exception as e:
        if debug:
            print(f"[ERROR] Failed to load MITRE data: {e}")
        return {}

def resolve_ttps_via_attack(apt_groups: List[str], mitre_data: dict, debug: bool = False) -> Dict[str, Dict[str, List[Dict[str, str]]]]:
    """
    Resolve TTPs for APT groups using MITRE ATT&CK data with alias support

    Returns:
        Dict mapping APT group -> tactic -> list of techniques
    """
    if not apt_groups or not mitre_data:
        return {}

    result = {}

    for apt_group in apt_groups:
        if debug:
            print(f"[DEBUG] Looking for APT group: {apt_group}")

        # Try to resolve alias first
        resolved_apt = APT_ALIASES.get(apt_group, apt_group)
        if resolved_apt != apt_group and debug:
            print(f"[DEBUG] Resolved alias '{apt_group}' -> '{resolved_apt}'")

        # Find the MITRE intrusion set
        mitre_id = None
        for obj in mitre_data.get('objects', []):
            if obj.get('type') == 'intrusion-set':
                # Check name field
                if obj.get('name', '').lower() == resolved_apt.lower():
                    mitre_id = obj.get('id')
                    break

                # Check aliases
                aliases = obj.get('aliases', [])
                for alias in aliases:
                    if alias.lower() == resolved_apt.lower():
                        mitre_id = obj.get('id')
                        break

                if mitre_id:
                    break

        if mitre_id:
            if debug:
                print(f"[DEBUG] Found MITRE ID for {resolved_apt}: {mitre_id}")

            # Find relationships for this intrusion set
            relationships = []
            for obj in mitre_data.get('objects', []):
                if (obj.get('type') == 'relationship' and
                    obj.get('source_ref') == mitre_id and
                    obj.get('relationship_type') == 'uses'):
                    relationships.append(obj.get('target_ref'))

            if debug:
                print(f"[DEBUG] Found {len(relationships)} technique relationships for {resolved_apt}")

            # Get techniques and organize by tactic
            apt_tactics = {}
            processed_techniques = set()

            for target_ref in relationships:
                # Find the technique object
                for obj in mitre_data.get('objects', []):
                    if obj.get('id') == target_ref and obj.get('type') == 'attack-pattern':
                        technique_id = obj.get('external_references', [{}])[0].get('external_id', '')
                        technique_name = obj.get('name', '')

                        if technique_id and technique_name and technique_id not in processed_techniques:
                            # Get kill chain phases (tactics)
                            kill_chain_phases = obj.get('kill_chain_phases', [])

                            for phase in kill_chain_phases:
                                tactic = phase.get('phase_name', 'unknown').replace('-', ' ').title()

                                if tactic not in apt_tactics:
                                    apt_tactics[tactic] = []

                                apt_tactics[tactic].append({
                                    'id': technique_id,
                                    'name': technique_name
                                })

                            processed_techniques.add(technique_id)
                        break

            if apt_tactics:
                result[apt_group] = apt_tactics  # Use original name, not resolved
                if debug:
                    technique_count = sum(len(techniques) for techniques in apt_tactics.values())
                    print(f"[DEBUG] Resolved {technique_count} TTPs for {apt_group}")
            else:
                if debug:
                    print(f"[DEBUG] No TTPs found for {apt_group}")
        else:
            if debug:
                print(f"[DEBUG] No MITRE entry found for APT group: {apt_group}")

    return result
