import json
import os

MITRE_FILE = "enterprise-attack.json"  # Ensure this file is in your project root or adjust path

def load_mitre_attack():
    """
    Loads MITRE ATT&CK enterprise STIX bundle and builds a technique mapping.
    Returns: dict of {technique_id: {"name": ..., "tactics": [...]}}
    """
    if not os.path.exists(MITRE_FILE):
        raise FileNotFoundError(f"{MITRE_FILE} not found. Download from: https://github.com/mitre/cti")

    with open(MITRE_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    mapping = {}
    for obj in data["objects"]:
        if obj.get("type") != "attack-pattern":
            continue

        ext_refs = obj.get("external_references", [])
        technique_id = next((ref["external_id"] for ref in ext_refs
                             if ref.get("source_name") == "mitre-attack" and ref.get("external_id", "").startswith("T")), None)
        if not technique_id:
            continue

        tactic_list = [phase["phase_name"].title() for phase in obj.get("kill_chain_phases", [])
                       if phase["kill_chain_name"] == "mitre-attack"]

        mapping[technique_id] = {
            "name": obj.get("name", "Unknown"),
            "tactics": tactic_list or ["Unknown"]
        }

    return mapping

def map_ttps(ttp_list, mitre_map):
    """
    Given a list of TTP IDs (e.g. T1059.001), return a dict with names and tactics.
    """
    output = {}
    for tid in ttp_list:
        if tid in mitre_map:
            output[tid] = mitre_map[tid]
        else:
            output[tid] = {"name": "Unknown Technique", "tactics": ["Unknown"]}
    return output
