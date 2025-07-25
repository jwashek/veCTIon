import json
import os
from typing import List, Dict
from collections import defaultdict
from .base_enricher import BaseEnricher, EnrichmentResult
from .ioc_utils import detect_ioc_type
from .malware_to_apt import map_malware_to_apt

class EnrichmentEngine:
    """Main engine that orchestrates multiple enrichers"""

    def __init__(self, debug=False):
        self.enrichers: List[BaseEnricher] = []
        self.debug = debug
        self.mitre_data = self._load_mitre_data()

    def register_enricher(self, enricher: BaseEnricher):
        """Register a new enricher"""
        if enricher.is_available():
            self.enrichers.append(enricher)
            if self.debug:
                print(f"[INFO] Registered enricher: {enricher.name}")
        else:
            if self.debug:
                print(f"[WARN] Enricher {enricher.name} is not available")

    def enrich_ioc(self, ioc: str) -> Dict:
        """Enrich an IOC using all available enrichers"""
        ioc_type = detect_ioc_type(ioc)
        if self.debug:
            print(f"[DEBUG] Detected IOC Type: {ioc_type}")

        combined_result = EnrichmentResult()

        for enricher in self.enrichers:
            try:
                if self.debug:
                    print(f"[INFO] Running enricher: {enricher.name}")
                result = enricher.enrich(ioc, ioc_type)
                combined_result = combined_result.merge(result)
                if self.debug:
                    print(f"[DEBUG] {enricher.name} found: {len(result.malware)} malware, {len(result.apt_groups)} APT groups")
            except Exception as e:
                if self.debug:
                    print(f"[ERROR] Enricher {enricher.name} failed: {e}")

        # Additional malware-to-APT mapping
        additional_apt_groups = set()
        for malware in combined_result.malware:
            apt_groups, confidence = map_malware_to_apt(malware)
            if apt_groups and confidence >= 0.8:
                # Handle both single APT and multiple APTs
                if isinstance(apt_groups, list):
                    additional_apt_groups.update(apt_groups)
                else:
                    additional_apt_groups.add(apt_groups)

        combined_result.apt_groups.update(additional_apt_groups)

        # Resolve TTPs grouped by threat actor
        ttps_by_actor = {}

        # Resolve TTPs for each APT group individually
        if combined_result.apt_groups:
            if self.debug:
                print(f"[DEBUG] Resolving TTPs for threat actors: {list(combined_result.apt_groups)}")

            for apt_group in combined_result.apt_groups:
                apt_ttps = self._resolve_apt_ttps({apt_group})  # Pass single APT as set
                if apt_ttps:
                    ttps_by_actor[apt_group] = apt_ttps
                    if self.debug:
                        total_ttps = sum(len(techniques) for techniques in apt_ttps.values())
                        print(f"[DEBUG] Resolved {total_ttps} TTPs for {apt_group}")

        # Handle individual TTPs (not tied to specific actors)
        if combined_result.raw_ttps:
            if self.debug:
                print(f"[DEBUG] Resolving individual TTPs: {list(combined_result.raw_ttps)}")
            individual_ttps = self._resolve_individual_ttps(combined_result.raw_ttps)
            if individual_ttps:
                ttps_by_actor["Individual TTPs"] = individual_ttps

        return {
            "malware": sorted(combined_result.malware),
            "apt_group": sorted(combined_result.apt_groups),
            "tools": sorted(combined_result.tools),
            "ttps": ttps_by_actor  # Now grouped by threat actor
        }

    def _load_mitre_data(self) -> Dict:
        """Load MITRE ATT&CK data"""
        mitre_file = "data/enterprise-attack.json"
        if not os.path.exists(mitre_file):
            if self.debug:
                print(f"[WARN] MITRE data file not found: {mitre_file}")
            return {}

        try:
            with open(mitre_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if self.debug:
                    print(f"[INFO] Loaded MITRE ATT&CK data with {len(data.get('objects', []))} objects")
                return data
        except Exception as e:
            if self.debug:
                print(f"[ERROR] Failed to load MITRE data: {e}")
            return {}

    def _resolve_apt_ttps(self, apt_groups: set) -> Dict[str, List[Dict[str, str]]]:
        """Resolve TTPs for APT groups using MITRE data"""
        if not self.mitre_data:
            return {}

        tactic_map = defaultdict(list)

        for apt_name in apt_groups:
            if self.debug:
                print(f"[DEBUG] Looking for APT group: {apt_name}")

            apt_name_clean = apt_name.lower().replace("-", "").replace(" ", "")

            # Find intrusion set
            intrusion_sets = [
                obj for obj in self.mitre_data.get("objects", [])
                if obj.get("type") == "intrusion-set"
                and (apt_name_clean in obj.get("name", "").lower().replace("-", "").replace(" ", "")
                     or any(apt_name_clean in alias.lower().replace("-", "").replace(" ", "")
                           for alias in obj.get("aliases", [])))
            ]

            if not intrusion_sets:
                if self.debug:
                    print(f"[DEBUG] No MITRE entry found for APT group: {apt_name}")
                continue

            apt_id = intrusion_sets[0].get("id")
            if self.debug:
                print(f"[DEBUG] Found MITRE ID for {apt_name}: {apt_id}")

            # Find relationships
            relationships = [
                r for r in self.mitre_data.get("objects", [])
                if (r.get("type") == "relationship" and
                    r.get("source_ref") == apt_id and
                    r.get("target_ref", "").startswith("attack-pattern--"))
            ]

            if self.debug:
                print(f"[DEBUG] Found {len(relationships)} technique relationships for {apt_name}")

            technique_ids = set(r["target_ref"] for r in relationships)

            # Extract techniques
            for obj in self.mitre_data.get("objects", []):
                if obj.get("id") in technique_ids and obj.get("external_references"):
                    external_id = None
                    for ref in obj.get("external_references", []):
                        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                            external_id = ref["external_id"]
                            break

                    if not external_id:
                        continue

                    name = obj.get("name", "Unknown Technique")
                    phases = obj.get("kill_chain_phases", [])

                    if not phases:
                        tactic_map["unknown"].append({"id": external_id, "name": name})
                    else:
                        for phase in phases:
                            phase_name = phase.get("phase_name", "unknown")
                            tactic_map[phase_name].append({"id": external_id, "name": name})

        return dict(tactic_map)

    def _resolve_individual_ttps(self, ttp_ids: set) -> Dict[str, List[Dict[str, str]]]:
        """Resolve individual TTP IDs"""
        if not self.mitre_data:
            return {}

        tactic_map = defaultdict(list)

        for obj in self.mitre_data.get("objects", []):
            if obj.get("type") != "attack-pattern" or not obj.get("external_references"):
                continue

            external_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                    external_id = ref["external_id"]
                    break

            if external_id not in ttp_ids:
                continue

            name = obj.get("name", "Unknown Technique")
            phases = obj.get("kill_chain_phases", [])

            if not phases:
                tactic_map["unknown"].append({"id": external_id, "name": name})
            else:
                for phase in phases:
                    phase_name = phase.get("phase_name", "unknown")
                    tactic_map[phase_name].append({"id": external_id, "name": name})

        return dict(tactic_map)
