import requests
import json
import os
from typing import Set
from core.base_enricher import BaseEnricher, EnrichmentResult
from core.malware_to_apt import map_malware_to_apt
from core.apt_to_ttps import resolve_ttps_via_attack

class OTXEnricher(BaseEnricher):
    def __init__(self, api_key: str, debug: bool = False):
        super().__init__("AlienVault OTX")
        self.api_key = api_key
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.debug = debug
        self.known_malware = self._load_known_malware()

    def _load_known_malware(self) -> Set[str]:
        """Load known legitimate malware families from file"""
        known_malware = set()

        # Try to load from data/known_malware.txt
        malware_file = os.path.join(os.path.dirname(__file__), '..', 'data', 'known_malware.txt')

        try:
            with open(malware_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        known_malware.add(line.lower())

            if self.debug:
                print(f"[DEBUG] OTX: Loaded {len(known_malware)} known malware families")

        except FileNotFoundError:
            if self.debug:
                print(f"[DEBUG] OTX: Known malware file not found at {malware_file}")
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] OTX: Error loading known malware: {e}")

        return known_malware

    def is_available(self) -> bool:
        return bool(self.api_key)

    def enrich(self, ioc: str, ioc_type: str) -> EnrichmentResult:
        result = EnrichmentResult(source="AlienVault OTX")

        try:
            # Only support certain IOC types
            if ioc_type not in ['ip', 'domain', 'md5', 'sha1', 'sha256', 'url']:
                if self.debug:
                    print(f"[DEBUG] OTX: Unsupported IOC type {ioc_type}")
                return result

            response = self._query_otx(ioc, ioc_type)
            if response:
                self._process_response(response, result)

        except Exception as e:
            if self.debug:
                print(f"[ERROR] OTX enricher failed: {e}")

        return result

    def _query_otx(self, ioc: str, ioc_type: str):
        """Query OTX API for IOC information"""
        headers = {
            'X-OTX-API-KEY': self.api_key,
            'User-Agent': 'veCTIon-TI-Tool'
        }

        # Map IOC types to OTX endpoints
        endpoint_map = {
            'ip': f"indicators/IPv4/{ioc}/general",
            'domain': f"indicators/domain/{ioc}/general",
            'md5': f"indicators/file/{ioc}/general",
            'sha1': f"indicators/file/{ioc}/general",
            'sha256': f"indicators/file/{ioc}/general",
            'url': f"indicators/url/{ioc}/general"
        }

        endpoint = endpoint_map.get(ioc_type)
        if not endpoint:
            return None

        url = f"{self.base_url}/{endpoint}"

        try:
            response = requests.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                return response.json()
            else:
                if self.debug:
                    print(f"[DEBUG] OTX: HTTP {response.status_code}")
                return None
        except requests.RequestException as e:
            if self.debug:
                print(f"[DEBUG] OTX: Request failed: {e}")
            return None

    def _process_response(self, data: dict, result: EnrichmentResult):
        """Process OTX API response"""
        if self.debug:
            print(f"[DEBUG] OTX: Processing response")

        # Get pulses (threat intelligence reports)
        pulses = data.get('pulse_info', {}).get('pulses', [])

        for pulse in pulses:
            # Extract malware families
            malware_families = pulse.get('malware_families', [])
            for family in malware_families:
                family_name = family.get('display_name', '').strip()
                if self._is_legitimate_malware(family_name):
                    cleaned_name = family_name.lower().replace(' ', '_')
                    result.malware.add(cleaned_name)
                    if self.debug:
                        print(f"[DEBUG] OTX: Found legitimate malware: '{family_name}' -> cleaned: '{cleaned_name}'")

                    # Try to map to APT group
                    apt_groups, confidence = map_malware_to_apt(family_name)
                    if apt_groups and confidence >= 0.8:
                        if isinstance(apt_groups, list):
                            for apt_group in apt_groups:
                                result.apt_groups.add(apt_group)
                        else:
                            result.apt_groups.add(apt_groups)
                else:
                    if self.debug:
                        print(f"[DEBUG] OTX: Filtered junk malware: '{family_name}'")

            # Extract adversary (APT group names)
            adversary = pulse.get('adversary', '').strip()
            if adversary and self._is_legitimate_apt(adversary):
                result.apt_groups.add(adversary)
                if self.debug:
                    print(f"[DEBUG] OTX: Found legitimate APT: '{adversary}'")

            # Extract relevant tags (be very selective)
            tags = pulse.get('tags', [])
            for tag in tags:
                tag_clean = tag.lower().strip()
                if self._is_legitimate_apt(tag_clean):
                    result.apt_groups.add(tag_clean)
                    if self.debug:
                        print(f"[DEBUG] OTX: Found legitimate APT from tag: '{tag_clean}'")
                else:
                    if self.debug:
                        print(f"[DEBUG] OTX: Filtered junk tag: '{tag_clean}'")

    def _is_legitimate_malware(self, name: str) -> bool:
        """Check if a malware name is legitimate using known malware list"""
        if not name or len(name) < 3:
            return False

        name_lower = name.lower().strip()

        # Check against known malware families first
        if name_lower in self.known_malware:
            return True

        # Check if any known malware family is contained in the name
        for known_family in self.known_malware:
            if known_family in name_lower:
                return True

        # Try to map this malware to an APT group - if it maps, it's probably legitimate
        apt_groups, confidence = map_malware_to_apt(name)
        if apt_groups and confidence >= 0.8:
            return True

        # Default to rejecting unknown malware
        return False

    def _is_legitimate_apt(self, name: str) -> bool:
        """Check if an APT name is legitimate by checking if it exists in apt_to_ttps mapping"""
        if not name or len(name) < 3:
            return False

        # Use the existing apt_to_ttps function to validate
        # If it returns TTPs, the APT is legitimate
        try:
            ttps = resolve_ttps_via_attack([name])
            return len(ttps) > 0
        except:
            return False
