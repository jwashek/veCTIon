import requests
import json
from core.base_enricher import BaseEnricher, EnrichmentResult
from core.malware_to_apt import map_malware_to_apt

class HybridAnalysisEnricher(BaseEnricher):
    """Hybrid Analysis enricher using correct GET request format"""

    def __init__(self, api_key: str = None, debug=False):
        super().__init__("Hybrid Analysis")
        self.api_key = api_key
        self.debug = debug
        self.base_url = "https://www.hybrid-analysis.com/api/v2"

    def is_available(self) -> bool:
        return bool(self.api_key)

    def enrich(self, ioc: str, ioc_type: str) -> EnrichmentResult:
        result = EnrichmentResult(source="Hybrid Analysis")

        if not self.api_key:
            if self.debug:
                print("[WARN] Hybrid Analysis API key not configured")
            return result

        try:
            if self.debug:
                print(f"[DEBUG] Hybrid Analysis: Querying {ioc_type} - {ioc}")

            if ioc_type in ['md5', 'sha1', 'sha256']:
                data = self._query_hash(ioc)
                if data:
                    self._process_response(data, result)
                    if result.malware or result.apt_groups:
                        result.confidence = "high"
                        if self.debug:
                            print(f"[DEBUG] Hybrid Analysis: Found {len(result.malware)} malware, {len(result.apt_groups)} APT groups")
                elif self.debug:
                    print("[DEBUG] Hybrid Analysis: No data returned")
            else:
                if self.debug:
                    print(f"[DEBUG] Hybrid Analysis: Unsupported IOC type {ioc_type}")

        except Exception as e:
            if self.debug:
                print(f"[ERROR] Hybrid Analysis enricher failed: {e}")

        return result

    def _query_hash(self, hash_value: str) -> dict:
        """Query Hybrid Analysis by hash using GET request (correct method)"""
        headers = {
            "api-key": self.api_key,
            "User-Agent": "veCTIon"
        }

        # Use GET request with hash as URL parameter
        url = f"{self.base_url}/search/hash"
        params = {"hash": hash_value}

        if self.debug:
            print(f"[DEBUG] Hybrid Analysis: GET {url}?hash={hash_value}")

        try:
            response = requests.get(url, headers=headers, params=params, timeout=15)

            if self.debug:
                print(f"[DEBUG] Hybrid Analysis: Response {response.status_code}")

            if response.status_code == 200:
                json_response = response.json()
                if self.debug:
                    if isinstance(json_response, list):
                        print(f"[DEBUG] Hybrid Analysis: Found {len(json_response)} results")
                    else:
                        print(f"[DEBUG] Hybrid Analysis: Response type: {type(json_response)}")
                return json_response
            elif response.status_code == 404:
                if self.debug:
                    print("[DEBUG] Hybrid Analysis: Hash not found")
            elif response.status_code == 400:
                if self.debug:
                    print(f"[DEBUG] Hybrid Analysis: Bad request - {response.text[:300]}")
            elif response.status_code == 403:
                if self.debug:
                    print("[DEBUG] Hybrid Analysis: API key invalid or insufficient permissions")
            elif response.status_code == 429:
                if self.debug:
                    print("[DEBUG] Hybrid Analysis: Rate limited")
            else:
                if self.debug:
                    print(f"[DEBUG] Hybrid Analysis: HTTP {response.status_code}")
                    print(f"[DEBUG] Hybrid Analysis: Response: {response.text[:300]}")

        except requests.exceptions.RequestException as e:
            if self.debug:
                print(f"[ERROR] Hybrid Analysis request failed: {e}")
        except Exception as e:
            if self.debug:
                print(f"[ERROR] Hybrid Analysis unexpected error: {e}")

        return {}

    def _process_response(self, data: dict, result: EnrichmentResult):
        """Process Hybrid Analysis response with better format handling"""
        if not data:
            return

        if self.debug:
            print(f"[DEBUG] Hybrid Analysis: Raw response keys: {list(data.keys()) if isinstance(data, dict) else 'Not a dict'}")

        # Handle different response formats
        samples = []

        if isinstance(data, list):
            samples = data
        elif isinstance(data, dict):
            # Check for different possible structures
            if 'result' in data:
                samples = data['result']
            elif 'data' in data:
                samples = data['data']
            else:
                # Treat the dict itself as a single sample
                samples = [data]

        if not isinstance(samples, list):
            samples = [samples] if samples else []

        if self.debug:
            print(f"[DEBUG] Hybrid Analysis: Processing {len(samples)} samples")

        for i, sample in enumerate(samples):
            if not isinstance(sample, dict):
                if self.debug:
                    print(f"[DEBUG] Hybrid Analysis: Sample {i} is not a dict: {type(sample)}")
                continue

            # Extract basic info
            threat_score = sample.get("threat_score", 0)
            verdict = sample.get("verdict", "")
            vx_family = sample.get("vx_family", "")

            if self.debug:
                print(f"[DEBUG] Hybrid Analysis: Sample {i} - threat_score={threat_score}, verdict='{verdict}', vx_family='{vx_family}'")

            # Process samples with some threat indication
            if threat_score > 30 or verdict in ["malicious", "suspicious"]:

                # Extract malware families
                families = sample.get("malware_families", [])
                if families:
                    if self.debug:
                        print(f"[DEBUG] Hybrid Analysis: Found malware_families: {families}")
                    for family in families:
                        if family and isinstance(family, str):
                            clean_family = family.lower().strip()
                            result.malware.add(clean_family)
                            if self.debug:
                                print(f"[DEBUG] Hybrid Analysis: Added malware family: {clean_family}")

                            # Try to map to APT(s) - UPDATED FOR MULTI-APT
                            apt_groups, confidence = map_malware_to_apt(clean_family)
                            if apt_groups and confidence >= 0.8:
                                if isinstance(apt_groups, list):
                                    for apt_group in apt_groups:
                                        result.apt_groups.add(apt_group)
                                        if self.debug:
                                            print(f"[DEBUG] Hybrid Analysis: Mapped '{clean_family}' to '{apt_group}' (confidence: {confidence:.2f})")
                                else:
                                    result.apt_groups.add(apt_groups)
                                    if self.debug:
                                        print(f"[DEBUG] Hybrid Analysis: Mapped '{clean_family}' to '{apt_groups}' (confidence: {confidence:.2f})")

                # Extract vx_family (virus family name)
                if vx_family:
                    clean_vx = vx_family.lower().strip()
                    result.malware.add(clean_vx)
                    if self.debug:
                        print(f"[DEBUG] Hybrid Analysis: Added vx_family: {clean_vx}")

                    # Try to map vx_family to APT(s) - UPDATED FOR MULTI-APT
                    apt_groups, confidence = map_malware_to_apt(clean_vx)
                    if apt_groups and confidence >= 0.8:
                        if isinstance(apt_groups, list):
                            for apt_group in apt_groups:
                                result.apt_groups.add(apt_group)
                                if self.debug:
                                    print(f"[DEBUG] Hybrid Analysis: Mapped vx_family '{clean_vx}' to '{apt_group}'")
                        else:
                            result.apt_groups.add(apt_groups)
                            if self.debug:
                                print(f"[DEBUG] Hybrid Analysis: Mapped vx_family '{clean_vx}' to '{apt_groups}'")

                # Extract from type_short
                type_short = sample.get("type_short", [])
                if isinstance(type_short, list):
                    for malware_type in type_short:
                        if malware_type and isinstance(malware_type, str):
                            clean_type = malware_type.lower().strip()
                            if any(keyword in clean_type for keyword in ["trojan", "backdoor", "rat", "stealer", "malware"]):
                                result.malware.add(clean_type)
                                if self.debug:
                                    print(f"[DEBUG] Hybrid Analysis: Added malware type: {clean_type}")
