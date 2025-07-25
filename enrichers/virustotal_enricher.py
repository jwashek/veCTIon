import requests
import time
import re
from core.base_enricher import BaseEnricher, EnrichmentResult
from core.malware_to_apt import map_malware_to_apt

class VirusTotalEnricher(BaseEnricher):
    """VirusTotal IOC enricher with improved error handling"""

    def __init__(self, api_key: str = None, debug=False):
        super().__init__("VirusTotal")
        self.api_key = api_key
        self.debug = debug
        self.base_url = "https://www.virustotal.com/api/v3/"

    def is_available(self) -> bool:
        return bool(self.api_key)

    def enrich(self, ioc: str, ioc_type: str) -> EnrichmentResult:
        result = EnrichmentResult(source="VirusTotal")

        if not self.api_key:
            if self.debug:
                print("[WARN] VirusTotal API key not configured")
            return result

        try:
            headers = {"x-apikey": self.api_key}

            if self.debug:
                print(f"[DEBUG] VirusTotal: Querying {ioc_type} - {ioc}")

            if ioc_type in ['md5', 'sha1', 'sha256']:
                data = self._query_file(ioc, headers)
            elif ioc_type == 'domain':
                data = self._query_domain(ioc, headers)
            elif ioc_type == 'ip':
                data = self._query_ip(ioc, headers)
            else:
                if self.debug:
                    print(f"[DEBUG] VirusTotal: Unsupported IOC type {ioc_type}")
                return result

            if data:
                self._process_response(data, result, ioc_type)
                if result.malware:
                    result.confidence = "high"
                    if self.debug:
                        print(f"[DEBUG] VirusTotal: Found {len(result.malware)} malware families")
                elif self.debug:
                    print("[DEBUG] VirusTotal: No malware detected")
            elif self.debug:
                print("[DEBUG] VirusTotal: No data returned")

        except Exception as e:
            if self.debug:
                print(f"[ERROR] VirusTotal enricher failed: {e}")

        return result

    def _query_file(self, file_hash: str, headers: dict) -> dict:
        """Query VirusTotal file report"""
        url = f"{self.base_url}files/{file_hash}"

        if self.debug:
            print(f"[DEBUG] VirusTotal: GET {url}")

        try:
            response = requests.get(url, headers=headers, timeout=15)

            if self.debug:
                print(f"[DEBUG] VirusTotal: Response {response.status_code}")

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                if self.debug:
                    print("[DEBUG] VirusTotal: File not found in database")
            elif response.status_code == 429:
                if self.debug:
                    print("[DEBUG] VirusTotal: Rate limited")
            else:
                if self.debug:
                    print(f"[DEBUG] VirusTotal: HTTP {response.status_code} - {response.text[:200]}")

        except Exception as e:
            if self.debug:
                print(f"[ERROR] VirusTotal API request failed: {e}")

        return {}

    def _query_domain(self, domain: str, headers: dict) -> dict:
        """Query VirusTotal domain report"""
        url = f"{self.base_url}domains/{domain}"
        response = requests.get(url, headers=headers, timeout=15)
        return response.json() if response.status_code == 200 else {}

    def _query_ip(self, ip: str, headers: dict) -> dict:
        """Query VirusTotal IP report"""
        url = f"{self.base_url}ip_addresses/{ip}"
        response = requests.get(url, headers=headers, timeout=15)
        return response.json() if response.status_code == 200 else {}

    def _process_response(self, data: dict, result: EnrichmentResult, ioc_type: str):
        """Process VirusTotal API response"""
        attributes = data.get('data', {}).get('attributes', {})

        if self.debug:
            print(f"[DEBUG] VirusTotal: Processing response with {len(attributes)} attributes")

        if ioc_type in ['md5', 'sha1', 'sha256']:
            # Process file scan results
            scans = attributes.get('last_analysis_results', {})

            if self.debug:
                malicious_count = sum(1 for scan in scans.values() if scan.get('category') == 'malicious')
                print(f"[DEBUG] VirusTotal: {malicious_count}/{len(scans)} engines detected as malicious")

            # Get meaningful names
            names = attributes.get('names', [])
            for name in names[:5]:  # Limit to first 5 names
                if name and len(name) > 3:
                    clean_name = self._clean_name(name)
                    if clean_name:
                        result.malware.add(clean_name)

            # Process detections from AV engines
            detections_added = 0
            for engine, scan_result in scans.items():
                if scan_result.get('category') == 'malicious':
                    detection = scan_result.get('result', '')
                    if detection:
                        clean_detection = self._clean_detection_name(detection)
                        if clean_detection and detections_added < 10:  # Limit detections
                            result.malware.add(clean_detection)
                            detections_added += 1

                            # Try to map to APT(s) - UPDATED FOR MULTI-APT
                            apt_groups, confidence = map_malware_to_apt(clean_detection)
                            if apt_groups and confidence >= 0.8:
                                if isinstance(apt_groups, list):
                                    for apt_group in apt_groups:
                                        result.apt_groups.add(apt_group)
                                        if self.debug:
                                            print(f"[DEBUG] VirusTotal: Mapped '{clean_detection}' to '{apt_group}'")
                                else:
                                    result.apt_groups.add(apt_groups)
                                    if self.debug:
                                        print(f"[DEBUG] VirusTotal: Mapped '{clean_detection}' to '{apt_groups}'")

    def _clean_name(self, name: str) -> str:
        """Clean file names"""
        if not name:
            return ""

        # Remove common noise
        name = re.sub(r'\.(exe|dll|bin|tmp)$', '', name, flags=re.IGNORECASE)
        name = re.sub(r'^(sample|malware|virus)', '', name, flags=re.IGNORECASE)

        if len(name) < 3:
            return ""

        return name.lower().strip()

    def _clean_detection_name(self, detection: str) -> str:
        """Clean and normalize detection names from AV engines"""
        if not detection:
            return ""

        # Remove common prefixes
        detection = re.sub(r'^(Trojan|Backdoor|Malware|Virus|Worm|Adware)[.:/\-_]?', '', detection, flags=re.IGNORECASE)
        detection = re.sub(r'[.!@#$%^&*()_+=\[\]{}|;:,.<>?/~`]', ' ', detection)
        detection = re.sub(r'\s+', ' ', detection).strip().lower()

        # Filter out generic/noise terms
        noise_terms = ['generic', 'variant', 'packed', 'obfuscated', 'suspicious', 'heur', 'behavioral']
        if any(term in detection for term in noise_terms):
            return ""

        if len(detection) < 3:
            return ""

        return detection
