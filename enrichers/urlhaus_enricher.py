import requests
import json
from core.base_enricher import BaseEnricher, EnrichmentResult
from core.malware_to_apt import map_malware_to_apt

class URLhausEnricher(BaseEnricher):
    """URLhaus IOC enricher"""

    API_URL = "https://urlhaus-api.abuse.ch/v1/"

    def __init__(self, api_key: str = None, debug=False):
        super().__init__("URLhaus")
        self.api_key = api_key
        self.debug = debug

    def is_available(self) -> bool:
        return True

    def enrich(self, ioc: str, ioc_type: str) -> EnrichmentResult:
        result = EnrichmentResult(source="URLhaus")

        try:
            data = None

            if ioc_type == 'url':
                data = self._query_url(ioc)
            elif ioc_type == 'domain':
                data = self._query_host(ioc)
            elif ioc_type in ['md5', 'sha256']:
                data = self._query_payload(ioc)

            if data and data.get('query_status') == 'ok':
                self._process_response(data, result)
                if result.malware or result.apt_groups:
                    result.confidence = "high"
                    if self.debug:
                        print(f"[DEBUG] URLhaus: Found data for {ioc}")
            elif self.debug:
                print(f"[DEBUG] URLhaus: No matches for {ioc}")

        except Exception as e:
            if self.debug:
                print(f"[ERROR] URLhaus enricher failed: {e}")

        return result

    def _query_url(self, url: str) -> dict:
        """Query URLhaus by URL"""
        headers = self._get_headers()
        payload = {'url': url}

        if self.debug:
            print(f"[DEBUG] URLhaus: Sending URL: {url}")

        try:
            response = requests.post(
                f"{self.API_URL}url/",
                data=payload,
                headers=headers,
                timeout=10
            )

            if self.debug:
                print(f"[DEBUG] URLhaus: Response status: {response.status_code}")
                print(f"[DEBUG] URLhaus: Response text: {response.text[:200]}")

            return response.json() if response.status_code == 200 else {}

        except Exception as e:
            if self.debug:
                print(f"[ERROR] URLhaus URL query failed: {e}")
            return {}

    def _query_host(self, host: str) -> dict:
        """Query URLhaus by host/domain"""
        headers = self._get_headers()
        payload = {'host': host}

        if self.debug:
            print(f"[DEBUG] URLhaus: Sending host: {host}")

        try:
            response = requests.post(
                f"{self.API_URL}host/",
                data=payload,
                headers=headers,
                timeout=10
            )

            if self.debug:
                print(f"[DEBUG] URLhaus: Response status: {response.status_code}")
                print(f"[DEBUG] URLhaus: Response text: {response.text[:200]}")

            return response.json() if response.status_code == 200 else {}

        except Exception as e:
            if self.debug:
                print(f"[ERROR] URLhaus host query failed: {e}")
            return {}

    def _query_payload(self, payload_hash: str) -> dict:
        """Query URLhaus by payload hash"""
        headers = self._get_headers()
        payload_data = {f'{self._detect_hash_type(payload_hash)}_hash': payload_hash}

        if self.debug:
            print(f"[DEBUG] URLhaus: Sending payload hash: {payload_hash}")

        try:
            response = requests.post(
                f"{self.API_URL}payload/",
                data=payload_data,
                headers=headers,
                timeout=10
            )

            if self.debug:
                print(f"[DEBUG] URLhaus: Response status: {response.status_code}")
                print(f"[DEBUG] URLhaus: Response text: {response.text[:200]}")

            return response.json() if response.status_code == 200 else {}

        except Exception as e:
            if self.debug:
                print(f"[ERROR] URLhaus payload query failed: {e}")
            return {}

    def _get_headers(self) -> dict:
        """Get request headers with optional API key"""
        headers = {
            'User-Agent': 'Mozilla/5.0',
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        if self.api_key:
            headers['Auth-Key'] = self.api_key

        return headers

    def _detect_hash_type(self, hash_value: str) -> str:
        """Detect hash type for URLhaus API"""
        hash_length = len(hash_value)
        if hash_length == 32:
            return 'md5'
        elif hash_length == 64:
            return 'sha256'
        else:
            return 'sha256'

    def _process_response(self, data: dict, result: EnrichmentResult):
        """Process URLhaus API response"""

        # Handle URL query response
        if 'url_status' in data:
            self._process_url_data(data, result)

        # Handle host query response
        elif 'urls' in data:
            self._process_host_data(data, result)

        # Handle payload query response
        elif 'sha256_hash' in data or 'md5_hash' in data:
            self._process_payload_data(data, result)

    def _process_url_data(self, data: dict, result: EnrichmentResult):
        """Process URL-specific data from URLhaus"""
        if self.debug:
            print(f"[DEBUG] URLhaus: _process_url_data called")
            print(f"[DEBUG] URLhaus: Raw data keys: {list(data.keys())}")
            print(f"[DEBUG] URLhaus: Threat field: {data.get('threat', 'N/A')}")
            print(f"[DEBUG] URLhaus: Tags field: {data.get('tags', 'N/A')}")

        # Extract threat info (but prefer tags for actual malware families)
        threat = data.get('threat', '')
        if threat and threat.lower() not in ['malware_download', 'malware', 'generic']:
            result.malware.add(threat.lower())
            if self.debug:
                print(f"[DEBUG] URLhaus: Added threat: {threat.lower()}")

            # Map to APT group(s) - UPDATED FOR MULTI-APT
            apt_groups, confidence = map_malware_to_apt(threat)
            if apt_groups and confidence >= 0.8:
                if isinstance(apt_groups, list):
                    for apt_group in apt_groups:
                        result.apt_groups.add(apt_group)
                        if self.debug:
                            print(f"[DEBUG] URLhaus: Mapped threat '{threat}' to '{apt_group}' (confidence: {confidence:.2f})")
                else:
                    result.apt_groups.add(apt_groups)
                    if self.debug:
                        print(f"[DEBUG] URLhaus: Mapped threat '{threat}' to '{apt_groups}' (confidence: {confidence:.2f})")

        # Extract malware families from tags (this is where the good stuff is!)
        tags = data.get('tags', [])
        if tags and isinstance(tags, list):
            # Generic/technical tags to ignore
            ignore_tags = {
                '32-bit', '64-bit', 'arm', 'x86', 'elf', 'pe', 'mach-o',
                'windows', 'linux', 'android', 'macos',
                'packed', 'upx', 'encrypted', 'obfuscated'
            }

            for tag in tags:
                if tag and isinstance(tag, str):
                    tag_lower = tag.lower().strip()

                    # Skip generic/technical tags
                    if tag_lower in ignore_tags:
                        continue

                    # Check for APT indicators in tags
                    if 'apt' in tag_lower or 'group' in tag_lower:
                        result.apt_groups.add(tag)
                        if self.debug:
                            print(f"[DEBUG] URLhaus: Added APT group from tag: {tag}")

                    # Add malware family tags (these are the valuable ones like 'mirai', 'Mozi')
                    else:
                        result.malware.add(tag_lower)
                        if self.debug:
                            print(f"[DEBUG] URLhaus: Added malware from tag: {tag_lower}")

                        # Try to map tag to APT group(s) - UPDATED FOR MULTI-APT
                        apt_groups, confidence = map_malware_to_apt(tag_lower)
                        if apt_groups and confidence >= 0.8:
                            if isinstance(apt_groups, list):
                                for apt_group in apt_groups:
                                    result.apt_groups.add(apt_group)
                                    if self.debug:
                                        print(f"[DEBUG] URLhaus: Mapped tag '{tag_lower}' to '{apt_group}' (confidence: {confidence:.2f})")
                            else:
                                result.apt_groups.add(apt_groups)
                                if self.debug:
                                    print(f"[DEBUG] URLhaus: Mapped tag '{tag_lower}' to '{apt_groups}' (confidence: {confidence:.2f})")

        # Extract payloads information
        payloads = data.get('payloads', [])
        if payloads and isinstance(payloads, list):
            for payload in payloads:
                if isinstance(payload, dict):
                    # Extract malware family from payload
                    malware_family = payload.get('malware_family', '')
                    if malware_family:
                        result.malware.add(malware_family.lower())
                        if self.debug:
                            print(f"[DEBUG] URLhaus: Added malware family from payload: {malware_family.lower()}")

                        # Map to APT(s) - UPDATED FOR MULTI-APT
                        apt_groups, confidence = map_malware_to_apt(malware_family)
                        if apt_groups and confidence >= 0.8:
                            if isinstance(apt_groups, list):
                                for apt_group in apt_groups:
                                    result.apt_groups.add(apt_group)
                                    if self.debug:
                                        print(f"[DEBUG] URLhaus: Mapped payload family '{malware_family}' to '{apt_group}'")
                            else:
                                result.apt_groups.add(apt_groups)
                                if self.debug:
                                    print(f"[DEBUG] URLhaus: Mapped payload family '{malware_family}' to '{apt_groups}'")

    def _process_host_data(self, data: dict, result: EnrichmentResult):
        """Process host/domain data from URLhaus"""
        urls = data.get('urls', [])

        for url_entry in urls:
            if isinstance(url_entry, dict):
                # Extract threat information
                threat = url_entry.get('threat', '')
                if threat:
                    result.malware.add(threat.lower())

                    # Map to APT(s) - UPDATED FOR MULTI-APT
                    apt_groups, confidence = map_malware_to_apt(threat)
                    if apt_groups and confidence >= 0.8:
                        if isinstance(apt_groups, list):
                            for apt_group in apt_groups:
                                result.apt_groups.add(apt_group)
                        else:
                            result.apt_groups.add(apt_groups)

                # Extract tags
                tags = url_entry.get('tags', [])
                for tag in tags:
                    if tag:
                        tag_lower = tag.lower()
                        if 'apt' in tag_lower:
                            result.apt_groups.add(tag)
                        elif any(family in tag_lower for family in ['trojan', 'backdoor', 'rat']):
                            result.malware.add(tag_lower)

    def _process_payload_data(self, data: dict, result: EnrichmentResult):
        """Process payload hash data from URLhaus"""
        # Extract malware family
        malware_family = data.get('malware_family', '')
        if malware_family:
            result.malware.add(malware_family.lower())

            # Map to APT group(s) - UPDATED FOR MULTI-APT
            apt_groups, confidence = map_malware_to_apt(malware_family)
            if apt_groups and confidence >= 0.8:
                if isinstance(apt_groups, list):
                    for apt_group in apt_groups:
                        result.apt_groups.add(apt_group)
                        if self.debug:
                            print(f"[DEBUG] URLhaus: Mapped malware '{malware_family}' to '{apt_group}' (confidence: {confidence:.2f})")
                else:
                    result.apt_groups.add(apt_groups)
                    if self.debug:
                        print(f"[DEBUG] URLhaus: Mapped malware '{malware_family}' to '{apt_groups}' (confidence: {confidence:.2f})")

        # Extract signature (often contains additional malware info)
        signature = data.get('signature', '')
        if signature and signature != malware_family:
            result.malware.add(signature.lower())

        # Extract from URLs that delivered this payload
        urls = data.get('urls', [])
        for url_entry in urls:
            if isinstance(url_entry, dict):
                # Extract additional threat info
                threat = url_entry.get('threat', '')
                if threat and threat.lower() != malware_family.lower():
                    result.malware.add(threat.lower())

                # Extract tags
                tags = url_entry.get('tags', [])
                for tag in tags:
                    if tag:
                        tag_lower = tag.lower()
                        if 'apt' in tag_lower:
                            result.apt_groups.add(tag)
