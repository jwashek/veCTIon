import requests
import json
import os
import zipfile
import re
from io import BytesIO
from urllib.parse import urlparse
from core.base_enricher import BaseEnricher, EnrichmentResult
from core.malware_to_apt import map_malware_to_apt

class ThreatFoxEnricher(BaseEnricher):
    """ThreatFox IOC enricher"""

    EXPORT_URL = "https://threatfox.abuse.ch/export/json/full/"
    EXTRACTED_FILE = "data/threatfox-iocs-full.json"

    def __init__(self, debug=False):
        super().__init__("ThreatFox")
        self.debug = debug
        self._ensure_data()

    def is_available(self) -> bool:
        return os.path.exists(self.EXTRACTED_FILE)

    def enrich(self, ioc: str, ioc_type: str) -> EnrichmentResult:
        result = EnrichmentResult(source="ThreatFox")

        if not self.is_available():
            if self.debug:
                print(f"[WARN] ThreatFox data not available at {self.EXTRACTED_FILE}")
            return result

        try:
            with open(self.EXTRACTED_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            if self.debug:
                print(f"[ERROR] Could not read ThreatFox data: {e}")
            return result

        ioc_clean = self._clean_ioc(ioc)
        matches = 0

        for group in data.values():
            for entry in group:
                if not isinstance(entry, dict):
                    continue

                entry_ioc = entry.get("ioc_value", "").lower()
                if ioc_clean in entry_ioc:
                    matches += 1
                    self._process_match(entry, result)

        if matches == 0:
            if self.debug:
                print(f"[INFO] ThreatFox: No matches for {ioc}")
        else:
            if self.debug:
                print(f"[INFO] ThreatFox: Found {matches} matches for {ioc}")
            result.confidence = "high" if matches > 3 else "medium"

        return result

    def _clean_ioc(self, ioc: str) -> str:
        """Clean and normalize IOC"""
        parsed = urlparse(ioc)
        if parsed.scheme:
            return parsed.hostname or ioc
        return ioc.strip().lower().rstrip("/")

    def _process_match(self, entry: dict, result: EnrichmentResult):
        """Process a matching ThreatFox entry"""
        # Extract malware
        malware_family = entry.get("malware", "")
        if malware_family:
            result.malware.add(malware_family)

            # Try to map malware to APT group(s)
            apt_groups, confidence = map_malware_to_apt(malware_family)
            if apt_groups and confidence >= 0.8:
                # Handle both single APT and multiple APTs
                if isinstance(apt_groups, list):
                    for apt_group in apt_groups:
                        result.apt_groups.add(apt_group)
                        if self.debug:
                            print(f"[DEBUG] ThreatFox: Mapped '{malware_family}' to '{apt_group}' (confidence: {confidence:.2f})")
                else:
                    result.apt_groups.add(apt_groups)
                    if self.debug:
                        print(f"[DEBUG] ThreatFox: Mapped '{malware_family}' to '{apt_groups}' (confidence: {confidence:.2f})")

        # Process tags
        tags = entry.get("tags", [])
        for tag in tags:
            tag_upper = tag.upper()

            # Check for APT groups
            if "APT" in tag_upper or "GROUP" in tag_upper:
                result.apt_groups.add(tag)

            # Check for TTP IDs (e.g., T1055, T1055.001)
            elif re.match(r"^T\d{4}(\.\d{3})?$", tag_upper):
                result.raw_ttps.add(tag_upper)

    def _ensure_data(self):
        """Download ThreatFox data if not present"""
        if os.path.exists(self.EXTRACTED_FILE):
            return

        # Create data directory if it doesn't exist
        os.makedirs("data", exist_ok=True)

        try:
            if self.debug:
                print("[INFO] Downloading ThreatFox data...")
            response = requests.get(self.EXPORT_URL, timeout=60)

            if response.status_code == 200 and response.headers.get("Content-Type", "").startswith("application/zip"):
                with zipfile.ZipFile(BytesIO(response.content)) as zip_ref:
                    first_json = next((f for f in zip_ref.namelist() if f.endswith(".json")), None)
                    if first_json:
                        # Extract to temporary location first
                        zip_ref.extract(first_json)
                        # Move to correct location
                        os.rename(first_json, self.EXTRACTED_FILE)
                        if self.debug:
                            print(f"[INFO] Downloaded and extracted ThreatFox data to {self.EXTRACTED_FILE}")
            else:
                if self.debug:
                    print(f"[ERROR] Failed to download ThreatFox data: HTTP {response.status_code}")
        except Exception as e:
            if self.debug:
                print(f"[ERROR] Could not download ThreatFox data: {e}")
