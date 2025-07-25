import requests
from core.base_enricher import BaseEnricher, EnrichmentResult

class MHREnricher(BaseEnricher):
    """Malware Hash Registry (hash.cymru.com) enricher"""

    def __init__(self, debug=False):
        super().__init__("Malware Hash Registry")
        self.debug = debug
        self.base_url = "https://hash.cymru.com"

    def is_available(self) -> bool:
        return True  # Public service, always available

    def enrich(self, ioc: str, ioc_type: str) -> EnrichmentResult:
        result = EnrichmentResult(source="MHR")

        try:
            if ioc_type in ['md5', 'sha1', 'sha256']:
                is_malicious = self._query_hash(ioc)
                if is_malicious:
                    result.malware.add("unknown_malware")  # MHR only tells us it's malicious
                    result.confidence = "medium"
                    if self.debug:
                        print(f"[DEBUG] MHR: Hash {ioc} marked as malicious")
                elif self.debug:
                    print(f"[DEBUG] MHR: Hash {ioc} not found or clean")

        except Exception as e:
            if self.debug:
                print(f"[ERROR] MHR enricher failed: {e}")

        return result

    def _query_hash(self, hash_value: str) -> bool:
        """Query MHR to check if hash is malicious"""
        try:
            # Use the simple text interface
            response = requests.post(
                f"{self.base_url}/lookup/",
                data={"hashes": hash_value},
                timeout=10,
                headers={"User-Agent": "veCTIon"}
            )

            if response.status_code == 200:
                # MHR returns results in format: hash,timestamp,av_hits
                # If hash is found as malicious, it will be in the response
                return hash_value.lower() in response.text.lower()

        except Exception:
            pass

        return False
