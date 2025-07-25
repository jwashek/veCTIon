import os
import requests
import gzip
from typing import Set
from core.base_enricher import BaseEnricher, EnrichmentResult
from core.ioc_utils import detect_ioc_type

class VirusShareEnricher(BaseEnricher):
    def __init__(self, debug=False):
        super().__init__("VirusShare")
        self.debug = debug
        self.hash_database: Set[str] = set()
        self.data_dir = "data/virusshare"
        self.loaded = False
        # Only download files that actually exist (first 5 files = ~655K hashes)
        self.hash_files = [f"VirusShare_{i:05d}.md5" for i in range(5)]

    def is_available(self) -> bool:
        return True

    def _ensure_data_directory(self):
        """Create data directory if it doesn't exist"""
        os.makedirs(self.data_dir, exist_ok=True)

    def _download_hash_file(self, filename: str) -> bool:
        """Download a single hash file from VirusShare"""
        local_path = os.path.join(self.data_dir, filename)

        # Skip if file already exists
        if os.path.exists(local_path):
            if self.debug:
                print(f"[DEBUG] VirusShare: {filename} already exists, skipping download")
            return True

        url = f"https://virusshare.com/hashes/{filename}"

        try:
            if self.debug:
                print(f"[DEBUG] VirusShare: Downloading {filename}...")

            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                with open(local_path, 'wb') as f:
                    f.write(response.content)
                if self.debug:
                    print(f"[DEBUG] VirusShare: Successfully downloaded {filename}")
                return True
            else:
                if self.debug:
                    print(f"[DEBUG] VirusShare: Failed to download {filename} - HTTP {response.status_code}")
                return False

        except Exception as e:
            if self.debug:
                print(f"[DEBUG] VirusShare: Error downloading {filename}: {e}")
            return False

    def _load_hash_file(self, filename: str) -> int:
        """Load hashes from a single file"""
        local_path = os.path.join(self.data_dir, filename)

        if not os.path.exists(local_path):
            return 0

        try:
            count = 0
            # Handle both regular and gzipped files
            if filename.endswith('.gz'):
                with gzip.open(local_path, 'rt') as f:
                    for line in f:
                        hash_value = line.strip()
                        if len(hash_value) == 32 and all(c in '0123456789abcdef' for c in hash_value.lower()):
                            self.hash_database.add(hash_value.lower())
                            count += 1
            else:
                with open(local_path, 'r') as f:
                    for line in f:
                        hash_value = line.strip()
                        if len(hash_value) == 32 and all(c in '0123456789abcdef' for c in hash_value.lower()):
                            self.hash_database.add(hash_value.lower())
                            count += 1

            if self.debug:
                print(f"[DEBUG] VirusShare: Loaded {count} hashes from {filename}")
            return count

        except Exception as e:
            if self.debug:
                print(f"[DEBUG] VirusShare: Error loading {filename}: {e}")
            return 0

    def _load_hash_database(self):
        """Load all hash files into memory"""
        if self.loaded:
            return

        self._ensure_data_directory()

        # Download hash files if they don't exist
        successful_downloads = 0
        for filename in self.hash_files:
            if self._download_hash_file(filename):
                successful_downloads += 1

        if self.debug:
            print(f"[DEBUG] VirusShare: Downloaded {successful_downloads}/{len(self.hash_files)} hash files")

        # Load all available hash files
        total_loaded = 0
        for filename in self.hash_files:
            loaded = self._load_hash_file(filename)
            total_loaded += loaded

        if self.debug:
            print(f"[DEBUG] VirusShare: Total hashes loaded: {total_loaded}")

        self.loaded = True

    def enrich(self, ioc: str, ioc_type: str) -> EnrichmentResult:
        result = EnrichmentResult(source="VirusShare")

        # Only handle MD5 hashes
        if ioc_type != "md5":
            if self.debug:
                print(f"[DEBUG] VirusShare: Unsupported IOC type {ioc_type}")
            return result

        # Load database on first use
        self._load_hash_database()

        # Check if hash exists in database
        ioc_lower = ioc.lower()
        if ioc_lower in self.hash_database:
            if self.debug:
                print(f"[DEBUG] VirusShare: Hash {ioc} found in database")
            result.malware.add("virusshare_malware")
        else:
            if self.debug:
                print(f"[DEBUG] VirusShare: Hash {ioc} not found in database")

        return result
