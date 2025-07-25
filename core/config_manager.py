import os
from typing import Dict, Optional

class ConfigManager:
    """Simple configuration file reader for API keys"""

    def __init__(self, config_file: str = "api_config"):
        self.config_file = config_file
        self.api_keys = {}
        self._load_config()

    def _load_config(self):
        """Load API keys from simple config file"""
        if not os.path.exists(self.config_file):
            print(f"[INFO] No config file found at {self.config_file}")
            return

        try:
            with open(self.config_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()

                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue

                    # Parse key = value format
                    if '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip()

                        if value:  # Only add non-empty values
                            self.api_keys[key] = value

            print(f"[INFO] Loaded {len(self.api_keys)} API keys from {self.config_file}")

        except Exception as e:
            print(f"[ERROR] Failed to load config file: {e}")

    def get_api_key(self, service: str) -> Optional[str]:
        """Get API key for a service"""
        return self.api_keys.get(service)
