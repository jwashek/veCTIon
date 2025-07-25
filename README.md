# veCTIon
Follow the vector. Unveil the threat.

veCTIon is a comprehensive threat intelligence enrichment tool that analyzes Indicators of Compromise (IOCs) and provides detailed attribution including malware families, threat actors, and MITRE ATT&CK TTPs.

## Features:
🔍 **Multi-Source Intelligence**: Aggregates data from multiple threat intelligence platforms

🎯 **APT Attribution**: Maps malware families to known threat actors and APT groups

⚔️ **MITRE ATT&CK TTP Integration**: Provides TTPs organized by threat actor and tactic

🚀 **Scalable Architecture**: Easy to add new threat intelligence sources

⚙️ **Config-Driven**: Simple configuration file for API keys

## Supported IOC Types
- Domains (example.com)
- URLs (http://malicious-site.com/payload.exe)
- IP Addresses (192.168.1.1)
- File Hashes (MD5, SHA1, SHA256)

## Supported Threat Intelligence Sources
- ThreatFox (abuse.ch)
- MalwareBazaar (abuse.ch)
- URLhaus (abuse.ch) - API key recommended
- VirusTotal - API key required
- Hybrid Analysis - API key required
- AlienVault OTX - API key required
- Malware Hash Registry (MHR) - Free hash lookups

## Installation:
### Prerequisites:
- Python 3.7 or higher
- (Optional, but recommended) API Keys for Threat Intelligence Sources

### Clone and Install:
```bash
git clone https://github.com/yourusername/veCTIon.git
cd veCTIon
pip install -r requirements.txt
```

### Configuration:
1. Copy the API configuration template:
```bash
cp api_config.example api_config
```
2. Edit api_config with your API keys:
```ini
# Remove the '#' and add your API keys
vt-key = your_virustotal_api_key_here
urlhaus-key = your_urlhaus_api_key_here
ha-key = your_hybrid_analysis_api_key_here
otx-key = your_otx_api_key_here
```
3. Get API Keys (optional but recommended):
  - VirusTotal: Register [here](https://www.virustotal.com/gui/join-us)
  - URLhaus: Register [here](https://urlhaus.abuse.ch/api/)
  - Hybrid Analysis: Register [here](https://www.hybrid-analysis.com/signup)
  - AlienVault OTX: Register [here](https://otx.alienvault.com/api)

## Usage
### Basic Usage:
```bash
# Analyze a domain
python3 veCTIon.py -i malicious-domain.com

# Analyze a hash
python3 veCTIon.py -i 5d41402abc4b2a76b9719d911017c592

# Analyze a URL
python3 veCTIon.py -i "http://malicious-site.com/payload.exe"
```
### Debug Mode:
```bash
# Enable debug output to see detailed processing
python3 veCTIon.py -i malicious-domain.com -d
```

### Command Line Options:
```bash
python3 veCTIon.py -h

options:
  -h, --help            show this help message and exit
  -i IOC, --ioc IOC     IOC to analyze (domain, URL, IP, hash)
  -d, --debug           Enable debug output
  -c CONFIG, --config CONFIG
                        Path to config file (default: api_config)
```

### Example Output:
```
📍 IOC: malicious-domain.com
🦠 Malware: sharp_panda, soul
👤 Threat Actor: APT19, Emissary Panda, Iron Tiger, Sharp Panda
⚔️  TTPs by Threat Actor:
    👤 APT19:
      📋 Command And Control:
        • T1132.001: Standard Encoding
        • T1071.001: Web Protocols
      📋 Defense Evasion:
        • T1218.011: Rundll32
        • T1027.013: Encrypted/Encoded File
    👤 Emissary Panda:
      📋 Collection:
        • T1056.001: Keylogging
        • T1074.001: Local Data Staging
      📋 Credential Access:
        • T1003.002: Security Account Manager
```

## Project Structure
```
veCTIon/
├── veCTIon.py                 # Main application
├── api_config                 # API keys configuration
├── core/                      # Core functionality
│   ├── __init__.py
│   ├── base_enricher.py       # Base enricher class
│   ├── enrichment_engine.py   # Main enrichment engine
│   ├── ioc_utils.py          # IOC type detection
│   ├── malware_to_apt.py     # Malware family mappings
│   └── apt_to_ttps.py        # APT to TTP mappings
├── enrichers/                 # Threat intelligence enrichers
│   ├── __init__.py
│   ├── threatfox_enricher.py
│   ├── malwarebazaar_enricher.py
│   ├── urlhaus_enricher.py
│   ├── virustotal_enricher.py
│   ├── hybrid_analysis_enricher.py
│   ├── otx_enricher.py
│   ├── mhr_enricher.py
│   └── virusshare_enricher.py
└── data/                      # Data files
    ├── enterprise-attack.json # MITRE ATT&CK data
    ├── known_malware.txt      # Known malware families
    └── threatfox-iocs-full.json
```

## Data Maintenance
### Adding New Enrichers:
veCTIon is designed to be easily extensible. To add a new threat intelligence source:

1. Create a new enricher in the `enrichers/` directory:
```python
from core.base_enricher import BaseEnricher, EnrichmentResult

class NewSourceEnricher(BaseEnricher):
    def __init__(self, api_key: str, debug: bool = False):
        super().__init__("New Source")
        self.api_key = api_key
        self.debug = debug

    def is_available(self) -> bool:
        return bool(self.api_key)

    def enrich(self, ioc: str, ioc_type: str) -> EnrichmentResult:
        result = EnrichmentResult(source="New Source")
        # Your enrichment logic here
        return result
```
2. Register it in veCTIon.py:
```python
from enrichers.new_source_enricher import NewSourceEnricher

# Add to main function
if config.get('new-source-key'):
    engine.register_enricher(NewSourceEnricher(
        api_key=config['new-source-key'], 
        debug=args.debug
    ))
```
### Adding New Malware Families:
Edit `data/known_malware.txt` and add new families (one per line):
```txt
new_malware_family
another_malware_variant
...
```
### Adding New APT Mappings:
Edit `core/malware_to_apt.py` to map malware families to APT groups:
```python
MALWARE_TO_APT = {
    "new_malware": "APT42",
    # ...
}
```
### Updating MITRE ATT&CK Data:
Download the latest enterprise-attack.json from MITRE and replace `data/enterprise-attack.json`.

## Contributing
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-enricher`)
3. Commit your changes (`git commit -am 'Add new enricher'`)
4. Push to the branch (`git push origin feature/new-enricher`)
5. Create a Pull Request

## API Rate Limits
Be aware of API rate limits for different services:
* **VirusTotal**: 4 requests/minute (free), 1000/minute (premium)
* **Hybrid Analysis**: Varies by plan
* **OTX**: 1000 requests/hour
* **URLhaus**: Rate limited, API key recommended

## Troubleshooting
### Common Issues:

"No matches found"
* Verify API keys are correctly configured
* Check if IOC exists in threat intelligence databases
* Try with debug mode (`-d`) to see detailed processing

"API Key Error"
* Ensure API keys are valid and active
* Check API key permissions and quotas
* Verify API key format in config file

"Module Import Error"
* Run `pip install -r requirements.txt`
* Ensure Python 3.7+ is being used

## Acknowledgments
* **MITRE ATT&CK** framework for TTP mappings
* **abuse.ch** for ThreatFox, MalwareBazaar, and URLhaus
* **VirusTotal** for malware intelligence
* **AlienVault OTX** for community threat intelligence
* **Hybrid Analysis** for dynamic malware analysis
