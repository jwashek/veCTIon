# IOC to APT Enricher
A lightweight CLI tool that enriches Indicators of Compromise (IOCs) with contextual threat intelligence, including associated APT groups, malware families, and MITRE ATT&CK TTPs.

Built for security analysts, threat hunters, and CTI teams who want a fast, scriptable IOC-to-APT attribution.

---

## Features

- 🔍 **Accepts IOCs**: IP address, domain, or file hash
- 🌐 **Queries public intel feeds**:
  - AlienVault OTX
  - Abuse.ch ThreatFox
- 🧠 **Maps TTPs** to MITRE ATT&CK techniques and tactics
- 📎 **Displays APT groups** and malware families (via Malpedia/OTX tagging)
- 💾 **Outputs results** in console (CSV/JSON export planned)

---

## Installation

```bash
git clone https://github.com/jwashek/IOC-to-APT-Enricher.git
cd IOC-to-APT-Enricher
pip install -r requirements.txt
```

##  Usage
```
python ioc2apt.py --ioc <your-ioc> --otx_key <your-otx-api-key>
```
### Requirements
```
requests
```

## Example
```
python ioc2apt.py --ioc 23.82.142.3 --otx_key abcd1234yourkey
```

### Output:
```
🔎 IOC: 23.82.142.3

🧠 MITRE ATT&CK Mapping:
T1059.001 - PowerShell          [Execution]
T1547.001 - Registry Run Key    [Persistence]
```

📚 Data Sources
* [AlienVault OTX](https://otx.alienvault.com/)
* [ThreatFox](https://threatfox.abuse.ch/) by abuse.ch
* [MITRE ATT&CK STIX](https://github.com/mitre/cti)
* (Future) [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/)
