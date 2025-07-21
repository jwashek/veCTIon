# IOC to APT Enricher
A lightweight CLI tool that enriches Indicators of Compromise (IOCs) with contextual threat intelligence, including associated APT groups, malware families, and MITRE ATT&CK TTPs.

Built for security analysts, threat hunters, and CTI teams who want a fast, scriptable IOC-to-APT attribution.

---

## 🚀 Features

- 🔍 Accepts IOCs: IP address, domain, or file hash
- 🌐 Queries public intel feeds:
  - AlienVault OTX
  - Abuse.ch ThreatFox
- 🧠 Maps returned TTPs to MITRE ATT&CK techniques and tactics
- 📎 Displays related APT groups and malware families (via Malpedia/OTX tagging)
- 💾 Outputs results in console (CSV/JSON export planned)

---

## 📦 Installation

```bash
git clone https://github.com/jwashek/IOC-to-APT-Enricher.git
cd IOC-to-APT-Enricher
pip install -r requirements.txt
```
