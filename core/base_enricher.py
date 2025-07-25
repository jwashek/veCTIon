from abc import ABC, abstractmethod
from typing import Dict, List, Set
from dataclasses import dataclass, field

@dataclass
class EnrichmentResult:
    """Standardized result structure for all enrichers"""
    malware: Set[str] = field(default_factory=set)
    apt_groups: Set[str] = field(default_factory=set)
    tools: Set[str] = field(default_factory=set)
    ttps: Dict[str, List[Dict[str, str]]] = field(default_factory=dict)
    raw_ttps: Set[str] = field(default_factory=set)  # For TTP IDs like T1055
    confidence: str = "unknown"  # low, medium, high
    source: str = ""

    def merge(self, other: 'EnrichmentResult') -> 'EnrichmentResult':
        """Merge two enrichment results"""
        merged = EnrichmentResult()
        merged.malware = self.malware.union(other.malware)
        merged.apt_groups = self.apt_groups.union(other.apt_groups)
        merged.tools = self.tools.union(other.tools)
        merged.raw_ttps = self.raw_ttps.union(other.raw_ttps)

        # Merge TTP dictionaries
        merged.ttps = self.ttps.copy()
        for tactic, techniques in other.ttps.items():
            if tactic in merged.ttps:
                # Avoid duplicates by converting to dict and back
                existing = {t['id']: t for t in merged.ttps[tactic]}
                for tech in techniques:
                    existing[tech['id']] = tech
                merged.ttps[tactic] = list(existing.values())
            else:
                merged.ttps[tactic] = techniques.copy()

        return merged

class BaseEnricher(ABC):
    """Base class for all IOC enrichers"""

    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    def enrich(self, ioc: str, ioc_type: str) -> EnrichmentResult:
        """Enrich an IOC and return standardized results"""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this enricher is available/configured"""
        pass
