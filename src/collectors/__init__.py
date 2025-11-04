"""
Feed collectors module - ingests threat intelligence from multiple sources

Available Collectors:
- VirusTotalCollector: Malicious files and URLs from VirusTotal
- AbuseIPDBCollector: IP abuse reports from AbuseIPDB  
- OTXCollector: Community threat intelligence from AlienVault OTX
"""

from src.collectors.base import BaseFeedCollector
from src.collectors.virustotal import VirusTotalCollector
from src.collectors.abuseipdb import AbuseIPDBCollector
from src.collectors.otx import OTXCollector
from src.collectors.manager import CollectorManager, run_collection

__all__ = [
    'BaseFeedCollector',
    'VirusTotalCollector',
    'AbuseIPDBCollector',
    'OTXCollector',
    'CollectorManager',
    'run_collection'
]

