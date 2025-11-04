"""
Collector Manager
Orchestrates all threat intelligence feed collectors
"""

import asyncio
import logging
import json
from typing import Dict, Any, List
from datetime import datetime
from sqlalchemy.orm import Session

from src.collectors.virustotal import VirusTotalCollector
from src.collectors.abuseipdb import AbuseIPDBCollector
from src.collectors.otx import OTXCollector

logger = logging.getLogger(__name__)


class CollectorManager:
    """Manages all threat intelligence collectors"""
    
    def __init__(self, config: Dict[str, Any], db_session: Session):
        """
        Initialize collector manager
        
        Args:
            config: Configuration dictionary
            db_session: Database session
        """
        self.config = config
        self.db_session = db_session
        self.collectors = {}
        
        # Initialize collectors based on config
        api_keys = config.get('api_keys', {})
        enabled_feeds = config.get('collectors', {}).get('enabled_feeds', [])
        
        if 'virustotal' in enabled_feeds and api_keys.get('virustotal'):
            self.collectors['virustotal'] = VirusTotalCollector(
                api_keys['virustotal'], 
                db_session
            )
            logger.info("Initialized VirusTotal collector")
        
        if 'abuseipdb' in enabled_feeds and api_keys.get('abuseipdb'):
            self.collectors['abuseipdb'] = AbuseIPDBCollector(
                api_keys['abuseipdb'], 
                db_session
            )
            logger.info("Initialized AbuseIPDB collector")
        
        if 'otx' in enabled_feeds and api_keys.get('otx'):
            self.collectors['otx'] = OTXCollector(
                api_keys['otx'], 
                db_session
            )
            logger.info("Initialized OTX collector")
        
        logger.info(f"Collector manager initialized with {len(self.collectors)} collectors")
    
    async def collect_from_source(self, source_name: str, limit: int = 100) -> Dict[str, Any]:
        """
        Collect threats from a specific source
        
        Args:
            source_name: Name of the source (virustotal, abuseipdb, otx)
            limit: Maximum number of threats to collect
            
        Returns:
            Collection statistics
        """
        collector = self.collectors.get(source_name)
        if not collector:
            logger.warning(f"Collector {source_name} not available")
            return {
                'source': source_name,
                'error': 'Collector not available',
                'collected': 0
            }
        
        try:
            logger.info(f"Starting collection from {source_name}")
            stats = await collector.collect(limit)
            logger.info(f"Completed collection from {source_name}: {stats.get('collected', 0)} threats")
            return stats
        except Exception as e:
            logger.error(f"Error collecting from {source_name}: {e}")
            return {
                'source': source_name,
                'error': str(e),
                'collected': 0
            }
    
    async def collect_all(self, limit_per_source: int = 100) -> Dict[str, Any]:
        """
        Collect threats from all enabled sources
        
        Args:
            limit_per_source: Maximum number of threats per source
            
        Returns:
            Combined collection statistics
        """
        start_time = datetime.utcnow()
        logger.info("Starting collection from all sources")
        
        # Collect from all sources concurrently
        tasks = [
            self.collect_from_source(source, limit_per_source) 
            for source in self.collectors.keys()
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Aggregate statistics
        total_stats = {
            'start_time': start_time.isoformat(),
            'end_time': datetime.utcnow().isoformat(),
            'duration_seconds': (datetime.utcnow() - start_time).total_seconds(),
            'sources': {},
            'total_collected': 0,
            'total_errors': 0
        }
        
        for result in results:
            if isinstance(result, dict):
                source = result.get('source', 'unknown')
                total_stats['sources'][source] = result
                total_stats['total_collected'] += result.get('collected', 0)
                total_stats['total_errors'] += result.get('errors', 0)
            else:
                logger.error(f"Collection task failed: {result}")
                total_stats['total_errors'] += 1
        
        logger.info(f"Collection complete: {total_stats['total_collected']} total threats collected")
        return total_stats
    
    def get_available_collectors(self) -> List[str]:
        """Get list of available collector names"""
        return list(self.collectors.keys())
    
    def get_collector_status(self) -> Dict[str, Any]:
        """Get status of all collectors"""
        status = {}
        for name, collector in self.collectors.items():
            status[name] = {
                'available': True,
                'source_name': collector.source_name,
                'class': collector.__class__.__name__
            }
        return status


async def run_collection(config_path: str = "config/config.json", limit: int = 100):
    """
    Standalone collection runner
    
    Args:
        config_path: Path to configuration file
        limit: Maximum threats per source
    """
    from src.storage.database import get_db
    
    # Load configuration
    with open(config_path, 'r') as f:
        config = json.load(f)
    
    # Get database session
    db_session = next(get_db())
    
    try:
        # Initialize manager and run collection
        manager = CollectorManager(config, db_session)
        stats = await manager.collect_all(limit)
        
        # Print results
        print("\n" + "="*50)
        print("THREAT INTELLIGENCE COLLECTION COMPLETE")
        print("="*50)
        print(f"Total threats collected: {stats['total_collected']}")
        print(f"Duration: {stats['duration_seconds']:.2f} seconds")
        print(f"Errors: {stats['total_errors']}")
        print("\nPer-source statistics:")
        for source, source_stats in stats['sources'].items():
            print(f"  {source}: {source_stats.get('collected', 0)} threats")
        print("="*50 + "\n")
        
        return stats
        
    finally:
        db_session.close()


if __name__ == "__main__":
    # Run collection when script is executed directly
    asyncio.run(run_collection())
