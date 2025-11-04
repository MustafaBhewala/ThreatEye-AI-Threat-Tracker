"""
Threat Intelligence Collection Script
Run this to collect threats from all configured sources
"""

import asyncio
import sys
import argparse
import logging
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from src.collectors.manager import run_collection

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('data/collection.log')
    ]
)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Collect threat intelligence from configured sources'
    )
    parser.add_argument(
        '--limit',
        type=int,
        default=50,
        help='Maximum number of threats to collect per source (default: 50)'
    )
    parser.add_argument(
        '--config',
        type=str,
        default='config/config.json',
        help='Path to configuration file (default: config/config.json)'
    )
    
    args = parser.parse_args()
    
    print("\n🔍 ThreatEye - Threat Intelligence Collection")
    print("=" * 60)
    print(f"Configuration: {args.config}")
    print(f"Limit per source: {args.limit}")
    print("=" * 60 + "\n")
    
    try:
        # Run collection
        stats = asyncio.run(run_collection(args.config, args.limit))
        
        # Exit with success
        sys.exit(0)
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Collection interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Collection failed: {e}")
        logging.error(f"Collection failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
