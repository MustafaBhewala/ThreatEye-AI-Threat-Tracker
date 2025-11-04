"""
Collectors API Router
Endpoints for managing threat intelligence collection
"""

from fastapi import APIRouter, Depends, BackgroundTasks, HTTPException
from sqlalchemy.orm import Session
from typing import Dict, Any, Optional
import json
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

from src.storage.database import get_db
from src.collectors.manager import CollectorManager

router = APIRouter()

# Load config
with open('config/config.json', 'r') as f:
    CONFIG = json.load(f)


@router.get("/status")
async def get_collectors_status(db: Session = Depends(get_db)):
    """
    Get status of all available collectors
    """
    manager = CollectorManager(CONFIG, db)
    status = manager.get_collector_status()
    
    return {
        "available_collectors": manager.get_available_collectors(),
        "collectors": status,
        "total": len(status)
    }


@router.post("/collect/{source}")
async def collect_from_source(
    source: str,
    background_tasks: BackgroundTasks,
    limit: int = 50,
    db: Session = Depends(get_db)
):
    """
    Trigger collection from a specific source
    
    Args:
        source: Source name (virustotal, abuseipdb, otx)
        limit: Maximum threats to collect
    """
    manager = CollectorManager(CONFIG, db)
    
    if source not in manager.get_available_collectors():
        raise HTTPException(
            status_code=404, 
            detail=f"Collector '{source}' not available. Available: {manager.get_available_collectors()}"
        )
    
    # Run collection in background
    async def run_background_collection():
        await manager.collect_from_source(source, limit)
    
    background_tasks.add_task(run_background_collection)
    
    return {
        "message": f"Collection from {source} started in background",
        "source": source,
        "limit": limit
    }


@router.post("/collect-all")
async def collect_from_all_sources(
    background_tasks: BackgroundTasks,
    limit: int = 50,
    db: Session = Depends(get_db)
):
    """
    Trigger collection from all enabled sources
    
    Args:
        limit: Maximum threats to collect per source
    """
    manager = CollectorManager(CONFIG, db)
    
    # Run collection in background
    async def run_background_collection():
        return await manager.collect_all(limit)
    
    background_tasks.add_task(run_background_collection)
    
    return {
        "message": "Collection from all sources started in background",
        "sources": manager.get_available_collectors(),
        "limit_per_source": limit
    }


@router.get("/history")
async def get_collection_history(
    limit: int = 20,
    db: Session = Depends(get_db)
):
    """
    Get recent collection history from feed_data table
    """
    from src.storage.models import FeedData
    from sqlalchemy import func, desc
    
    # Get collection stats grouped by source
    stats = db.query(
        FeedData.source,
        func.count(FeedData.id).label('total_collected'),
        func.max(FeedData.retrieved_at).label('last_collection')
    ).group_by(FeedData.source).all()
    
    # Get recent collections
    recent = db.query(FeedData).order_by(
        desc(FeedData.retrieved_at)
    ).limit(limit).all()
    
    return {
        "statistics": [
            {
                "source": stat.source,
                "total_collected": stat.total_collected,
                "last_collection": stat.last_collection.isoformat() if stat.last_collection else None
            }
            for stat in stats
        ],
        "recent_collections": [
            {
                "id": item.id,
                "source": item.source,
                "indicator_id": item.indicator_id,
                "retrieved_at": item.retrieved_at.isoformat()
            }
            for item in recent
        ]
    }
