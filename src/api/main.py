"""
FastAPI Main Application
Entry point for ThreatEye REST API
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.storage.database import db_manager, init_database


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifecycle manager for FastAPI app
    Handles startup and shutdown events
    """
    # Startup
    print("🚀 Starting ThreatEye API...")
    
    # Initialize database
    init_database()
    
    # Check database health
    if db_manager.health_check():
        print("✅ Database connected successfully")
    else:
        print("❌ Database connection failed")
    
    yield
    
    # Shutdown
    print("🛑 Shutting down ThreatEye API...")


# Create FastAPI app
app = FastAPI(
    title="ThreatEye API",
    description="AI-Powered Threat Intelligence Platform - REST API for managing threat indicators, alerts, and reports",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)


# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174", 
        "http://localhost:5175",
        "http://localhost:3000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint - API health check"""
    return {
        "message": "🛡️ ThreatEye API",
        "version": "1.0.0",
        "status": "operational",
        "docs": "/docs"
    }


# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    db_healthy = db_manager.health_check()
    
    return {
        "status": "healthy" if db_healthy else "unhealthy",
        "database": "connected" if db_healthy else "disconnected",
        "api": "operational"
    }


# Import and include routers
from src.api.routes import indicators, dashboard, collectors, scan, history
app.include_router(indicators.router, prefix="/api/indicators", tags=["Indicators"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])
app.include_router(collectors.router, prefix="/api/collectors", tags=["Collectors"])
app.include_router(scan.router, prefix="/api/scan", tags=["Scan"])
app.include_router(history.router, prefix="/api/history", tags=["History"])

# More routers to be added:
# from src.api.routes import alerts, reports
# app.include_router(alerts.router, prefix="/api/alerts", tags=["Alerts"])
# app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
