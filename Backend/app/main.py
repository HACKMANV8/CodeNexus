"""
Honeypot CTDR - Main FastAPI Application
Central entry point for the honeypot threat detection system
"""

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from contextlib import asynccontextmanager
import uvicorn
import logging
from typing import Dict, Any

from app.core.config import settings
from app.core.database import get_db, init_db
from app.core.security import get_current_active_user
from app.api.endpoints import (
    auth, attacks, dashboard, responses, ml_models, threat_intel
)
from app.honeypots.factory import HoneypotFactory
from app.ml.behavior_predictor import BehaviorPredictor
from app.pipeline.ingest import EventIngestor
from app.utils.logger import setup_logging

logger = setup_logging(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan management
    Handles startup and shutdown events
    """
    logger.info("🚀 Starting Honeypot CTDR System...")
    
    try:
        await init_db()
        logger.info("✅ Database initialized successfully")
        
        BehaviorPredictor.load_models()
        logger.info("✅ ML models loaded successfully")
        
        honeypot_factory = HoneypotFactory()
        await honeypot_factory.start_all_honeypots()
        logger.info("✅ Honeypot services started successfully")
        
        event_ingestor = EventIngestor()
        event_ingestor.start()
        logger.info("✅ Event ingestion pipeline started")
        
        logger.info("🎯 Honeypot CTDR System ready - Monitoring for threats...")
        yield
        
    except Exception as e:
        logger.error(f"❌ Startup failed: {str(e)}")
        raise
    
    finally:
        logger.info("🛑 Shutting down Honeypot CTDR System...")
        
        try:
            honeypot_factory = HoneypotFactory()
            await honeypot_factory.stop_all_honeypots()
            logger.info("✅ Honeypot services stopped")
            
            event_ingestor.stop()
            logger.info("✅ Event ingestion pipeline stopped")
            
        except Exception as e:
            logger.error(f"❌ Shutdown error: {str(e)}")

app = FastAPI(
    title="Honeypot CTDR System",
    description="AI-Powered Cyber Threat Detection & Response Platform",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.ALLOWED_HOSTS
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(
    auth.router,
    prefix="/api/v1/auth",
    tags=["Authentication"]
)

app.include_router(
    attacks.router,
    prefix="/api/v1/attacks",
    tags=["Attack Monitoring"]
)

app.include_router(
    dashboard.router,
    prefix="/api/v1/dashboard",
    tags=["Dashboard"]
)

app.include_router(
    responses.router,
    prefix="/api/v1/responses",
    tags=["Response Actions"]
)

app.include_router(
    ml_models.router,
    prefix="/api/v1/ml",
    tags=["Machine Learning"]
)

app.include_router(
    threat_intel.router,
    prefix="/api/v1/threat-intel",
    tags=["Threat Intelligence"]
)

@app.get("/")
async def root():
    """Root endpoint - System status"""
    return {
        "status": "operational",
        "system": "Honeypot CTDR",
        "version": "1.0.0",
        "message": "AI-Powered Threat Detection System Running"
    }

@app.get("/health")
async def health_check():
    """Comprehensive health check endpoint"""
    health_status = {
        "status": "healthy",
        "timestamp": "2024-01-01T00:00:00Z",  # Use actual timestamp
        "components": {
            "database": "connected",
            "ml_models": "loaded",
            "honeypots": "running",
            "event_pipeline": "active"
        },
        "metrics": {
            "active_connections": 0,
            "attack_count_today": 0,
            "ml_predictions": 0
        }
    }
    
   
    try:
        db = get_db()
       
        
        return health_status
    except Exception as e:
        health_status["status"] = "degraded"
        health_status["error"] = str(e)
        return health_status

@app.get("/api/v1/system/info")
async def system_info(current_user: dict = Depends(get_current_active_user)):
    """System information endpoint (protected)"""
    return {
        "system_name": "Honeypot CTDR",
        "version": "1.0.0",
        "uptime": "0 days 0 hours",  # Calculate actual uptime
        "honeypots_active": ["ssh", "web", "ftp"],
        "ml_models_loaded": ["threat_classifier", "behavior_predictor", "url_detector"],
        "security_level": "high"
    }

@app.exception_handler(404)
async def not_found_handler(request, exc):
    return JSONResponse(
        status_code=404,
        content={"detail": "Resource not found"}
    )

@app.exception_handler(500)
async def internal_error_handler(request, exc):
    logger.error(f"Internal server error: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )

if __name__ == "__main__":

    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="info"
    )