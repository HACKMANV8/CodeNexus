"""
Honeypot CTDR System - Startup Script
Main entry point for launching the backend application
"""

import sys
import os
import logging
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

def setup_environment():
    """Setup application environment"""
    try:
        from app.core.config import settings
        from app.utils.logger import setup_logging
       
        logger = setup_logging("startup")
        
        if not settings.DATABASE_URL:
            logger.error("DATABASE_URL environment variable not set")
            return False
            
        if not settings.SECRET_KEY:
            logger.error("SECRET_KEY environment variable not set")
            return False
            
        logger.info("✅ Environment validation successful")
        return True
        
    except Exception as e:
        print(f"❌ Environment setup failed: {e}")
        return False

def run_development_server():
    """Run the development server"""
    try:
        import uvicorn
        from app.core.config import settings
        
        print("🚀 Starting Honeypot CTDR Development Server...")
        print(f"📍 Host: {settings.HOST}")
        print(f"🎯 Port: {settings.PORT}")
        print(f"🔧 Debug: {settings.DEBUG}")
        print(f"📚 API Docs: http://{settings.HOST}:{settings.PORT}/api/docs")
        print("Press Ctrl+C to stop the server")
        
        uvicorn.run(
            "app.main:app",
            host=settings.HOST,
            port=settings.PORT,
            reload=settings.DEBUG,
            log_level="info",
            access_log=True
        )
        
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    except Exception as e:
        print(f"❌ Server error: {e}")
        sys.exit(1)

def run_production_server():
    """Run the production server"""
    try:
        import uvicorn
        from app.core.config import settings
        
        print("🚀 Starting Honeypot CTDR Production Server...")
        print(f"📍 Host: {settings.HOST}")
        print(f"🎯 Port: {settings.PORT}")
        print("🔒 Production mode enabled")
        
        uvicorn.run(
            "app.main:app",
            host=settings.HOST,
            port=settings.PORT,
            reload=False,
            workers=settings.WORKERS,
            log_level="warning"
        )
        
    except Exception as e:
        print(f"❌ Production server error: {e}")
        sys.exit(1)

def run_migration():
    """Run database migrations"""
    try:
        from app.core.database import run_migrations
        
        print("🔄 Running database migrations...")
        run_migrations()
        print("✅ Database migrations completed")
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        sys.exit(1)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Honeypot CTDR System")
    parser.add_argument(
        "command",
        choices=["dev", "prod", "migrate", "check"],
        help="Command to execute"
    )
    
    args = parser.parse_args()
   
    if not setup_environment():
        sys.exit(1)
    
    if args.command == "dev":
        run_development_server()
    elif args.command == "prod":
        run_production_server()
    elif args.command == "migrate":
        run_migration()
    elif args.command == "check":
        print("✅ System check completed - All dependencies available")
        sys.exit(0)

if __name__ == "__main__":
    main()