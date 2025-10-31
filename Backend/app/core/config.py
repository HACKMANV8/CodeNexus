from pydantic import BaseSettings
from typing import List
from pathlib import Path

class Settings(BaseSettings):
    # Database Settings - Matching your database.py structure
    database_hostname: str = "localhost"
    database_port: str = "5432"
    database_password: str = "password"  # Change this!
    database_name: str = "honeypot_ctdr"
    database_username: str = "postgres"
    
    # Database connection pool settings
    database_pool_size: int = 20
    database_max_overflow: int = 30
    database_pool_recycle: int = 3600
    database_echo: bool = False
    
    # JWT Settings
    secret_key: str = "your-secret-key-change-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    
    # Honeypot Settings
    ssh_honeypot_port: int = 2222
    web_honeypot_port: int = 8080
    ftp_honeypot_port: int = 2121
    
    # API Settings
    api_v1_str: str = "/api/v1"
    cors_origins: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
    ]
    
    # Application Settings
    app_name: str = "Honeypot CTDR"
    debug: bool = True
    host: str = "0.0.0.0"
    port: int = 8000
    
    # Paths
    base_dir: Path = Path(__file__).parent.parent.parent
    logs_dir: Path = base_dir / "logs"
    data_dir: Path = base_dir / "data"

    class Config:
        env_file = ".env"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Create necessary directories
        self.logs_dir.mkdir(exist_ok=True)
        self.data_dir.mkdir(exist_ok=True)

settings = Settings()