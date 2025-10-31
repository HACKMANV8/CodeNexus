import psycopg2
from app.core.config import settings
from app.core.database import init_db

def create_database():
    """Create database if it doesn't exist"""
    try:
        # Connect to PostgreSQL default database
        conn = psycopg2.connect(
            host=settings.database_hostname,
            port=settings.database_port,
            user=settings.database_username,
            password=settings.database_password,
            database="postgres"  # Connect to default postgres database
        )
        conn.autocommit = True
        cursor = conn.cursor()
        
        # Check if database exists
        cursor.execute(f"SELECT 1 FROM pg_catalog.pg_database WHERE datname = '{settings.database_name}'")
        exists = cursor.fetchone()
        
        if not exists:
            cursor.execute(f"CREATE DATABASE {settings.database_name}")
            print(f"Database '{settings.database_name}' created successfully")
        else:
            print(f"Database '{settings.database_name}' already exists")
            
        cursor.close()
        conn.close()
        
    except Exception as e:
        print(f"Error creating database: {e}")
        # Fallback to SQLite for development
        print("Falling back to SQLite for development...")

if __name__ == "__main__":
    create_database()
    init_db()
    print("Database setup completed!")