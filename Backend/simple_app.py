# simple_app.py - Place this in D:\backend\simple_app.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Honeypot CTDR", version="1.0.0")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {
        "status": "operational", 
        "system": "Honeypot CTDR",
        "message": "Backend is running successfully!"
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": "2024-01-01T00:00:00Z"}

@app.get("/api/test")
async def test_endpoint():
    return {"message": "API is working!", "status": "success"}

# Mock endpoints for frontend testing
@app.get("/api/v1/dashboard/overview")
async def dashboard_overview():
    return {
        "timestamp": "2024-01-01T00:00:00Z",
        "attack_metrics": {
            "last_hour": 5,
            "last_24_hours": 42,
            "last_7_days": 287,
            "unique_attackers_24h": 15,
            "high_severity_24h": 8
        },
        "system_metrics": {
            "active_honeypots": 3,
            "total_honeypots": 3,
            "ml_predictions_24h": 156,
            "ml_accuracy": 0.95
        },
        "honeypot_status": {
            "ssh": {"status": "running", "attacks": 12},
            "web": {"status": "running", "attacks": 25},
            "ftp": {"status": "running", "attacks": 5}
        }
    }

@app.get("/api/v1/attacks/live")
async def live_attacks():
    return [
        {
            "id": 1,
            "event_id": "attack_001",
            "honeypot_type": "ssh",
            "source_ip": "192.168.1.100",
            "source_port": 54321,
            "destination_port": 2222,
            "timestamp": "2024-01-01T10:30:00Z",
            "country": "US",
            "city": "New York",
            "threat_level": "high",
            "ml_confidence": 0.92,
            "is_malicious": True
        },
        {
            "id": 2,
            "event_id": "attack_002",
            "honeypot_type": "web",
            "source_ip": "10.0.0.50",
            "source_port": 12345,
            "destination_port": 8080,
            "timestamp": "2024-01-01T10:25:00Z",
            "country": "CN",
            "city": "Beijing",
            "threat_level": "critical",
            "ml_confidence": 0.98,
            "is_malicious": True
        }
    ]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")