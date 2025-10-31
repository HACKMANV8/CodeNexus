import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

from app.main import app
from app.core.database import get_db
from app.honeypots.ssh_honeypot import SSHHoneypot
from app.honeypots.web_honeypot import WebHoneypot
from app.models.schemas import AttackEvent

client = TestClient(app)

@pytest.fixture
def mock_db():
    return MagicMock()

def test_ssh_honeypot_initialization():
    honeypot = SSHHoneypot(port=2222)
    assert honeypot.port == 2222
    assert honeypot.service_name == "ssh"
    assert honeypot.is_running == False

def test_web_honeypot_initialization():
    honeypot = WebHoneypot(port=8080)
    assert honeypot.port == 8080
    assert honeypot.service_name == "web"
    assert honeypot.is_running == False

@patch('app.honeypots.ssh_honeypot.socket')
def test_ssh_honeypot_start_stop(mock_socket):
    honeypot = SSHHoneypot(port=2222)
    
    mock_socket.socket.return_value.bind.return_value = None
    mock_socket.socket.return_value.listen.return_value = None
    
    result = honeypot.start()
    assert result == True
    assert honeypot.is_running == True
    
    honeypot.stop()
    assert honeypot.is_running == False

def test_attack_event_creation():
    attack_event = AttackEvent(
        source_ip="192.168.1.100",
        service_type="ssh",
        attack_type="brute_force",
        payload="ssh connection attempt",
        timestamp="2024-01-01T12:00:00Z"
    )
    
    assert attack_event.source_ip == "192.168.1.100"
    assert attack_event.service_type == "ssh"
    assert attack_event.attack_type == "brute_force"

def test_honeypot_factory():
    from app.honeypots.factory import HoneypotFactory
    
    ssh_honeypot = HoneypotFactory.create_honeypot("ssh", 2222)
    assert ssh_honeypot.service_name == "ssh"
    
    web_honeypot = HoneypotFactory.create_honeypot("web", 8080)
    assert web_honeypot.service_name == "web"

def test_honeypot_endpoints(mock_db):
    app.dependency_overrides[get_db] = lambda: mock_db
    
    response = client.get("/api/v1/honeypots/status")
    assert response.status_code == 200
    
    response = client.post("/api/v1/honeypots/start/ssh")
    assert response.status_code in [200, 400]