import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime

from app.pipeline.ingest import EventIngestor
from app.pipeline.enrich import DataEnricher
from app.pipeline.classify import ThreatClassifier
from app.pipeline.responder import ResponseEngine
from app.models.schemas import AttackEvent, EnrichedEvent

class TestEventIngestor:
    def test_event_ingestor_initialization(self):
        ingestor = EventIngestor()
        assert ingestor.batch_size == 100
        assert ingestor.batch_timeout == 30

    def test_event_validation(self):
        ingestor = EventIngestor()
        
        valid_event = {
            "source_ip": "192.168.1.100",
            "service_type": "ssh",
            "timestamp": "2024-01-01T12:00:00Z"
        }
        
        invalid_event = {
            "source_ip": "invalid_ip",
            "service_type": "unknown_service"
        }
        
        assert ingestor._validate_event(valid_event) == True
        assert ingestor._validate_event(invalid_event) == False

    def test_batch_processing(self):
        ingestor = EventIngestor()
        events = [{"source_ip": f"192.168.1.{i}", "service_type": "ssh"} for i in range(50)]
        
        processed = ingestor.process_batch(events)
        assert len(processed) == 50

class TestDataEnricher:
    def test_data_enricher_initialization(self):
        enricher = DataEnricher()
        assert enricher.geoip_db_path is not None

    @patch('app.pipeline.enrich.GeoIP2.database.Reader')
    def test_geoip_enrichment(self, mock_geoip):
        enricher = DataEnricher()
        enricher.geoip_reader = mock_geoip
        
        mock_city = MagicMock()
        mock_city.country.iso_code = "US"
        mock_city.city.name = "New York"
        mock_city.location.latitude = 40.7128
        mock_city.location.longitude = -74.0060
        mock_geoip.city.return_value = mock_city
        
        event = AttackEvent(source_ip="8.8.8.8", service_type="web")
        enriched = enricher.add_geoip_data(event)
        
        assert enriched.country_code == "US"
        assert enriched.city == "New York"
        assert enriched.latitude == 40.7128

    @patch('app.services.whois_client.whois')
    def test_whois_enrichment(self, mock_whois):
        enricher = DataEnricher()
        
        mock_whois_data = MagicMock()
        mock_whois_data.creation_date = "2020-01-01"
        mock_whois.return_value = mock_whois_data
        
        event = AttackEvent(source_ip="8.8.8.8", service_type="web")
        enriched = enricher.add_whois_data(event)
        
        assert "domain_age" in enriched.additional_data

class TestThreatClassifier:
    def test_threat_classifier_initialization(self):
        classifier = ThreatClassifier()
        assert classifier.ml_models == {}

    @patch('app.ml.url_detector.URLDetector')
    def test_malicious_url_detection(self, mock_detector):
        classifier = ThreatClassifier()
        classifier.ml_models["url_detector"] = mock_detector
        
        mock_detector.predict.return_value = {
            "is_malicious": True,
            "confidence": 0.95,
            "features": {"length": 50, "entropy": 4.5}
        }
        
        event = EnrichedEvent(
            source_ip="192.168.1.100",
            service_type="web",
            requested_url="http://phishing-site.com"
        )
        
        result = classifier.classify_threat(event)
        assert result.threat_level == "high"
        assert result.confidence_score == 0.95

class TestResponseEngine:
    def test_response_engine_initialization(self):
        engine = ResponseEngine()
        assert engine.response_actions == {}

    def test_action_prioritization(self):
        engine = ResponseEngine()
        
        events = [
            {"threat_level": "low", "confidence": 0.6},
            {"threat_level": "high", "confidence": 0.9},
            {"threat_level": "medium", "confidence": 0.7}
        ]
        
        prioritized = engine._prioritize_actions(events)
        assert prioritized[0]["threat_level"] == "high"

    @patch('app.services.rate_limiter.RateLimiter')
    def test_rate_limit_action(self, mock_limiter):
        engine = ResponseEngine()
        engine.rate_limiter = mock_limiter
        
        mock_limiter.block_ip.return_value = True
        
        result = engine.execute_action("rate_limit", {"ip": "192.168.1.100", "duration": 3600})
        assert result["success"] == True
        assert result["action"] == "rate_limit"