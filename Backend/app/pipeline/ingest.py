"""
Event Ingestion Pipeline
Collects and processes raw attack events from honeypots
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from concurrent.futures import ThreadPoolExecutor

from app.core.database import get_db
from app.models.database_models import AttackEvent
from app.models.schemas import AttackEventCreate
from app.core.config import settings

logger = logging.getLogger(__name__)

class EventIngestor:
    def __init__(self):
        self.is_running = False
        self.thread_pool = ThreadPoolExecutor(max_workers=10)
        self.event_queue = asyncio.Queue()
        self.processed_count = 0

    async def start(self):
        self.is_running = True
        logger.info("Event ingestion pipeline started")
        
        process_task = asyncio.create_task(self._process_events())
        await process_task

    async def stop(self):
        self.is_running = False
        self.thread_pool.shutdown(wait=True)
        logger.info("Event ingestion pipeline stopped")

    async def ingest_event(self, event_data: Dict[str, Any]):
        await self.event_queue.put(event_data)

    async def _process_events(self):
        while self.is_running:
            try:
                event_data = await self.event_queue.get()
                await self._handle_single_event(event_data)
                self.event_queue.task_done()
            except Exception as e:
                logger.error(f"Error processing event: {e}")

    async def _handle_single_event(self, event_data: Dict[str, Any]):
        try:
            event_id = self._generate_event_id()
            event_data["event_id"] = event_id
            event_data["timestamp"] = datetime.utcnow()

            validated_event = AttackEventCreate(**event_data)
            
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                self.thread_pool, 
                self._store_event, 
                validated_event.dict()
            )
            
            self.processed_count += 1
            logger.debug(f"Event ingested: {event_id}")

        except Exception as e:
            logger.error(f"Failed to ingest event: {e}")

    def _store_event(self, event_dict: Dict[str, Any]):
        try:
            from app.core.database import SessionLocal
            db = SessionLocal()
            
            attack_event = AttackEvent(**event_dict)
            db.add(attack_event)
            db.commit()
            
            logger.info(f"Stored attack event from {event_dict.get('source_ip')}")
            
        except Exception as e:
            logger.error(f"Failed to store event in database: {e}")
        finally:
            db.close()

    def _generate_event_id(self) -> str:
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        return f"event_{timestamp}_{self.processed_count}"

    def get_stats(self) -> Dict[str, Any]:
        return {
            "is_running": self.is_running,
            "queue_size": self.event_queue.qsize(),
            "processed_count": self.processed_count,
            "thread_pool_workers": self.thread_pool._max_workers
        }

async def start_ingestion_pipeline():
    ingestor = EventIngestor()
    await ingestor.start()
    return ingestor

async def ingest_attack_event(event_type: str, source_ip: str, payload: Dict[str, Any]):
    event_data = {
        "honeypot_type": event_type,
        "source_ip": source_ip,
        "payload": json.dumps(payload) if payload else None,
        "raw_data": payload
    }
    
    ingestor = EventIngestor()
    await ingestor.ingest_event(event_data)