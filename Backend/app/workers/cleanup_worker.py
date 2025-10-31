"""
Cleanup Background Worker
Database maintenance and data cleanup tasks
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import os

from app.core.database import get_db
from app.models.database_models import AttackEvent, MLPrediction, ResponseAction
from app.core.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)

class CleanupWorker:
    def __init__(self):
        self.is_running = False
        self.cleanup_interval = 3600
        self.retention_periods = {
            'attack_events': timedelta(days=30),
            'ml_predictions': timedelta(days=90),
            'response_actions': timedelta(days=60),
            'audit_logs': timedelta(days=180)
        }
        self.max_batch_size = 1000

    async def start(self):
        if self.is_running:
            logger.warning("Cleanup worker already running")
            return

        self.is_running = True
        logger.info("Starting cleanup background worker")

        try:
            while self.is_running:
                start_time = datetime.utcnow()
                
                try:
                    await self._run_cleanup_tasks()
                    await self._cleanup_temp_files()
                    await self._optimize_database()
                except Exception as e:
                    logger.error(f"Cleanup worker processing error: {e}")

                processing_time = (datetime.utcnow() - start_time).total_seconds()
                sleep_time = max(300, self.cleanup_interval - processing_time)
                
                await asyncio.sleep(sleep_time)

        except asyncio.CancelledError:
            logger.info("Cleanup worker stopped")
        except Exception as e:
            logger.error(f"Cleanup worker crashed: {e}")
        finally:
            self.is_running = False

    async def stop(self):
        self.is_running = False
        logger.info("Stopping cleanup worker")

    async def _run_cleanup_tasks(self):
        try:
            logger.info("Starting cleanup tasks")
            
            tasks = [
                self._cleanup_old_attack_events(),
                self._cleanup_old_ml_predictions(),
                self._cleanup_old_response_actions(),
                self._cleanup_expired_cache(),
                self._update_database_statistics()
            ]
            
            for task in tasks:
                try:
                    await task
                except Exception as e:
                    logger.error(f"Cleanup task failed: {e}")

            logger.info("Cleanup tasks completed")

        except Exception as e:
            logger.error(f"Cleanup tasks execution failed: {e}")

    async def _cleanup_old_attack_events(self):
        try:
            from app.core.database import SessionLocal
            db = SessionLocal()

            cutoff_date = datetime.utcnow() - self.retention_periods['attack_events']
            
            old_events_count = db.query(AttackEvent).filter(
                AttackEvent.timestamp < cutoff_date
            ).count()

            if old_events_count > 0:
                logger.info(f"Cleaning up {old_events_count} old attack events")
                
                deleted_count = 0
                while deleted_count < old_events_count:
                    batch = db.query(AttackEvent).filter(
                        AttackEvent.timestamp < cutoff_date
                    ).limit(self.max_batch_size).all()
                    
                    if not batch:
                        break
                    
                    for event in batch:
                        db.delete(event)
                    
                    db.commit()
                    deleted_count += len(batch)
                    logger.info(f"Deleted {len(batch)} attack events")
                    
                    if len(batch) < self.max_batch_size:
                        break

                logger.info(f"Completed cleanup of {deleted_count} attack events")

            db.close()

        except Exception as e:
            logger.error(f"Attack events cleanup failed: {e}")

    async def _cleanup_old_ml_predictions(self):
        try:
            from app.core.database import SessionLocal
            db = SessionLocal()

            cutoff_date = datetime.utcnow() - self.retention_periods['ml_predictions']
            
            old_predictions_count = db.query(MLPrediction).filter(
                MLPrediction.timestamp < cutoff_date
            ).count()

            if old_predictions_count > 0:
                logger.info(f"Cleaning up {old_predictions_count} old ML predictions")
                
                deleted_count = db.query(MLPrediction).filter(
                    MLPrediction.timestamp < cutoff_date
                ).delete(synchronize_session=False)
                
                db.commit()
                logger.info(f"Deleted {deleted_count} ML predictions")

            db.close()

        except Exception as e:
            logger.error(f"ML predictions cleanup failed: {e}")

    async def _cleanup_old_response_actions(self):
        try:
            from app.core.database import SessionLocal
            db = SessionLocal()

            cutoff_date = datetime.utcnow() - self.retention_periods['response_actions']
            
            old_actions_count = db.query(ResponseAction).filter(
                ResponseAction.created_at < cutoff_date
            ).count()

            if old_actions_count > 0:
                logger.info(f"Cleaning up {old_actions_count} old response actions")
                
                deleted_count = db.query(ResponseAction).filter(
                    ResponseAction.created_at < cutoff_date
                ).delete(synchronize_session=False)
                
                db.commit()
                logger.info(f"Deleted {deleted_count} response actions")

            db.close()

        except Exception as e:
            logger.error(f"Response actions cleanup failed: {e}")

    async def _cleanup_expired_cache(self):
        try:
            from app.core.cache import cache_manager
            
            cache_stats = cache_manager.get_stats()
            logger.info(f"Cache stats: {cache_stats}")
            
        except Exception as e:
            logger.error(f"Cache cleanup failed: {e}")

    async def _cleanup_temp_files(self):
        try:
            temp_dirs = [
                settings.DATA_DIR / "temp_storage",
                settings.LOGS_DIR
            ]
            
            for temp_dir in temp_dirs:
                if temp_dir.exists():
                    await self._cleanup_directory(temp_dir, days=7)

        except Exception as e:
            logger.error(f"Temp files cleanup failed: {e}")

    async def _cleanup_directory(self, directory: str, days: int):
        try:
            cutoff_time = datetime.now().timestamp() - (days * 86400)
            deleted_files = 0
            
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        if os.path.getmtime(file_path) < cutoff_time:
                            os.remove(file_path)
                            deleted_files += 1
                    except (OSError, PermissionError) as e:
                        logger.warning(f"Could not delete file {file_path}: {e}")
            
            if deleted_files > 0:
                logger.info(f"Cleaned up {deleted_files} old files from {directory}")

        except Exception as e:
            logger.error(f"Directory cleanup failed for {directory}: {e}")

    async def _optimize_database(self):
        try:
            from app.core.database import SessionLocal
            db = SessionLocal()

            tables = ['attack_events', 'ml_predictions', 'response_actions', 'attacker_profiles']
            
            for table in tables:
                try:
                    db.execute(f"ANALYZE {table};")
                    logger.debug(f"Analyzed table: {table}")
                except Exception as e:
                    logger.warning(f"Could not analyze table {table}: {e}")

            db.close()

        except Exception as e:
            logger.error(f"Database optimization failed: {e}")

    async def _update_database_statistics(self):
        try:
            from app.core.database import SessionLocal
            db = SessionLocal()

            stats = {}
            
            stats['total_attack_events'] = db.query(AttackEvent).count()
            stats['today_attack_events'] = db.query(AttackEvent).filter(
                AttackEvent.timestamp >= datetime.utcnow().date()
            ).count()
            
            stats['total_ml_predictions'] = db.query(MLPrediction).count()
            stats['malicious_attacks'] = db.query(AttackEvent).filter(
                AttackEvent.is_malicious == True
            ).count()
            
            stats['active_response_actions'] = db.query(ResponseAction).filter(
                ResponseAction.status.in_(['executed', 'pending_approval'])
            ).count()

            logger.info(f"Database statistics: {stats}")

            db.close()

        except Exception as e:
            logger.error(f"Database statistics update failed: {e}")

    async def run_immediate_cleanup(self, task_type: str = "all") -> Dict[str, Any]:
        results = {}
        
        try:
            if task_type in ["all", "attack_events"]:
                await self._cleanup_old_attack_events()
                results['attack_events'] = 'completed'
            
            if task_type in ["all", "ml_predictions"]:
                await self._cleanup_old_ml_predictions()
                results['ml_predictions'] = 'completed'
            
            if task_type in ["all", "response_actions"]:
                await self._cleanup_old_response_actions()
                results['response_actions'] = 'completed'
            
            if task_type in ["all", "temp_files"]:
                await self._cleanup_temp_files()
                results['temp_files'] = 'completed'
            
            logger.info(f"Immediate cleanup completed for: {task_type}")
            
        except Exception as e:
            logger.error(f"Immediate cleanup failed: {e}")
            results['error'] = str(e)
        
        return results

    def get_worker_status(self) -> Dict[str, Any]:
        return {
            'is_running': self.is_running,
            'cleanup_interval': self.cleanup_interval,
            'retention_periods': {k: str(v) for k, v in self.retention_periods.items()},
            'max_batch_size': self.max_batch_size,
            'last_activity': datetime.utcnow().isoformat()
        }

cleanup_worker = CleanupWorker()

async def start_cleanup_worker():
    worker = CleanupWorker()
    await worker.start()
    return worker

async def run_cleanup_tasks(task_type: str = "all") -> Dict[str, Any]:
    worker = CleanupWorker()
    return await worker.run_immediate_cleanup(task_type)