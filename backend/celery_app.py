"""
celery_app.py — Celery application configuration and task definitions for Kavach AI.
Allows offloading heavy static scans and dynamic sandbox tracing to queue workers.
"""

import os
import logging
from celery import Celery

logger = logging.getLogger("kavach_celery")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
celery_app = Celery("kavach_tasks", broker=REDIS_URL, backend=REDIS_URL)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    broker_connection_retry_on_startup=True
)

@celery_app.task(name="kavach_tasks.run_static_analysis")
def run_static_analysis(doc_id: str, request_data: dict, release_semaphore: bool = False):
    logger.info(f"Celery worker received static analysis task for doc {doc_id}")
    try:
        from main import run_analysis_pipeline, AnalysisRequest
        req = AnalysisRequest(**request_data)
        run_analysis_pipeline(doc_id, req, release_semaphore)
        logger.info(f"Celery static analysis task finished for doc {doc_id}")
    except Exception as e:
        logger.exception(f"Celery static analysis task failed for doc {doc_id}: {e}")
        raise

@celery_app.task(name="kavach_tasks.run_dynamic_analysis")
def run_dynamic_analysis(doc_id: str, apk_url: str, uid: str):
    logger.info(f"Celery worker received dynamic analysis task for doc {doc_id}")
    try:
        from routes import run_dynamic_analysis_pipeline
        run_dynamic_analysis_pipeline(doc_id, apk_url, uid)
        logger.info(f"Celery dynamic analysis task finished for doc {doc_id}")
    except Exception as e:
        logger.exception(f"Celery dynamic analysis task failed for doc {doc_id}: {e}")
        raise
