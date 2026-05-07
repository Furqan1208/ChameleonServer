# ADDED_ML: Optional APScheduler job for periodic retraining checks.
from __future__ import annotations

import asyncio
import logging

logger = logging.getLogger(__name__)


def initialize_ml_scheduler(app) -> object | None:
    """Initialize a safe background scheduler that checks every 6 hours."""
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
    except Exception as exc:
        logger.warning("APScheduler unavailable, ML scheduler disabled: %s", exc)
        return None

    scheduler = BackgroundScheduler()

    def _job_wrapper() -> None:
        try:
            from app.ml.train_model import auto_retrain_async

            loop = asyncio.new_event_loop()
            try:
                asyncio.set_event_loop(loop)
                result = loop.run_until_complete(auto_retrain_async())
                if not result.get("success"):
                    logger.warning("Auto retrain job reported failure: %s", result.get("error"))
            finally:
                loop.close()
        except Exception as exc:
            logger.error("ML scheduler job failed: %s", exc, exc_info=True)

    scheduler.add_job(
        _job_wrapper,
        trigger="interval",
        hours=6,
        id="ml_auto_retrain_6h",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )

    try:
        scheduler.start()
        app.state.ml_scheduler = scheduler
        logger.info("ML scheduler initialized (6-hour retrain checks).")
    except Exception as exc:
        logger.warning("Could not start ML scheduler: %s", exc)
        return None

    @app.on_event("shutdown")
    def _shutdown_scheduler() -> None:
        try:
            if hasattr(app.state, "ml_scheduler") and app.state.ml_scheduler:
                app.state.ml_scheduler.shutdown(wait=False)
        except Exception as exc:
            logger.warning("ML scheduler shutdown error: %s", exc)

    return scheduler
