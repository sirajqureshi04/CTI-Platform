"""
Scheduler for automated CTI feed execution.
Aligned with Core settings and FeedManager orchestration.
"""

import time
import signal
from datetime import datetime, timedelta
from threading import Thread, Event
from typing import Any, Callable, Dict, Optional

from backend.core.logger import CTILogger
from backend.core.config import settings

logger = CTILogger.get_logger(__name__)

class Scheduler:
    """
    Periodic task scheduler for the CTI Pipeline.
    
    Uses threading for concurrent execution and an Event-based 
    stop mechanism for graceful shutdowns.
    """
    
    def __init__(self):
        self._tasks: Dict[str, Dict[str, Any]] = {}
        self._shutdown_event = Event()
        self._thread: Optional[Thread] = None
        
        logger.info("CTI Scheduler initialized")

    def schedule_task(
        self,
        task_id: str,
        task_func: Callable,
        interval_minutes: Optional[int] = None,
        enabled: bool = True
    ) -> None:
        """
        Schedules a task using intervals from config or manual override.
        """
        # Default to config setting if not specified
        interval = interval_minutes or settings.SCRAPE_INTERVAL_MINUTES
        interval_seconds = interval * 60

        self._tasks[task_id] = {
            "task_id": task_id,
            "task_func": task_func,
            "interval_seconds": interval_seconds,
            "enabled": enabled,
            "last_run": None,
            "next_run": datetime.now(),  # Run immediately on first start
            "run_count": 0,
            "is_running": False
        }
        
        logger.info(f"Task '{task_id}' scheduled every {interval} minutes.")

    def _execute_wrapper(self, task_id: str):
        """Wrapper to track task state and prevent overlapping runs."""
        task = self._tasks[task_id]
        if task["is_running"]:
            logger.warning(f"Task {task_id} is still running from previous cycle. Skipping.")
            return

        task["is_running"] = True
        try:
            logger.info(f"Starting scheduled run: {task_id}")
            task["task_func"]()
            task["last_run"] = datetime.now()
            task["run_count"] += 1
        except Exception as e:
            logger.error(f"Critical failure in task {task_id}: {e}", exc_info=True)
        finally:
            task["is_running"] = False
            task["next_run"] = datetime.now() + timedelta(seconds=task["interval_seconds"])

    def _run_loop(self) -> None:
        """Main execution loop with Event-based interruption."""
        while not self._shutdown_event.is_set():
            now = datetime.now()
            
            for task_id, task_info in self._tasks.items():
                if not task_info["enabled"]:
                    continue
                
                if now >= task_info["next_run"] and not task_info["is_running"]:
                    # Run task in a separate thread to prevent blocking the scheduler
                    Thread(target=self._execute_wrapper, args=(task_id,), daemon=True).start()
            
            # Check every 10 seconds (more responsive than 60s)
            self._shutdown_event.wait(timeout=10)

    def start(self) -> None:
        """Start the scheduler thread."""
        if self._thread and self._thread.is_alive():
            return
        
        self._shutdown_event.clear()
        self._thread = Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        logger.info("CTI Scheduler daemon started.")

    def stop(self) -> None:
        """Gracefully stop the scheduler."""
        logger.info("Stopping scheduler...")
        self._shutdown_event.set()
        if self._thread:
            self._thread.join(timeout=15)
        logger.info("Scheduler stopped.")

    def get_status(self) -> Dict[str, Any]:
        """Returns health status of all scheduled tasks."""
        return {
            tid: {
                "next_run": info["next_run"].strftime("%Y-%m-%d %H:%M:%S"),
                "run_count": info["run_count"],
                "active": info["is_running"]
            }
            for tid, info in self._tasks.items()
        }