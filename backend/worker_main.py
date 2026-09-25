import time
import signal
import sys
from app.kafka.worker import run_worker_in_background
from app.ingestion.ingestion_manager import IngestionManager
from app.monitoring.logger import get_logger

logger = get_logger("ulpf.worker.main")

def main():
    logger.info("Initializing worker manager")
    manager = IngestionManager()
    worker = run_worker_in_background(manager.process_log)

    def signal_handler(sig, frame):
        logger.info("Gracefully shutting down worker")
        worker.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    logger.info("Worker is running in background. Press Ctrl+C to stop.")
    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
