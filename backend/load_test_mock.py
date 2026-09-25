import time
from app.ingestion.ingestion_manager import IngestionManager

def run_load_test():
    manager = IngestionManager("sqlite:///:memory:")
    # Initialize state
    manager.process_log("init")

    log = "Sep 24 10:00:00 host1 sshd[123]: Accepted password for user from 10.0.0.1 port 50000 ssh2"

    for count in [1000, 10000]:
        start = time.time()
        for _ in range(count):
            manager.process_log(log)
        elapsed = time.time() - start

        print(f"Count: {count} logs")
        print(f"Elapsed: {elapsed:.2f} seconds")
        print(f"Rate: {count/elapsed:.2f} events/sec")
        print(f"Latency: {(elapsed/count)*1000:.2f} ms/event\n")

if __name__ == "__main__":
    run_load_test()
