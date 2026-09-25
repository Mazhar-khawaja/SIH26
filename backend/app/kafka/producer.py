import json
import uuid
import time
from typing import List, Dict, Any
from kafka import KafkaProducer
from app.config.settings import settings
from app.monitoring.logger import get_logger

logger = get_logger("ulpf.kafka.producer")

class ULPFProducer:
    def __init__(self, bootstrap_servers: str = None):
        self.bootstrap_servers = bootstrap_servers or settings.kafka_bootstrap_servers
        self.topic = settings.kafka_topic
        try:
            self.producer = KafkaProducer(
                bootstrap_servers=self.bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                key_serializer=lambda v: v.encode('utf-8') if v else None,
                retries=3
            )
            self.connected = True
        except Exception as e:
            logger.error("Failed to connect to Kafka producer", error=e)
            self.connected = False

    def send_bulk(self, logs: List[str], request_id: str) -> int:
        if not self.connected:
            raise RuntimeError("Kafka producer is not connected")

        accepted = 0
        for log in logs:
            if not log or not log.strip():
                continue

            message = {
                "request_id": request_id,
                "log": log,
                "timestamp": time.time(),
                "attempts": 0
            }
            # Use request_id as key for partition locality if needed
            self.producer.send(self.topic, key=request_id, value=message)
            accepted += 1

        self.producer.flush()
        return accepted

    def send_dlq(self, payload: Dict[str, Any], error: str) -> None:
        if not self.connected:
            return

        dlq_message = {
            "payload": payload,
            "error": error,
            "dlq_timestamp": time.time()
        }
        self.producer.send(settings.kafka_dlq_topic, key=payload.get("request_id", ""), value=dlq_message)
        self.producer.flush()

producer_instance = None

def get_producer() -> ULPFProducer:
    global producer_instance
    if producer_instance is None:
        producer_instance = ULPFProducer()
    return producer_instance
