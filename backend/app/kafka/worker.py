import json
import time
import sys
import threading
from typing import Callable, Any
from kafka import KafkaConsumer, TopicPartition
from kafka.errors import KafkaError
from app.config.settings import settings
from app.monitoring.logger import get_logger
from app.kafka.producer import get_producer

logger = get_logger("ulpf.kafka.worker")

class ULPFWorker:
    def __init__(self, processor_func: Callable[[str], Any]):
        self.bootstrap_servers = settings.kafka_bootstrap_servers
        self.topic = settings.kafka_topic
        self.group_id = settings.kafka_group_id
        self.processor_func = processor_func
        self.running = False
        self.producer = get_producer()

        try:
            self.consumer = KafkaConsumer(
                self.topic,
                bootstrap_servers=self.bootstrap_servers,
                group_id=self.group_id,
                value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                auto_offset_reset='earliest',
                enable_auto_commit=False,
                max_poll_records=settings.kafka_batch_size
            )
            self.connected = True
        except Exception as e:
            logger.error("Failed to connect to Kafka consumer", error=e)
            self.connected = False

    def start(self):
        if not self.connected:
            logger.error("Cannot start worker, Kafka disconnected.")
            return

        self.running = True
        logger.info("Worker started, listening for messages...")

        while self.running:
            try:
                # Poll for messages
                message_batch = self.consumer.poll(timeout_ms=1000)
                if not message_batch:
                    continue

                for tp, messages in message_batch.items():
                    for msg in messages:
                        self.process_message(msg.value)

                # Commit offsets after successful processing of batch
                self.consumer.commit()
            except Exception as e:
                logger.error("Error polling Kafka", error=str(e))
                time.sleep(5)

    def process_message(self, payload: dict):
        log = payload.get("log")
        attempts = payload.get("attempts", 0)

        try:
            # Process log
            self.processor_func(log)
            logger.info("Successfully processed message from Kafka")
        except Exception as e:
            attempts += 1
            payload["attempts"] = attempts
            logger.warning(f"Failed to process message, attempt {attempts}", error=str(e))

            if attempts >= settings.kafka_max_retries:
                logger.error("Message exceeded max retries, sending to DLQ")
                self.producer.send_dlq(payload, str(e))
            else:
                # Retry by pushing back to the main topic
                # Wait briefly to not flood
                time.sleep(1)
                self.producer.producer.send(self.topic, key=payload.get("request_id"), value=payload)

    def stop(self):
        self.running = False
        if self.connected:
            self.consumer.close()

def run_worker_in_background(processor_func):
    worker = ULPFWorker(processor_func)
    thread = threading.Thread(target=worker.start, daemon=True)
    thread.start()
    return worker
