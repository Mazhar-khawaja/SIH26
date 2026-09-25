from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_name: str = "ULPF"
    app_env: str = "development"
    log_level: str = "INFO"
    host: str = "0.0.0.0"
    port: int = 8000
    database_url: str = "sqlite:///data/ulpf.db"
    cors_origins: List[str] = ["*"]

    jwt_secret: str = "supersecret_default_key_change_me_in_prod"
    jwt_algorithm: str = "HS256"
    api_key: str = "default_api_key_change_me"

    rate_limit: str = "100/minute"
    upload_rate_limit: str = "10/minute"

    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_topic: str = "ulpf_events"
    kafka_dlq_topic: str = "ulpf_events_dlq"
    kafka_group_id: str = "ulpf_workers"
    kafka_batch_size: int = 100
    kafka_max_retries: int = 3

    opensearch_enabled: bool = True
    opensearch_url: str = "http://localhost:9200"
    opensearch_username: str = ""
    opensearch_password: str = ""
    opensearch_index: str = "ulpf-events"
    opensearch_analytics_index: str = "ulpf-analytics"
    opensearch_timeout: int = 10

    analytics_enabled: bool = True
    failed_login_threshold: int = 5
    failed_login_window_seconds: int = 300
    source_ip_event_threshold: int = 100
    source_ip_window_seconds: int = 60
    anomaly_zscore_threshold: float = 3.0
    min_baseline_samples: int = 50

    intelligence_enabled: bool = True
    ai_classification_threshold: float = 0.8

    siem_enabled: bool = False
    siem_url: str = ""
    siem_api_key: str = ""
    siem_token: str = ""
    siem_timeout: int = 5
    siem_verify_tls: bool = True
    siem_max_retries: int = 3
    siem_retry_backoff_seconds: int = 2

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

settings = Settings()
