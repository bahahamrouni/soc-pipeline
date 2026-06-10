#!/usr/bin/env python3
"""
Storage Service - SOC Pipeline Phase 5
Reads from ai-results Kafka topic.
Writes every result to:
  - OpenSearch (full document, for search/dashboards)
  - PostgreSQL  (structured incident record, for the API/dashboard)
"""

import json
import time
import logging
import os
import uuid
from datetime import datetime, timezone
from confluent_kafka import Consumer, KafkaError
import psycopg2
import psycopg2.extras
from opensearchpy import OpenSearch, RequestsHttpConnection
from opensearchpy.helpers import bulk

logging.basicConfig(
    level=os.environ.get('LOG_LEVEL', 'INFO'),
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
#  SEVERITY MAPPING
#  PostgreSQL schema uses SMALLINT 0-3
# ─────────────────────────────────────────────
SEVERITY_INT = {
    "info":     0,
    "low":      0,
    "medium":   1,
    "high":     2,
    "critical": 3,
}


class PostgresWriter:
    def __init__(self):
        self.host     = os.environ.get('POSTGRES_HOST', 'postgres')
        self.port     = int(os.environ.get('POSTGRES_PORT', 5432))
        self.db       = os.environ.get('POSTGRES_DB', 'socdb')
        self.user     = os.environ.get('POSTGRES_USER', 'socadmin')
        self.password = os.environ.get('POSTGRES_PASSWORD', 'S0cAdmin!')
        self.conn     = None

    def connect(self):
        for attempt in range(10):
            try:
                self.conn = psycopg2.connect(
                    host=self.host, port=self.port,
                    dbname=self.db, user=self.user, password=self.password,
                    connect_timeout=5,
                )
                self.conn.autocommit = False
                logger.info("Connected to PostgreSQL")
                return True
            except Exception as e:
                logger.warning(f"PostgreSQL connection attempt {attempt + 1} failed: {e}")
                time.sleep(2)
        logger.error("Cannot connect to PostgreSQL")
        return False

    def ensure_connection(self):
        """Reconnect if connection was lost."""
        try:
            if self.conn and not self.conn.closed:
                self.conn.cursor().execute("SELECT 1")
                return True
        except Exception:
            pass
        return self.connect()

    def write_incident(self, result):
        """Insert one ai-result into the incidents table."""
        if not self.ensure_connection():
            raise RuntimeError("PostgreSQL unavailable")

        ai   = result.get("ai_inference", {})
        rule = result.get("correlation_rule", {})
        ta   = result.get("triggering_alert", {})

        # Map severity string → int
        sev_str = result.get("severity", "medium")
        sev_int = SEVERITY_INT.get(sev_str, 1)

        # Extract source IPs and target hosts
        src_ip   = ta.get("source", {}).get("ip")
        src_ips  = [src_ip] if src_ip and src_ip != "unknown" else []
        hostname = ta.get("host", {}).get("name")
        hosts    = [hostname] if hostname and hostname != "unknown" else []

        # Timestamp
        ts_str = result.get("@timestamp", datetime.now(timezone.utc).isoformat())
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except Exception:
            ts = datetime.now(timezone.utc)

        sql = """
            INSERT INTO incidents (
                id, created_at, updated_at,
                first_seen, last_seen,
                severity, category, confidence,
                source_ips, target_hosts,
                event_count, status,
                raw_incident
            ) VALUES (
                %s, %s, %s,
                %s, %s,
                %s, %s, %s,
                %s, %s,
                %s, %s,
                %s
            )
            ON CONFLICT (id) DO UPDATE SET
                updated_at  = EXCLUDED.updated_at,
                last_seen   = EXCLUDED.last_seen,
                event_count = EXCLUDED.event_count,
                confidence  = EXCLUDED.confidence,
                raw_incident = EXCLUDED.raw_incident
        """

        incident_id = result.get("incident_id", str(uuid.uuid4()))

        with self.conn.cursor() as cur:
            cur.execute(sql, (
                incident_id,
                ts, ts,           # created_at, updated_at
                ts, ts,           # first_seen, last_seen
                sev_int,
                ai.get("attack_class", rule.get("name", "unknown")),
                ai.get("confidence", 0.0),
                src_ips or None,
                hosts or None,
                result.get("event_count", 0),
                result.get("status", "open"),
                json.dumps(result),
            ))
        self.conn.commit()


class OpenSearchWriter:
    def __init__(self):
        self.host  = os.environ.get('OPENSEARCH_HOST', 'opensearch')
        self.port  = int(os.environ.get('OPENSEARCH_PORT', 9201))
        self.index = os.environ.get('OPENSEARCH_INDEX', 'soc-incidents')
        self.client = None

    def connect(self):
        for attempt in range(10):
            try:
                self.client = OpenSearch(
                    hosts=[{"host": self.host, "port": self.port}],
                    http_compress=True,
                    use_ssl=False,
                    verify_certs=False,
                    connection_class=RequestsHttpConnection,
                    timeout=10,
                )
                info = self.client.info()
                logger.info(f"Connected to OpenSearch: {info['version']['number']}")
                self._ensure_index()
                return True
            except Exception as e:
                logger.warning(f"OpenSearch connection attempt {attempt + 1} failed: {e}")
                time.sleep(2)
        logger.error("Cannot connect to OpenSearch")
        return False

    def _ensure_index(self):
        """Create index with mappings if it doesn't exist."""
        if self.client.indices.exists(index=self.index):
            return
        mapping = {
            "mappings": {
                "properties": {
                    "@timestamp":       {"type": "date"},
                    "incident_id":      {"type": "keyword"},
                    "severity":         {"type": "keyword"},
                    "status":           {"type": "keyword"},
                    "event_count":      {"type": "integer"},
                    "correlation_key":  {"type": "keyword"},
                    "ai_inference": {
                        "properties": {
                            "attack_class":    {"type": "keyword"},
                            "confidence":      {"type": "float"},
                            "is_true_positive":{"type": "boolean"},
                        }
                    },
                    "triggering_alert": {
                        "properties": {
                            "host": {
                                "properties": {
                                    "name": {"type": "keyword"},
                                    "ip":   {"type": "ip"},
                                }
                            },
                            "rule": {
                                "properties": {
                                    "id":       {"type": "keyword"},
                                    "name":     {"type": "text"},
                                    "category": {"type": "keyword"},
                                }
                            },
                        }
                    },
                }
            },
            "settings": {
                "number_of_shards":   1,
                "number_of_replicas": 0,
            }
        }
        self.client.indices.create(index=self.index, body=mapping)
        logger.info(f"Created OpenSearch index: {self.index}")

    def write_incident(self, result):
        """Index one document into OpenSearch."""
        doc_id = result.get("incident_id", str(uuid.uuid4()))
        self.client.index(
            index=self.index,
            id=doc_id,
            body=result,
        )


class StorageService:
    def __init__(self):
        self.kafka_broker   = os.environ.get('KAFKA_BROKER', 'kafka:9092')
        self.consumer_topic = os.environ.get('KAFKA_CONSUMER_TOPIC', 'ai-results')

        self.consumer        = None
        self.pg_writer       = PostgresWriter()
        self.os_writer       = OpenSearchWriter()

        self.processed_count = 0
        self.pg_errors       = 0
        self.os_errors       = 0

    def connect_kafka(self):
        logger.info(f"Connecting to Kafka: {self.kafka_broker}")

        config = {
            'bootstrap.servers': self.kafka_broker,
            'group.id': 'storage-service',
            'auto.offset.reset': 'earliest',
            'enable.auto.commit': True,
            'session.timeout.ms': 30000,
            'heartbeat.interval.ms': 10000,
            'topic.metadata.refresh.interval.ms': 5000,
        }

        try:
            self.consumer = Consumer(config)
            logger.info("Refreshing Kafka metadata...")
            time.sleep(3)

            for attempt in range(10):
                try:
                    self.consumer.subscribe([self.consumer_topic])
                    logger.info(f"Subscribed to {self.consumer_topic} (attempt {attempt + 1})")
                    return True
                except Exception as e:
                    logger.warning(f"Subscribe attempt {attempt + 1} failed: {e}")
                    time.sleep(2)

            logger.error("Failed to subscribe after 10 attempts")
            return False

        except Exception as e:
            logger.error(f"Kafka connection failed: {e}")
            return False

    def store(self, result):
        """Write one result to both storage backends."""
        incident_id = result.get("incident_id", "?")
        attack      = result.get("ai_inference", {}).get("attack_class", "?")
        severity    = result.get("severity", "?")

        # PostgreSQL
        try:
            self.pg_writer.write_incident(result)
        except Exception as e:
            self.pg_errors += 1
            logger.error(f"PostgreSQL write failed [{incident_id}]: {e}")

        # OpenSearch
        try:
            self.os_writer.write_incident(result)
        except Exception as e:
            self.os_errors += 1
            logger.error(f"OpenSearch write failed [{incident_id}]: {e}")

        self.processed_count += 1
        logger.info(
            f"[{self.processed_count}] Stored | {attack} | severity={severity} | id={incident_id[:8]}..."
        )

    def run(self):
        logger.info("=" * 60)
        logger.info("SOC STORAGE SERVICE")
        logger.info("=" * 60)
        logger.info(f"Kafka broker:      {self.kafka_broker}")
        logger.info(f"Consumer topic:    {self.consumer_topic}")
        logger.info(f"PostgreSQL:        {self.pg_writer.host}:{self.pg_writer.port}")
        logger.info(f"OpenSearch:        {self.os_writer.host}:{self.os_writer.port}")
        logger.info(f"OpenSearch index:  {self.os_writer.index}")
        logger.info("=" * 60)

        # Connect to storage backends first
        pg_ok = self.pg_writer.connect()
        os_ok = self.os_writer.connect()

        if not pg_ok:
            logger.warning("PostgreSQL unavailable — incidents will not be persisted to SQL")
        if not os_ok:
            logger.warning("OpenSearch unavailable — incidents will not be indexed")

        if not self.connect_kafka():
            logger.error("Cannot start without Kafka")
            return False

        logger.info("Storage service running... (Press Ctrl+C to stop)")

        try:
            while True:
                msg = self.consumer.poll(timeout=1.0)

                if msg is None:
                    continue

                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        continue
                    logger.error(f"Consumer error: {msg.error()}")
                    continue

                try:
                    result = json.loads(msg.value().decode('utf-8'))
                    self.store(result)

                    if self.processed_count % 50 == 0:
                        logger.info(
                            f"Stats: stored={self.processed_count} "
                            f"pg_errors={self.pg_errors} os_errors={self.os_errors}"
                        )

                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON: {e}")

        except KeyboardInterrupt:
            logger.info("Shutdown requested...")
        finally:
            if self.consumer:
                self.consumer.close()

            logger.info("=" * 60)
            logger.info("FINAL STATISTICS")
            logger.info(f"Records stored:   {self.processed_count}")
            logger.info(f"PostgreSQL errors:{self.pg_errors}")
            logger.info(f"OpenSearch errors:{self.os_errors}")
            logger.info("Storage service stopped")

        return True


if __name__ == "__main__":
    service = StorageService()
    service.run()