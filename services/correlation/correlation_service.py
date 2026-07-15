#!/usr/bin/env python3
"""
Correlation Engine - SOC Pipeline Phase 3
Consumes enriched alerts, applies sliding-window rules via Redis,
produces incidents to the incidents Kafka topic.
"""

import json
import time
import logging
import os
import uuid
from datetime import datetime, timezone
from confluent_kafka import Consumer, Producer, KafkaError
import redis

logging.basicConfig(
    level=os.environ.get('LOG_LEVEL', 'INFO'),
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
#  CORRELATION RULES
#  Each rule defines:
#    id          - unique rule identifier
#    name        - human-readable name
#    description - what it detects
#    window_sec  - sliding time window in seconds
#    threshold   - how many hits to trigger
#    severity    - incident severity when triggered
#    key_fn      - function(alert) → Redis key suffix (groups alerts)
#    match_fn    - function(alert) → bool (does this alert apply?)
# ─────────────────────────────────────────────

CORRELATION_RULES = [
    {
        "id": "CORR-001",
        "name": "Brute Force Detection",
        "description": "Multiple authentication failures from the same source IP within a short window",
        "window_sec": 60,
        "threshold": 5,
        "severity": "high",
        "key_fn": lambda a: f"brute_force:{a.get('host', {}).get('ip', 'unknown')}",
        "match_fn": lambda a: (
            a.get("rule", {}).get("id") in ["60104", "60106", "5710", "5712", "2501", "2502"]
            or "authentication_failed" in a.get("rule", {}).get("category", "")
            or "brute_force" in a.get("rule", {}).get("category", "")
        ),
    },
    {
        "id": "CORR-002",
        "name": "Privilege Escalation Burst",
        "description": "Repeated privilege-related high severity alerts from the same host",
        "window_sec": 120,
        "threshold": 3,
        "severity": "critical",
        "key_fn": lambda a: f"priv_esc:{a.get('host', {}).get('name', 'unknown')}",
        "match_fn": lambda a: (
            a.get("event", {}).get("severity") in ["high", "critical"]
            and any(g in a.get("rule", {}).get("category", "")
                    for g in ["windows_security", "privilege", "escalation", "sudo"])
        ),
    },
    {
        "id": "CORR-003",
        "name": "Lateral Movement",
        "description": "Same source IP triggering alerts on multiple distinct destination hosts",
        "window_sec": 300,
        "threshold": 3,
        "severity": "critical",
        "mode": "distinct",
        # Key is source IP ONLY � distinct destination hosts are tracked via a Redis SET (value_fn)
        "key_fn": lambda a: f"lateral:{a.get('source', {}).get('ip', 'unknown')}",
        # The value added to the set for this alert � distinct count of THIS is what matters
        "value_fn": lambda a: a.get("host", {}).get("name", "unknown"),
        "match_fn": lambda a: (
            a.get("source", {}).get("ip", "unknown") not in ["unknown", None]
            and a.get("event", {}).get("severity") in ["medium", "high", "critical"]
        ),
    },
    {
        "id": "CORR-004",
        "name": "Alert Storm",
        "description": "Abnormally high volume of alerts from a single agent — possible misconfiguration or active attack",
        "window_sec": 60,
        "threshold": 20,
        "severity": "medium",
        "key_fn": lambda a: f"alert_storm:{a.get('host', {}).get('name', 'unknown')}",
        "match_fn": lambda a: True,  # Matches all alerts — counts volume per agent
    },
    {
        "id": "CORR-005",
        "name": "Repeated High Severity",
        "description": "Multiple high or critical severity alerts from the same host in a short period",
        "window_sec": 180,
        "threshold": 3,
        "severity": "high",
        "key_fn": lambda a: f"high_sev:{a.get('host', {}).get('name', 'unknown')}",
        "match_fn": lambda a: a.get("event", {}).get("severity") in ["high", "critical"],
    },
    {
        "id": "CORR-006",
        "name": "Reconnaissance/ port scan",
        "description": "pfsense port scan confirmed by wazuh frequency correlation (rule 100201)",
        "window_sec": 30,
        "threshold": 1,
        "severity": "high",
        "key_fn": lambda a: f"recon:{a.get('data', {}).get('srcip', a.get('source', {}).get('ip', 'unkown'))}",
        "match_fn": lambda a: (
            a.get("rule", {}).get("id") == "100201"
            or "port_scan" in a.get("rule", {}).get("groups", [])
            or "recon" in a.get("rule", {}).get("groups", [])
        ),
     },
]


class RedisWindowCounter:
    """
    Sliding window counter using Redis INCR + EXPIRE.
    Each key tracks how many times an event occurred within the window.
    On threshold breach: fires once, then resets the counter.
    """

    def __init__(self, redis_client):
        self.r = redis_client

    def increment_and_check(self, key, window_sec, threshold):
        """
        Increment counter for key.
        Returns (current_count, triggered)
        triggered=True only on the exact threshold crossing.
        """
        full_key = f"corr:{key}"
        pipe = self.r.pipeline()
        pipe.incr(full_key)
        pipe.expire(full_key, window_sec)
        results = pipe.execute()
        count = results[0]

        if count == threshold:
            # Reset so it can fire again after another full threshold of events
            self.r.delete(full_key)
            return count, True

        return count, False

    def add_and_check_distinct(self, key, member, window_sec, threshold):
        """
        Track DISTINCT members added to a set within a sliding window.
        Fires when the number of distinct members reaches threshold.
        Returns (distinct_count, triggered).
        """
        full_key = f"corrset:{key}"
        pipe = self.r.pipeline()
        pipe.sadd(full_key, member)
        pipe.expire(full_key, window_sec)
        pipe.scard(full_key)
        results = pipe.execute()
        count = results[2]
        if count == threshold:
            self.r.delete(full_key)
            return count, True
        return count, False

    def get_count(self, key):
        full_key = f"corr:{key}"
        val = self.r.get(full_key)
        return int(val) if val else 0


class CorrelationEngine:
    def __init__(self):
        self.kafka_broker = os.environ.get('KAFKA_BROKER', 'kafka:9092')
        self.consumer_topic = os.environ.get('KAFKA_CONSUMER_TOPIC', 'alerts-enriched')
        self.producer_topic = os.environ.get('KAFKA_PRODUCER_TOPIC', 'incidents')
        self.redis_host = os.environ.get('REDIS_HOST', 'redis')
        self.redis_port = int(os.environ.get('REDIS_PORT', 6379))

        self.consumer = None
        self.producer = None
        self.redis_client = None
        self.window_counter = None

        self.alerts_processed = 0
        self.incidents_fired = 0

    # ── Connections ──────────────────────────────────────────────────────────

    def connect_redis(self):
        logger.info(f"Connecting to Redis: {self.redis_host}:{self.redis_port}")
        for attempt in range(10):
            try:
                self.redis_client = redis.Redis(
                    host=self.redis_host,
                    port=self.redis_port,
                    password=os.environ.get('REDIS_PASSWORD', None),
                    db=0,
                    decode_responses=True,
                    socket_connect_timeout=5,
                )
                self.redis_client.ping()
                self.window_counter = RedisWindowCounter(self.redis_client)
                logger.info("Connected to Redis")
                return True
            except Exception as e:
                logger.warning(f"Redis connection attempt {attempt + 1} failed: {e}")
                time.sleep(2)
        logger.error("Cannot connect to Redis after 10 attempts")
        return False

    def connect_kafka(self):
        logger.info(f"Connecting to Kafka: {self.kafka_broker}")

        consumer_config = {
            'bootstrap.servers': self.kafka_broker,
            'group.id': 'correlation-engine',
            'auto.offset.reset': 'earliest',
            'enable.auto.commit': True,
            'session.timeout.ms': 30000,
            'heartbeat.interval.ms': 10000,
            'topic.metadata.refresh.interval.ms': 5000,
        }

        producer_config = {
            'bootstrap.servers': self.kafka_broker,
            'acks': 'all',
            'retries': 10,
            'topic.metadata.refresh.interval.ms': 5000,
        }

        try:
            self.consumer = Consumer(consumer_config)
            self.producer = Producer(producer_config)

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

    # ── Core Logic ───────────────────────────────────────────────────────────

    def evaluate_rules(self, alert):
        """
        Run all correlation rules against one enriched alert.
        For each matching rule, increment its Redis counter.
        If threshold crossed, build and publish an incident.
        """
        for rule in CORRELATION_RULES:
            try:
                if not rule["match_fn"](alert):
                    continue

                key = rule["key_fn"](alert)
                if rule.get("mode") == "distinct":
                    member = rule["value_fn"](alert)
                    count, triggered = self.window_counter.add_and_check_distinct(
                        key, member, rule["window_sec"], rule["threshold"]
                    )
                else:
                    count, triggered = self.window_counter.increment_and_check(
                        key, rule["window_sec"], rule["threshold"]
                    )

                logger.debug(
                    f"Rule {rule['id']} | key={key} | count={count}/{rule['threshold']}"
                )

                if triggered:
                    self.fire_incident(rule, alert, count, key)

            except Exception as e:
                logger.error(f"Error evaluating rule {rule['id']}: {e}")

    def fire_incident(self, rule, triggering_alert, count, correlation_key):
        """Build an incident object and publish it to the incidents Kafka topic."""
        incident = {
            "incident_id": str(uuid.uuid4()),
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "correlation_rule": {
                "id": rule["id"],
                "name": rule["name"],
                "description": rule["description"],
                "threshold": rule["threshold"],
                "window_sec": rule["window_sec"],
            },
            "severity": rule["severity"],
            "status": "open",
            "correlation_key": correlation_key,
            "event_count": count,
            # Include context from the triggering alert
            "triggering_alert": {
                "host": triggering_alert.get("host", {}),
                "source": triggering_alert.get("source", {}),
                "rule": triggering_alert.get("rule", {}),
                "event": triggering_alert.get("event", {}),
                "asset": triggering_alert.get("asset", {}),
            },
            "_source": "correlation-engine",
        }

        try:
            self.producer.produce(
                self.producer_topic,
                key=incident["incident_id"].encode('utf-8'),
                value=json.dumps(incident, default=str).encode('utf-8')
            )
            self.producer.flush()
            self.incidents_fired += 1

            logger.info(
                f"🚨 INCIDENT FIRED | {rule['id']} | {rule['name']} | "
                f"severity={rule['severity']} | key={correlation_key} | "
                f"count={count}/{rule['threshold']}"
            )

        except Exception as e:
            logger.error(f"Failed to publish incident: {e}")

    # ── Main Loop ────────────────────────────────────────────────────────────

    def run(self):
        logger.info("=" * 60)
        logger.info("SOC CORRELATION ENGINE")
        logger.info("=" * 60)
        logger.info(f"Kafka broker:    {self.kafka_broker}")
        logger.info(f"Consumer topic:  {self.consumer_topic}")
        logger.info(f"Producer topic:  {self.producer_topic}")
        logger.info(f"Redis:           {self.redis_host}:{self.redis_port}")
        logger.info(f"Rules loaded:    {len(CORRELATION_RULES)}")
        for r in CORRELATION_RULES:
            logger.info(
                f"  [{r['id']}] {r['name']} "
                f"(threshold={r['threshold']}, window={r['window_sec']}s, severity={r['severity']})"
            )
        logger.info("=" * 60)

        if not self.connect_redis():
            logger.error("Cannot start without Redis")
            return False

        if not self.connect_kafka():
            logger.error("Cannot start without Kafka")
            return False

        logger.info("Correlation engine running... (Press Ctrl+C to stop)")

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
                    alert = json.loads(msg.value().decode('utf-8'))
                    self.evaluate_rules(alert)
                    self.alerts_processed += 1

                    if self.alerts_processed % 100 == 0:
                        logger.info(
                            f"Stats: alerts_processed={self.alerts_processed} "
                            f"incidents_fired={self.incidents_fired}"
                        )

                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON in message: {e}")

        except KeyboardInterrupt:
            logger.info("Shutdown requested...")
        finally:
            if self.producer:
                self.producer.flush()
            if self.consumer:
                self.consumer.close()

            logger.info("=" * 60)
            logger.info("FINAL STATISTICS")
            logger.info(f"Alerts processed: {self.alerts_processed}")
            logger.info(f"Incidents fired:  {self.incidents_fired}")
            logger.info("Correlation engine stopped")

        return True


if __name__ == "__main__":
    engine = CorrelationEngine()
    engine.run()
