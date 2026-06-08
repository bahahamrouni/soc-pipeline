#!/usr/bin/env python3
"""
AI Inference Service - SOC Pipeline Phase 4
Reads incidents, classifies attack type + confidence using XGBoost,
writes enriched results to ai-results Kafka topic.
"""

import json
import time
import logging
import os
import uuid
import numpy as np
from datetime import datetime, timezone
from confluent_kafka import Consumer, Producer, KafkaError
import xgboost as xgb
from sklearn.preprocessing import LabelEncoder
import pickle

logging.basicConfig(
    level=os.environ.get('LOG_LEVEL', 'INFO'),
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
#  ATTACK CLASSES
#  These are the labels XGBoost will classify into
# ─────────────────────────────────────────────
ATTACK_CLASSES = [
    "brute_force",
    "privilege_escalation",
    "lateral_movement",
    "alert_storm",
    "reconnaissance",
    "data_exfiltration",
    "malware_activity",
    "normal_activity",
]

# ─────────────────────────────────────────────
#  FEATURE MAPPINGS
# ─────────────────────────────────────────────
RULE_ID_MAP = {
    "CORR-001": 1,  # Brute Force
    "CORR-002": 2,  # Privilege Escalation
    "CORR-003": 3,  # Lateral Movement
    "CORR-004": 4,  # Alert Storm
    "CORR-005": 5,  # Repeated High Severity
}

SEVERITY_MAP = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

ROLE_MAP = {
    "unknown": 0,
    "workstation": 1,
    "web-server": 2,
    "file-server": 3,
    "db-server": 4,
    "siem-server": 5,
}


# ─────────────────────────────────────────────
#  SYNTHETIC TRAINING DATA GENERATOR
#  Realistic patterns based on known attack behaviors
# ─────────────────────────────────────────────
def generate_training_data(n_samples=2000):
    """
    Generate synthetic but realistic labeled training data.
    Features: [rule_id, severity, event_count, window_sec,
               threshold, asset_criticality, asset_role,
               source_ip_internal, hour_of_day]
    """
    np.random.seed(42)
    X, y = [], []

    label_encoder = LabelEncoder()
    label_encoder.fit(ATTACK_CLASSES)

    patterns = [
        # (label, rule_id, severity_range, count_range, criticality_range, role_range, internal_src)
        ("brute_force",         1, (2,4), (5,50),  (1,3), (0,3), 0.3),
        ("brute_force",         1, (3,4), (5,30),  (1,2), (1,2), 0.5),
        ("privilege_escalation",2, (3,4), (3,15),  (2,4), (2,5), 0.8),
        ("privilege_escalation",5, (3,4), (3,10),  (3,5), (3,5), 0.9),
        ("lateral_movement",    3, (2,4), (3,20),  (1,4), (0,4), 0.7),
        ("lateral_movement",    5, (3,4), (3,12),  (2,4), (1,4), 0.8),
        ("alert_storm",         4, (1,3), (20,100),(1,3), (0,3), 0.5),
        ("alert_storm",         4, (2,3), (20,80), (1,2), (0,2), 0.4),
        ("reconnaissance",      1, (1,3), (3,20),  (1,3), (1,3), 0.2),
        ("reconnaissance",      3, (1,3), (3,15),  (1,2), (0,2), 0.3),
        ("data_exfiltration",   3, (2,4), (3,10),  (3,5), (3,5), 0.9),
        ("data_exfiltration",   5, (3,4), (3,8),   (4,5), (4,5), 0.95),
        ("malware_activity",    2, (3,4), (3,15),  (2,4), (2,4), 0.8),
        ("malware_activity",    5, (3,4), (3,10),  (3,5), (3,5), 0.85),
        ("normal_activity",     1, (0,2), (1,5),   (1,2), (0,2), 0.6),
        ("normal_activity",     4, (0,2), (1,10),  (1,2), (0,2), 0.5),
    ]

    samples_per_pattern = n_samples // len(patterns)

    for (label, rule_id, sev_range, cnt_range,
         crit_range, role_range, int_prob) in patterns:

        for _ in range(samples_per_pattern):
            severity    = np.random.randint(*sev_range)
            event_count = np.random.randint(*cnt_range)
            criticality = np.random.randint(*crit_range)
            role        = np.random.randint(*role_range)
            internal    = 1 if np.random.random() < int_prob else 0
            window_sec  = np.random.choice([60, 120, 180, 300])
            threshold   = np.random.randint(3, 21)
            hour        = np.random.randint(0, 24)

            # Add noise
            severity    = min(4, max(0, severity + np.random.randint(-1, 2)))
            event_count = max(1, event_count + np.random.randint(-2, 5))

            X.append([rule_id, severity, event_count, window_sec,
                      threshold, criticality, role, internal, hour])
            y.append(label)

    X = np.array(X, dtype=np.float32)
    y = label_encoder.transform(y)

    return X, y, label_encoder


# ─────────────────────────────────────────────
#  XGBOOST MODEL
# ─────────────────────────────────────────────
class AttackClassifier:
    def __init__(self):
        self.model = None
        self.label_encoder = None
        self.model_path = "/app/model/xgboost_model.pkl"

    def train(self):
        logger.info("Generating synthetic training data...")
        X, y, self.label_encoder = generate_training_data(n_samples=2000)

        logger.info(f"Training XGBoost on {len(X)} samples, {len(ATTACK_CLASSES)} classes...")

        self.model = xgb.XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            use_label_encoder=False,
            eval_metric='mlogloss',
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X, y)

        # Save model
        os.makedirs("/app/model", exist_ok=True)
        with open(self.model_path, 'wb') as f:
            pickle.dump({"model": self.model, "encoder": self.label_encoder}, f)

        logger.info("XGBoost model trained and saved")

    def load_or_train(self):
        if os.path.exists(self.model_path):
            logger.info("Loading existing model...")
            try:
                with open(self.model_path, 'rb') as f:
                    data = pickle.load(f)
                self.model = data["model"]
                self.label_encoder = data["encoder"]
                logger.info("Model loaded from disk")
                return
            except Exception as e:
                logger.warning(f"Failed to load model: {e}. Retraining...")
        self.train()

    def extract_features(self, incident):
        """Extract numeric feature vector from an incident."""
        rule_id = RULE_ID_MAP.get(
            incident.get("correlation_rule", {}).get("id", ""), 0
        )
        severity = SEVERITY_MAP.get(
            incident.get("severity", "medium"), 2
        )
        event_count = incident.get("event_count", 1)
        window_sec = incident.get("correlation_rule", {}).get("window_sec", 60)
        threshold = incident.get("correlation_rule", {}).get("threshold", 5)

        ta = incident.get("triggering_alert", {})
        asset = ta.get("asset", {})
        criticality = int(asset.get("criticality") or 1)
        role = ROLE_MAP.get(asset.get("role", "unknown"), 0)

        # Is source IP internal? (192.168.x.x)
        src_ip = ta.get("source", {}).get("ip", "unknown") or "unknown"
        internal = 1 if src_ip.startswith("192.168.") else 0

        # Hour of day from timestamp
        try:
            ts = incident.get("@timestamp", "")
            hour = datetime.fromisoformat(ts.replace("Z", "+00:00")).hour
        except Exception:
            hour = 12

        return np.array([[rule_id, severity, event_count, window_sec,
                          threshold, criticality, role, internal, hour]],
                        dtype=np.float32)

    def predict(self, incident):
        """
        Returns (attack_class, confidence, all_probabilities)
        """
        features = self.extract_features(incident)
        proba = self.model.predict_proba(features)[0]
        class_idx = int(np.argmax(proba))
        confidence = float(proba[class_idx])
        attack_class = self.label_encoder.inverse_transform([class_idx])[0]

        all_probs = {
            self.label_encoder.inverse_transform([i])[0]: round(float(p), 4)
            for i, p in enumerate(proba)
        }

        return attack_class, confidence, all_probs


# ─────────────────────────────────────────────
#  INFERENCE SERVICE
# ─────────────────────────────────────────────
class AIInferenceService:
    def __init__(self):
        self.kafka_broker = os.environ.get('KAFKA_BROKER', 'kafka:9092')
        self.consumer_topic = os.environ.get('KAFKA_CONSUMER_TOPIC', 'incidents')
        self.producer_topic = os.environ.get('KAFKA_PRODUCER_TOPIC', 'ai-results')

        self.consumer = None
        self.producer = None
        self.classifier = AttackClassifier()

        self.processed_count = 0
        self.error_count = 0

    def connect_kafka(self):
        logger.info(f"Connecting to Kafka: {self.kafka_broker}")

        consumer_config = {
            'bootstrap.servers': self.kafka_broker,
            'group.id': 'ai-inference-service',
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

    def process_incident(self, incident):
        """Run inference on one incident and publish enriched result."""
        try:
            attack_class, confidence, all_probs = self.classifier.predict(incident)

            # Determine if this looks like a true positive
            is_true_positive = confidence >= 0.6 and attack_class != "normal_activity"

            result = {
                **incident,  # Keep all original incident fields
                "ai_inference": {
                    "attack_class": attack_class,
                    "confidence": round(confidence, 4),
                    "is_true_positive": is_true_positive,
                    "all_probabilities": all_probs,
                    "model": "xgboost-v1",
                    "inference_timestamp": datetime.now(timezone.utc).isoformat(),
                },
            }

            self.producer.produce(
                self.producer_topic,
                key=incident.get("incident_id", str(uuid.uuid4())).encode('utf-8'),
                value=json.dumps(result, default=str).encode('utf-8')
            )
            self.producer.flush()
            self.processed_count += 1

            tp_label = "TRUE_POSITIVE" if is_true_positive else "FALSE_POSITIVE"
            logger.info(
                f"[{self.processed_count}] {incident.get('correlation_rule', {}).get('id')} → "
                f"{attack_class} | confidence={confidence:.2%} | {tp_label}"
            )

        except Exception as e:
            self.error_count += 1
            logger.error(f"Inference error: {e}")

    def run(self):
        logger.info("=" * 60)
        logger.info("SOC AI INFERENCE SERVICE")
        logger.info("=" * 60)
        logger.info(f"Kafka broker:   {self.kafka_broker}")
        logger.info(f"Consumer topic: {self.consumer_topic}")
        logger.info(f"Producer topic: {self.producer_topic}")
        logger.info(f"Attack classes: {ATTACK_CLASSES}")
        logger.info("=" * 60)

        # Train / load model before connecting to Kafka
        self.classifier.load_or_train()

        if not self.connect_kafka():
            logger.error("Cannot start without Kafka")
            return False

        logger.info("AI Inference running... (Press Ctrl+C to stop)")

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
                    incident = json.loads(msg.value().decode('utf-8'))
                    self.process_incident(incident)
                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON: {e}")

        except KeyboardInterrupt:
            logger.info("Shutdown requested...")
        finally:
            if self.producer:
                self.producer.flush()
            if self.consumer:
                self.consumer.close()

            logger.info("=" * 60)
            logger.info("FINAL STATISTICS")
            logger.info(f"Incidents processed: {self.processed_count}")
            logger.info(f"Errors:              {self.error_count}")
            logger.info("AI Inference service stopped")

        return True


if __name__ == "__main__":
    service = AIInferenceService()
    service.run()