#!/usr/bin/env python3
"""
Ingestion Service - SOC Pipeline Phase 1
Reads Wazuh alerts.json and sends to Kafka
"""

import json
import time
import logging
import os
from pathlib import Path
from confluent_kafka import Producer, KafkaError

logging.basicConfig(
    level=os.environ.get('LOG_LEVEL', 'INFO'),
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class IngestionService:
    def __init__(self):
        self.alerts_file = os.environ.get('ALERTS_FILE', '/app/data/alerts.json')
        self.kafka_broker = os.environ.get('KAFKA_BROKER', 'kafka:9092')
        self.kafka_topic = os.environ.get('KAFKA_TOPIC', 'wazuh-alerts-raw')
        self.poll_interval = int(os.environ.get('POLL_INTERVAL', '2'))
        
        self.producer = None
        self.last_position = 0
        self.position_file = os.environ.get('POSITION_FILE', self.alerts_file + '.pos')
        
        self.sent_count = 0
        self.error_count = 0
    
    def connect_kafka(self):
        """Connect to Kafka broker using Confluent client with retry"""
        logger.info(f"Connecting to Kafka: {self.kafka_broker}")
        
        producer_config = {
            'bootstrap.servers': self.kafka_broker,
            'acks': 'all',
            'retries': 10,
            'topic.metadata.refresh.interval.ms': 5000,
        }
        
        try:
            self.producer = Producer(producer_config)
            
            # Force metadata refresh
            logger.info("Refreshing Kafka metadata...")
            time.sleep(3)
            
            # Test producer with retry
            for attempt in range(10):
                try:
                    # Trigger metadata fetch by checking topic
                    self.producer.list_topics(timeout=5)
                    logger.info(f"Kafka metadata refreshed (attempt {attempt + 1})")
                    return True
                except Exception as e:
                    logger.warning(f"Metadata refresh attempt {attempt + 1} failed: {e}")
                    time.sleep(2)
            
            logger.error("Failed to refresh metadata after 10 attempts")
            return False
            
        except Exception as e:
            logger.error(f"Failed to connect to Kafka: {e}")
            return False
    
    def load_position(self):
        """Load last read position"""
        if os.path.exists(self.position_file):
            try:
                with open(self.position_file, 'r') as f:
                    self.last_position = int(f.read().strip())
                logger.info(f"Loaded position: {self.last_position}")
            except Exception as e:
                logger.warning(f"Could not load position: {e}")
    
    def save_position(self):
        """Save current read position"""
        try:
            with open(self.position_file, 'w') as f:
                f.write(str(self.last_position))
        except Exception as e:
            logger.error(f"Could not save position: {e}")
    
    def read_existing_alerts(self):
        """Read existing alerts from file"""
        if not os.path.exists(self.alerts_file):
            logger.warning(f"Alerts file not found: {self.alerts_file}")
            return
        
        logger.info(f"Reading existing alerts from {self.alerts_file}...")
        
        try:
            with open(self.alerts_file, 'r', encoding='utf-8', errors='replace') as f:
                line_num = 0
                for line in f:
                    line_num += 1
                    if line_num <= self.last_position:
                        continue
                    
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        alert = json.loads(line)
                        self.send_alert(alert)
                        self.last_position = line_num
                    except json.JSONDecodeError as e:
                        logger.error(f"JSON decode error on line {line_num}: {e}")
                        self.error_count += 1
        
        except IOError as e:
            logger.error(f"File read error: {e}")
        
        self.save_position()
        logger.info(f"Finished reading existing alerts. Position: {self.last_position}")
    
    def send_alert(self, alert):
        """Send alert to Kafka"""
        try:
            alert['_event_id'] = alert.get('id', str(int(time.time() * 1000)))
            alert['_ingest_timestamp'] = time.time()
            alert['_source'] = 'wazuh'
            
            self.producer.produce(
                self.kafka_topic,
                value=json.dumps(alert, default=str).encode('utf-8')
            )
            self.producer.flush()
            
            self.sent_count += 1
            logger.debug(f"[{self.sent_count}] Sent alert: {alert.get('rule', {}).get('id', 'unknown')}")
            
        except Exception as e:
            self.error_count += 1
            logger.error(f"Send error: {e}")
    
    def watch_for_new_alerts(self):
        """Watch file for new alerts"""
        logger.info("Watching for new alerts...")
        
        try:
            while True:
                try:
                    with open(self.alerts_file, 'r', encoding='utf-8', errors='replace') as f:
                        f.seek(0, 2)  # Go to end
                        
                        while True:
                            pos_before = f.tell()
                            line = f.readline()
                            if not line:
                                time.sleep(self.poll_interval)
                                continue
                            if not line.endswith('\n'):
                                f.seek(pos_before)
                                time.sleep(0.2)
                                continue
                            
                            line = line.strip()
                            if not line:
                                continue
                            
                            try:
                                alert = json.loads(line)
                                self.send_alert(alert)
                                self.last_position += 1
                                self.save_position()
                            except json.JSONDecodeError as e:
                                logger.warning(f"Malformed line, rewinding to entry: {e}")
                                f.seek(pos_before)
                                time.sleep(0.2)
                
                except IOError:
                    time.sleep(self.poll_interval)
        
        except KeyboardInterrupt:
            logger.info("Watch interrupted")
    
    def run(self):
        """Main event loop"""
        logger.info("="*60)
        logger.info("SOC INGESTION SERVICE")
        logger.info("="*60)
        logger.info(f"Source file: {self.alerts_file}")
        logger.info(f"Kafka broker: {self.kafka_broker}")
        logger.info(f"Topic: {self.kafka_topic}")
        logger.info(f"Poll interval: {self.poll_interval}s")
        logger.info("="*60)
        
        self.load_position()
        
        if not self.connect_kafka():
            logger.error("Cannot start without Kafka")
            return False
        
        self.read_existing_alerts()
        self.watch_for_new_alerts()
        
        logger.info("="*60)
        logger.info("FINAL STATISTICS")
        logger.info(f"Alerts sent: {self.sent_count}")
        logger.info(f"Errors: {self.error_count}")
        logger.info("Service stopped")
        
        return True


if __name__ == "__main__":
    service = IngestionService()
    service.run()
