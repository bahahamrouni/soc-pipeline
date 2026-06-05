#!/usr/bin/env python3
"""
Ingestion Service - SOC Pipeline
Reads Wazuh alerts from alerts.json and publishes to Kafka
"""

import json
import time
import uuid
import os
import sys
import logging
from pathlib import Path

logging.basicConfig(
    level=os.environ.get('LOG_LEVEL', 'INFO'),
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

try:
    from kafka import KafkaProducer
    from kafka.errors import NoBrokersAvailable
except ImportError:
    logger.info("Installing kafka-python...")
    os.system(f"{sys.executable} -m pip install kafka-python -q")
    from kafka import KafkaProducer
    from kafka.errors import NoBrokersAvailable


class IngestionService:
    def __init__(self):
        self.alerts_file = os.environ.get('ALERTS_FILE', '/app/data/alerts.json')
        self.kafka_broker = os.environ.get('KAFKA_BROKER', 'kafka:9092')
        self.topic = os.environ.get('KAFKA_TOPIC', 'wazuh-alerts-raw')
        self.poll_interval = int(os.environ.get('POLL_INTERVAL', 2))
        
        self.producer = None
        self.file_position = 0
        self.processed_count = 0
        self.error_count = 0
        self.running = True
        
    def connect_kafka(self):
        logger.info(f"Connecting to Kafka: {self.kafka_broker}")
        
        for attempt in range(15):
            try:
                self.producer = KafkaProducer(
                    bootstrap_servers=[self.kafka_broker],
                    value_serializer=lambda v: json.dumps(v, default=str).encode('utf-8'),
                    max_block_ms=5000,
                    request_timeout_ms=5000
                )
                self.producer.bootstrap_connected()
                logger.info(f"Connected to Kafka (attempt {attempt + 1})")
                return True
            except NoBrokersAvailable:
                logger.warning(f"Kafka unavailable, retrying... ({attempt + 1}/15)")
                time.sleep(3)
            except Exception as e:
                logger.warning(f"Connection error: {e} ({attempt + 1}/15)")
                time.sleep(3)
        
        logger.error("Failed to connect to Kafka after 15 attempts")
        return False
    
    def get_position(self):
        pos_file = Path(self.alerts_file).with_suffix('.pos')
        if pos_file.exists():
            try:
                position = int(pos_file.read_text().strip())
                logger.info(f"Resuming from position: {position}")
                return position
            except:
                return 0
        logger.info("Starting from beginning (no saved position)")
        return 0
    
    def save_position(self, position):
        pos_file = Path(self.alerts_file).with_suffix('.pos')
        try:
            pos_file.write_text(str(position))
        except:
            pass
    
    def process_line(self, line, line_num):
        line = line.strip()
        if not line:
            return False
        
        try:
            alert = json.loads(line)
            
            alert['_event_id'] = str(uuid.uuid4())
            alert['_ingest_timestamp'] = time.time()
            alert['_source'] = 'wazuh'
            
            future = self.producer.send(self.topic, value=alert)
            future.get(timeout=5)
            
            self.processed_count += 1
            
            rule_id = alert.get('rule', {}).get('id', 'unknown')
            agent = alert.get('agent', {}).get('name', 'unknown')
            logger.debug(f"[{self.processed_count}] Rule:{rule_id} Agent:{agent}")
            
            return True
            
        except json.JSONDecodeError:
            self.error_count += 1
            if self.error_count <= 5:
                logger.warning(f"Line {line_num}: Invalid JSON")
            return False
        except Exception as e:
            self.error_count += 1
            logger.error(f"Kafka send error: {e}")
            return False
    
    def process_file(self):
        if not Path(self.alerts_file).exists():
            logger.debug(f"Waiting for file: {self.alerts_file}")
            return
        
        try:
            with open(self.alerts_file, 'r') as f:
                f.seek(self.file_position)
                
                lines_processed = 0
                for line_num, line in enumerate(f, 1):
                    if self.process_line(line, line_num):
                        lines_processed += 1
                
                new_position = f.tell()
                if new_position > self.file_position:
                    self.file_position = new_position
                    self.save_position(self.file_position)
                    
                if lines_processed > 0:
                    logger.info(f"Processed {lines_processed} alerts (Total: {self.processed_count})")
                    
        except Exception as e:
            logger.error(f"File read error: {e}")
    
    def run(self):
        logger.info("="*60)
        logger.info("SOC INGESTION SERVICE")
        logger.info("="*60)
        logger.info(f"Source file: {self.alerts_file}")
        logger.info(f"Kafka broker: {self.kafka_broker}")
        logger.info(f"Topic: {self.topic}")
        logger.info(f"Poll interval: {self.poll_interval}s")
        logger.info("="*60)
        
        if not self.connect_kafka():
            logger.error("Cannot start without Kafka")
            sys.exit(1)
        
        self.file_position = self.get_position()
        
        logger.info("Reading existing alerts...")
        self.process_file()
        
        logger.info("Watching for new alerts...")
        logger.info("(Press Ctrl+C to stop)")
        
        try:
            while self.running:
                if Path(self.alerts_file).exists():
                    current_size = Path(self.alerts_file).stat().st_size
                    if current_size > self.file_position:
                        self.process_file()
                
                time.sleep(self.poll_interval)
                
        except KeyboardInterrupt:
            logger.info("Shutdown requested...")
        finally:
            if self.producer:
                self.producer.flush()
                self.producer.close()
            
            logger.info("="*60)
            logger.info("FINAL STATISTICS")
            logger.info(f"Alerts processed: {self.processed_count}")
            logger.info(f"Errors: {self.error_count}")
            logger.info("Service stopped")


if __name__ == "__main__":
    service = IngestionService()
    service.run()