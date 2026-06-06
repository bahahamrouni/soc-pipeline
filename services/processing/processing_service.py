#!/usr/bin/env python3
"""
Processing Service - SOC Pipeline Phase 2
Consumes raw Wazuh alerts, parses, normalizes to ECS, enriches with CMDB
"""

import json
import time
import logging
import os
from datetime import datetime

logging.basicConfig(
    level=os.environ.get('LOG_LEVEL', 'INFO'),
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

try:
    from kafka import KafkaConsumer, KafkaProducer
    from kafka.errors import NoBrokersAvailable
except ImportError:
    logger.info("Installing kafka-python...")
    os.system("pip install kafka-python -q")
    from kafka import KafkaConsumer, KafkaProducer


class CMDBLookup:
    """Simple CMDB for asset enrichment"""
    
    def __init__(self):
        self.assets = {
            "192.168.10.10": {"hostname": "wazuh-manager", "criticality": 3, "role": "siem-server"},
            "192.168.10.21": {"hostname": "web-srv-01", "criticality": 2, "role": "web-server"},
            "192.168.10.22": {"hostname": "db-srv-01", "criticality": 3, "role": "db-server"},
            "192.168.10.30": {"hostname": "win-srv-2022-01", "criticality": 2, "role": "file-server"},
            "192.168.20.11": {"hostname": "workstation-01", "criticality": 1, "role": "workstation"},
        }
    
    def lookup(self, ip):
        """Lookup asset by IP"""
        return self.assets.get(ip, {"hostname": "unknown", "criticality": 1, "role": "unknown"})


class LogTemplate:
    """Simple log template extraction"""
    
    def extract_template(self, log_message):
        """Extract first 100 chars as template signature"""
        if not log_message:
            return ""
        return log_message[:100] if len(log_message) > 100 else log_message


class ProcessingService:
    def __init__(self):
        self.kafka_broker = os.environ.get('KAFKA_BROKER', 'kafka:9092')
        self.consumer_topic = os.environ.get('KAFKA_CONSUMER_TOPIC', 'wazuh-alerts-raw')
        self.producer_topic = os.environ.get('KAFKA_PRODUCER_TOPIC', 'alerts-enriched')
        
        self.consumer = None
        self.producer = None
        self.cmdb = CMDBLookup()
        self.template = LogTemplate()
        
        self.processed_count = 0
        self.error_count = 0
    
    def connect_kafka(self):
        """Connect to Kafka broker"""
        logger.info(f"Connecting to Kafka: {self.kafka_broker}")
        
        for attempt in range(15):
            try:
                self.consumer = KafkaConsumer(
                    self.consumer_topic,
                    bootstrap_servers=[self.kafka_broker],
                    auto_offset_reset='earliest',
                    value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                    group_id='processing-service',
                    enable_auto_commit=True,
                    max_poll_records=10,
                    session_timeout_ms=30000,
                    heartbeat_interval_ms=10000,
                    request_timeout_ms=40000,
                    connections_max_idle_ms=540000
                )
                
                self.producer = KafkaProducer(
                    bootstrap_servers=[self.kafka_broker],
                    value_serializer=lambda v: json.dumps(v, default=str).encode('utf-8'),
                    acks='all',
                    retries=3
                )
                
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
    
    def parse_wazuh_alert(self, alert):
        """Parse Wazuh alert structure"""
        timestamp = alert.get('timestamp', datetime.utcnow().isoformat())
        rule_id = alert.get('rule', {}).get('id', 'unknown')
        rule_level = alert.get('rule', {}).get('level', 0)
        rule_group = alert.get('rule', {}).get('groups', [])
        rule_description = alert.get('rule', {}).get('description', 'Unknown')
        
        agent_id = alert.get('agent', {}).get('id', 'unknown')
        agent_name = alert.get('agent', {}).get('name', 'unknown')
        agent_ip = alert.get('agent', {}).get('ip', 'unknown')
        
        full_log = alert.get('full_log', '')
        
        return {
            'timestamp': timestamp,
            'rule_id': rule_id,
            'rule_level': rule_level,
            'rule_group': rule_group,
            'rule_description': rule_description,
            'agent_id': agent_id,
            'agent_name': agent_name,
            'agent_ip': agent_ip,
            'full_log': full_log,
        }
    
    def normalize_to_ecs(self, parsed, alert):
        """Normalize to ECS format"""
        
        log_template = self.template.extract_template(parsed['full_log']) if parsed['full_log'] else ''
        asset = self.cmdb.lookup(parsed['agent_ip'])
        
        severity_map = {0: 'info', 1: 'low', 2: 'low', 3: 'medium', 4: 'medium', 5: 'high', 6: 'critical', 7: 'critical'}
        severity = severity_map.get(parsed['rule_level'], 'unknown')
        
        ecs_event = {
            '@timestamp': parsed['timestamp'],
            'event': {
                'id': alert.get('_event_id', 'unknown'),
                'module': 'wazuh',
                'category': 'security' if parsed['rule_level'] >= 2 else 'process',
                'type': 'alert',
                'severity': severity,
                'reason': parsed['rule_description'],
                'action': 'log',
            },
            'host': {
                'name': parsed['agent_name'],
                'id': parsed['agent_id'],
                'ip': parsed['agent_ip'],
                'os': {
                    'type': 'linux' if 'ubuntu' in parsed['agent_name'].lower() else 'windows' if 'win' in parsed['agent_name'].lower() else 'unknown'
                },
            },
            'asset': {
                'hostname': asset.get('hostname'),
                'criticality': asset.get('criticality'),
                'role': asset.get('role'),
            },
            'log': {
                'level': parsed['rule_level'],
                'logger': 'wazuh',
                'original': parsed['full_log'],
            },
            'rule': {
                'id': parsed['rule_id'],
                'name': parsed['rule_description'],
                'category': ', '.join(parsed['rule_group']) if parsed['rule_group'] else 'unknown',
                'ruleset': 'wazuh',
            },
            'log_template': log_template,
            'wazuh': alert,
            'source': {
                'ip': alert.get('data', {}).get('srcip', alert.get('data', {}).get('source_ip', 'unknown')),
                'port': alert.get('data', {}).get('srcport'),
            },
            'destination': {
                'ip': alert.get('data', {}).get('dstip', alert.get('data', {}).get('destination_ip', 'unknown')),
                'port': alert.get('data', {}).get('dstport'),
            },
            '_processing_timestamp': time.time(),
            '_normalized': True,
        }
        
        return ecs_event
    
    def process_alert(self, alert):
        """Process one alert: parse, normalize, enrich"""
        try:
            parsed = self.parse_wazuh_alert(alert)
            ecs_event = self.normalize_to_ecs(parsed, alert)
            
            future = self.producer.send(self.producer_topic, value=ecs_event)
            future.get(timeout=5)
            
            self.processed_count += 1
            
            logger.debug(f"[{self.processed_count}] Rule:{parsed['rule_id']} Severity:{ecs_event['event']['severity']} Agent:{parsed['agent_name']}")
            
            return True
            
        except Exception as e:
            self.error_count += 1
            logger.error(f"Processing error: {e}")
            return False
    
    def run(self):
        """Main event loop"""
        logger.info("="*60)
        logger.info("SOC PROCESSING SERVICE")
        logger.info("="*60)
        logger.info(f"Kafka broker: {self.kafka_broker}")
        logger.info(f"Consumer topic: {self.consumer_topic}")
        logger.info(f"Producer topic: {self.producer_topic}")
        logger.info("="*60)
        
        if not self.connect_kafka():
            logger.error("Cannot start without Kafka")
            return False
        
        logger.info("Processing alerts...")
        logger.info("(Press Ctrl+C to stop)")
        
        try:
            for message in self.consumer:
                alert = message.value
                self.process_alert(alert)
        
        except KeyboardInterrupt:
            logger.info("Shutdown requested...")
        finally:
            if self.producer:
                self.producer.flush()
                self.producer.close()
            if self.consumer:
                self.consumer.close()
            
            logger.info("="*60)
            logger.info("FINAL STATISTICS")
            logger.info(f"Alerts processed: {self.processed_count}")
            logger.info(f"Errors: {self.error_count}")
            logger.info("Service stopped")
        
        return True


if __name__ == "__main__":
    service = ProcessingService()
    service.run()