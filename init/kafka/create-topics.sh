#!/bin/bash
set -e

BROKER="kafka:9092"

echo "[kafka-init] Waiting for broker..."
until kafka-broker-api-versions --bootstrap-server "$BROKER" > /dev/null 2>&1; do
  sleep 2
done
echo "[kafka-init] Broker ready"

create_topic() {
  local name=$1
  local partitions=$2
  local retention_ms=$3

  if kafka-topics --bootstrap-server "$BROKER" --list | grep -q "^${name}$"; then
    echo "✓ Topic '$name' exists"
  else
    kafka-topics --bootstrap-server "$BROKER" \
      --create \
      --topic "$name" \
      --partitions "$partitions" \
      --replication-factor 1 \
      --config retention.ms="$retention_ms" \
      --config compression.type=lz4
    echo "✓ Created topic '$name'"
  fi
}

create_topic "wazuh-alerts-raw" 4 86400000
create_topic "alerts-parsed" 4 172800000
create_topic "alerts-normalized" 4 604800000
create_topic "alerts-enriched" 4 604800000
create_topic "incidents" 2 2592000000
create_topic "ai-results" 2 2592000000

echo "[kafka-init] Done"
kafka-topics --bootstrap-server "$BROKER" --list