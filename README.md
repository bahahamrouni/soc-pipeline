markdown# SOC Pipeline — Phase 0 & 1

Complete AI-assisted SOC pipeline on top of Wazuh SIEM.

## Architecture
Wazuh Agents → Wazuh Manager → alerts.json
↓
Ingestion Service
↓
Kafka (event bus)
↓
Processing Service
↓
PostgreSQL + OpenSearch (storage)
↓
API + Dashboard

## Requirements

- Docker ≥ 24.0
- Docker Compose v2
- 8 vCPU, 8 GB RAM minimum
- Wazuh Manager running with alerts.json generation

## Quick Start

```bash
# Clone repo
git clone <your-repo> soc-pipeline
cd soc-pipeline

# Configure
nano .env    # adjust passwords if needed

# Deploy
make setup
make up

# Monitor
make logs s=ingestion
```

## Services

| Service | Role | Port | Status |
|---------|------|------|--------|
| Kafka | Event bus | 9092 | ✓ Phase 0 |
| Redis | State cache | 6379 | ✓ Phase 0 |
| PostgreSQL | Incident DB | 5432 | ✓ Phase 0 |
| Ingestion | Read Wazuh alerts | internal | ✓ Phase 1 |
| Processing | Parse & normalize | internal | ⏳ Phase 2 |
| Correlation | Group incidents | internal | ⏳ Phase 3 |
| API | REST endpoints | 8000 | ⏳ Phase 5 |
| Dashboard | React UI | 3000 | ⏳ Phase 5 |

## Commands

```bash
make up              # Start all
make down            # Stop all
make status          # Show containers
make logs s=kafka    # Tail service logs
make health          # Check all healthy
make topics          # List Kafka topics
make clean           # Delete all data (DESTRUCTIVE)
```

## Verify Pipeline

```bash
# Check containers running
docker compose ps

# See ingestion logs
docker compose logs -f ingestion

# Peek at Kafka messages
docker compose exec kafka kafka-console-consumer \
  --topic wazuh-alerts-raw \
  --bootstrap-server localhost:9092 \
  --from-beginning \
  --max-messages 5
```

## Files

- `docker-compose.yml` — infrastructure definition
- `.env` — configuration variables
- `config/` — service configs
- `init/` — database schemas, Kafka topics
- `services/ingestion/` — Wazuh alert reader