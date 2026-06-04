.PHONY: help setup up down restart status logs clean health topics

help:
	@echo "SOC Pipeline Commands:"
	@echo "  make setup          - First-time setup"
	@echo "  make up             - Start all services"
	@echo "  make down           - Stop all services"
	@echo "  make restart        - Restart all services"
	@echo "  make status         - Show container status"
	@echo "  make logs s=kafka   - Tail logs (service name)"
	@echo "  make health         - Check health of all services"
	@echo "  make topics         - List Kafka topics"
	@echo "  make clean          - Remove all volumes (DESTRUCTIVE)"

setup:
	@echo "Setting up SOC Pipeline..."
	@chmod +x init/kafka/create-topics.sh
	@chmod +x init/opensearch/create-index-template.sh
	@echo "✓ Setup complete. Run: make up"

up:
	docker compose up -d

down:
	docker compose down

restart:
	docker compose restart

status:
	docker compose ps

logs:
	docker compose logs -f $(s)

health:
	@echo "Checking service health..."
	@docker compose exec kafka kafka-broker-api-versions --bootstrap-server localhost:9092 > /dev/null 2>&1 && echo "✓ Kafka OK" || echo "✗ Kafka DOWN"
	@docker compose exec redis redis-cli ping > /dev/null 2>&1 && echo "✓ Redis OK" || echo "✗ Redis DOWN"
	@docker compose exec postgres pg_isready -U socadmin -d socdb > /dev/null 2>&1 && echo "✓ PostgreSQL OK" || echo "✗ PostgreSQL DOWN"

topics:
	docker compose exec kafka kafka-topics --bootstrap-server localhost:9092 --list

clean:
	docker compose down -v
	@echo "All volumes removed"