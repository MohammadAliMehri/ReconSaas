.PHONY: help install run web docker docker-down clean test

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-18s\033[0m %s\n", $$1, $$2}'

install: ## Install locally (pip install -e .)
	pip install -r requirements.txt
	pip install -e .

run: ## Run CLI scan (usage: make run TARGET=example.com MODE=hybrid)
	python -m recon_framework.cli --target $(TARGET) --mode $(MODE) -v

web: ## Run web UI locally on port 5000
	pip install flask gunicorn 2>/dev/null
	RECON_OUTPUT_DIR=./recon-output python -m flask --app recon_framework.web.app:create_app run --host 0.0.0.0 --port 5000 --debug

docker: ## Build and run with Docker Compose
	docker-compose up -d --build

docker-down: ## Stop Docker containers
	docker-compose down

docker-logs: ## View Docker logs
	docker-compose logs -f

test: ## Run test suite
	python -m pytest tests/ -v

clean: ## Remove output and cache
	rm -rf recon-output/ __pycache__/ .pytest_cache/ *.egg-info/ dist/ build/
