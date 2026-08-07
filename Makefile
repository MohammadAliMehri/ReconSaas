.PHONY: help install test clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-18s\033[0m %s\n", $$1, $$2}'

install: ## Install locally (pip install -e .)
	pip install -r requirements.txt
	pip install -e .

test: ## Run test suite
	python -m pytest tests/ -v

clean: ## Remove output and cache
	rm -rf recon-output/ __pycache__/ .pytest_cache/ *.egg-info/ dist/ build/
