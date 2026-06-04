.PHONY: install install-dev export-dataset train run-daemon test lint format clean help

PYTHON      := python3
PIP         := $(PYTHON) -m pip
ALERTS_PATH := /var/ossec/logs/alerts/alerts.json
CONFIG      := config/config.yaml

help:
	@echo ""
	@echo "  UEBA ML — Commandes disponibles"
	@echo "  ================================"
	@echo "  make install        Installer les dépendances"
	@echo "  make install-dev    Installer avec outils de dev (pytest, ruff...)"
	@echo "  make export-dataset Exporter dataset.csv depuis alerts.json"
	@echo "  make train          Exécuter le notebook d'entraînement"
	@echo "  make run-daemon     Lancer le daemon de détection temps réel"
	@echo "  make test           Lancer les tests unitaires"
	@echo "  make lint           Vérifier le style du code"
	@echo "  make format         Formater le code avec black"
	@echo "  make clean          Nettoyer les fichiers temporaires"
	@echo ""

install:
	$(PIP) install -e .

install-dev:
	$(PIP) install -e ".[dev]"

export-dataset:
	$(PYTHON) -m ueba.features.parse_logs $(ALERTS_PATH) \
		--output data/dataset.csv \
		--config $(CONFIG)

train:
	jupyter nbconvert \
		--to notebook \
		--execute notebooks/ueba_ml_pipeline.ipynb \
		--output notebooks/ueba_ml_pipeline_executed.ipynb

run-daemon:
	$(PYTHON) -m ueba.integration.daemon \
		--config $(CONFIG) \
		--verbose

test:
	$(PYTHON) -m pytest tests/ -v --cov=src/ueba --cov-report=term-missing

lint:
	$(PYTHON) -m ruff check src/ tests/

format:
	$(PYTHON) -m black src/ tests/ --line-length 100

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null; true
	find . -name "*.pyc" -delete 2>/dev/null; true
	rm -rf .pytest_cache .coverage htmlcov/ dist/ build/ *.egg-info/
	@echo "Nettoyage terminé"
