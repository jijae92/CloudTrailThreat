SHELL := /bin/bash
PYTHON := python3.11
VENV := .venv
ACTIVATE := source $(VENV)/bin/activate

.PHONY: up install scan scan-safe test deploy clean

up: $(VENV)/bin/activate

$(VENV)/bin/activate:
	$(PYTHON) -m venv $(VENV)
	$(ACTIVATE) && pip install --upgrade pip && pip install -r requirements.txt

install: up

scan: up
	$(ACTIVATE) && python -m scanner --template templates/app-sam.yaml --source functions/vulnerable --format json --out artifacts/scan.json

scan-safe: up
	$(ACTIVATE) && python -m scanner --template templates/app-sam.yaml --source functions/safe --format json --out artifacts/scan_safe.json

test: up
	$(ACTIVATE) && pytest -q

deploy: up
	$(ACTIVATE) && sam build && sam deploy --guided

clean:
	rm -rf $(VENV) artifacts/scan*.json .pytest_cache
