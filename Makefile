PYTHON ?= python3
VENV   ?= .venv
BIN     = $(VENV)/bin

.PHONY: help venv lint test check clean

help:
	@echo "venv   create .venv and install development dependencies"
	@echo "lint   ruff, yamllint and pymarkdown"
	@echo "test   run the test suite (compiles benign fixtures)"
	@echo "check  lint and test (what CI runs)"

venv:
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -r requirements-dev.txt
	$(BIN)/pip install -e .

lint:
	$(BIN)/ruff check .
	$(BIN)/ruff format --check .
	$(BIN)/yamllint -s .
	$(BIN)/pymarkdown --config .pymarkdown.json scan -r --exclude .venv --exclude .github .

test:
	$(BIN)/pytest

check: lint test

clean:
	rm -rf .pytest_cache .ruff_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
