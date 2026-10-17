# Common tasks. Everything runs inside the local virtualenv.
PY ?= python3
VENV ?= .venv
BIN := $(VENV)/bin

.PHONY: install test lint format format-check check eval clean

$(BIN)/python:
	$(PY) -m venv $(VENV)

install: $(BIN)/python  ## install Hider in editable mode with the dev tools
	$(BIN)/pip install -e ".[dev]"

test:  ## run the test suite
	$(BIN)/python -m pytest

lint:  ## lint with ruff
	$(BIN)/ruff check .

format:  ## format with ruff and apply safe lint fixes
	$(BIN)/ruff format .
	$(BIN)/ruff check --fix .

format-check:  ## fail if anything is unformatted
	$(BIN)/ruff format --check .

check: lint format-check test  ## everything CI runs

eval:  ## measure redaction recall on the synthetic corpus (writes out/)
	$(BIN)/python -m hider eval

clean:  ## remove caches and generated output
	rm -rf out .pytest_cache .ruff_cache build dist *.egg-info
