# AegisMem for Enterprise AI Customer Support - Makefile
# Reproducible execution commands for evaluation, demonstrations, and test suites.

PYTHON ?= python
SCENARIO ?= policy

.PHONY: all test demo seed attack load reproduce clean compose-up compose-down

all: test

test:
	$(PYTHON) -m pytest tests -q

demo:
	$(PYTHON) scripts/demo_end_to_end.py

seed:
	$(PYTHON) -m domain.customer_support.taxonomy

attack:
	$(PYTHON) -m attack_lab.adaptive_attacker --scenario $(SCENARIO)

load:
	$(PYTHON) evaluation/run_load_test.py

reproduce:
	$(PYTHON) evaluation/run_domain_benchmarks.py

compose-up:
	docker compose up --build -d

compose-down:
	docker compose down -v

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

