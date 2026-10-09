PY ?= python
.PHONY: install demo test bench ui
install: ; $(PY) -m pip install -r requirements.txt
demo: ; PY=$(PY) bash scripts/run_examples.sh
test: ; $(PY) -m pytest -q
bench: ; $(PY) benchmarks/impact_benchmark.py --runs 20
ui: ; streamlit run app.py
