# Repository Guidelines

## Project Structure & Module Organization
- `agent/`: Core multi-agent runtime (RDE) and tool framework; start at `agent/base.py`, `agent/core/`.
- `firmhive/`: Firmware-specific implementation: `blueprint.py` (workflow), `assistants.py`, `knowagent.py`, `tools.py`, `utils/`.
- `baselines/`: Baseline agents/pipelines used for comparisons.
- `scripts/`: Ready-to-run entrypoints (see below).
- Outputs go to `output/` for ad-hoc runs and `result/` for evaluations (both git-ignored).
- `exp/`: Curated experiment artifacts intended for paper submission.

## Build, Test, and Development Commands
- Install deps: `pip install -r requirements.txt` (requires `radare2`; `r2ghidra` recommended).
- Configure keys: `cp config.ini.template config.ini` then edit `[llm]` section.
- Dataset root (scripts): `export KARONTE_DATASET_DIR=/path/to/karonte_dataset`.
- Run FirmHive (custom path):
  ```bash
  python -u firmhive/blueprint.py --search_dir /path/to/extracted_firmware --output ./output
  ```
- Run presets:
  ```bash
  bash scripts/run_hierarchical.sh
  bash scripts/run_baseline_agent.sh
  bash scripts/run_baseline_pipeline.sh
  ```

## Coding Style & Naming Conventions
- Python 3.8+, PEP 8, 4-space indentation; line length ~100.
- Names: `snake_case` for modules/functions, `CamelCase` for classes, `UPPER_CASE` for constants.
- Prefer type hints and concise docstrings for public functions and agent/tool interfaces.
- Keep domain logic in `firmhive/` and reusable runtime/tooling in `agent/`.

## Testing Guidelines
- No formal test suite yet. When adding tests, prefer `pytest` under `tests/` with files named `test_*.py`.
- Focus first on `firmhive/utils/` and tool wrappers; use small fixture firmware samples from `exp/` and temporary dirs.
- Example: `pytest -q` (optionally with `pytest-cov` for coverage reporting).

## Commit & Pull Request Guidelines
- Current history favors short topic commits. Prefer clearer, conventional subjects in imperative mood.
- Recommended format: `feat(firmhive): add verification report aggregator` or `fix(agent): handle r2 timeout`.
- PRs should include: purpose/motivation, runnable command example, before/after behavior, linked issues, and sample output snippets (e.g., `verification_report.md`).

## Security & Configuration Tips
- Never commit secrets; `config.ini` and outputs are already git-ignored. Use `config.ini.template` to share defaults.
- You can redact sensitive strings via message filters (see README "Message Filtering").
- Ensure `radare2` (and optionally `r2ghidra`) are installed and visible in `PATH` before running analyses.
