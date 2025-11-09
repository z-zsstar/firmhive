# FirmHive Artifact (Paper Version)

FirmHive is a hierarchical multi-agent system for automated firmware vulnerability analysis. This branch is the anonymized, artifact-ready release with runnable scripts and results.

## Highlights & Advantages
- Hierarchical Delegation (RDE): Dynamically spawns a tree of agents (directory → file → function), scaling to large firmware with fewer blind spots.
- Proactive Knowledge Hub (PKH): Structured, queryable memory to connect findings across agents and phases.
- Two-Phase Workflow: Explore widely to collect candidates, then Verify to confirm—reduces false positives and delivers high-precision reports.
- Configurable Agent Blueprint: In `firmhive/blueprint.py`, tune layers, prompts, tools, max-iterations, and delegation (sequential/parallel).
- Asynchronous ReAct Agents: Use `run_in_background: true` for heavy sub-tasks, continue reasoning, then `wait` to merge results—cuts latency on big scans.

## Repository Layout
- `agent/`: Core agent runtime and tool framework
- `firmhive/`: Blueprint, assistants, knowledge hub, tools, utils
- `eval/`: Baselines (Single Agent / Pipeline, with/without KB)
- `scripts/`: Reproduction scripts
- `results/`: Full run outputs (knowledge_base.jsonl/md, verification_results.jsonl, verification_report.md)
- `exp/`: Curated, compact reports included in the paper

## Requirements
- Python 3.8+
- radare2 (latest recommended); optional: install r2ghidra via `r2pm`
- Python deps: `pip install -r requirements.txt`

## Dataset (Anonymized)
Set the dataset root once to avoid hardcoded paths:
```bash
export KARONTE_DATASET_DIR=/path/to/karonte_dataset
```
Discovery expects: `<base>/<BRAND>/analyzed/<FIRMWARE>` (BRAND ∈ d-link, NETGEAR, Tenda, TP_Link).

## How To Run
- Our method (Hierarchical):
```bash
bash scripts/run_hierarchical.sh --T5_COMPREHENSIVE_ANALYSIS
```
- Baselines:
```bash
bash scripts/run_baseline_agent.sh
bash scripts/run_baseline_agent_kb.sh
bash scripts/run_baseline_pipeline.sh
bash scripts/run_baseline_pipeline_kb.sh
```

## Outputs & Reading Order
- Exploration: `knowledge_base.jsonl` / `knowledge_base.md`
- Verification: `verification_results.jsonl`, `verification_report.md` (start here)
- Path: `results/<METHOD>/<TASK>/<FIRMWARE>/`

## Reproduce
1) Copy `config.ini.template` → `config.ini` and set API keys
2) Ensure `radare2` in PATH; optionally install `r2ghidra`
3) `export KARONTE_DATASET_DIR=/path/to/karonte_dataset`
4) Run scripts; confirm outputs under `results/`

## Notes
- Branch is anonymized and focused on evaluation; full documentation lives on `main`.
