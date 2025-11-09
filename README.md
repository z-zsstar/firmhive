# FirmHive Artifact (Paper Version)

This branch provides the anonymized, artifact-ready version used for paper evaluation.

## Requirements
- Python 3.8+
- radare2 (latest recommended)
- r2ghidra (optional, improves decompilation)
- `pip install -r requirements.txt`

## Dataset Path (Anonymized)
Set the dataset root once to avoid hardcoded paths.
```bash
export KARONTE_DATASET_DIR=/path/to/karonte_dataset
```

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

## Outputs
- `result/` contains run outputs (knowledge_base.jsonl, verification_results.jsonl, verification_report.md).
- `exp/` contains curated results for the paper.

## Reproducibility Checklist
1) Copy `config.ini.template` → `config.ini` and set API keys.
2) Ensure `radare2` in PATH; to install r2ghidra: `r2pm init && r2pm install r2ghidra`.
3) `export KARONTE_DATASET_DIR=/path/to/karonte_dataset`.
4) Run scripts above; inspect `verification_report.md` under `result/<METHOD>/<TASK>/<FIRMWARE>/`.

## Notes
- This branch avoids personal paths/secrets and minimizes non-essential docs.
- For full architecture and extended docs, see the `main` branch.
