# FirmHive

## Architecture At A Glance
- Recursive Delegation Engine (RDE): Agents form a dynamic tree (directory → file → function). Delegation is explicit via Assistant tools and can be parallelized.
- Proactive Knowledge Hub (PKH): A dedicated agent stores and queries structured findings, enabling cross‑file linking and reuse.
- ReAct‑style Tooling: Agents decide actions each turn (`tool`/`wait`/`finish`) and call tools with typed parameters, receiving concrete evidence back into the context.
- Asynchronous Execution: Long‑running operations can run in the background (`run_in_background: true`), and agents can `wait` to merge results, reducing end‑to‑end latency on large scans.

## Execution Model
1) The top‑level script builds a master agent from the blueprint (`firmhive/blueprint.py`).
2) Agents iterate with a JSON schema: think → choose `action` → pass `action_input` → receive tool result → continue or `finish`.
3) Delegation is just another tool call: `TaskDelegator`/`ParallelTaskDelegator` create sub‑agents with their own context, tools, prompts, and iteration budgets.
4) Background jobs: when a tool is marked `is_background_task`, the agent records it and may use `wait` later to join results.
5) PKH: findings are summarized and stored via the KnowledgeBase agent/tools; other agents can query the KB to connect evidence.

## Blueprint Customization (`firmhive/blueprint.py`)
- Layers: adjust how many levels (e.g., directory/file/function) and which assistant performs delegation.
- Prompts: per‑layer system prompts tailor behavior (strict file scope, function call‑chain tracing, etc.).
- Tools: assign different tool sets per layer (filesystem vs. binary analysis vs. KB operations).
- Parallelization: switch delegators to parallel variants for breadth; keep terminal agents focused on tool work.
- Budgets: per‑agent `max_iterations`, timeouts, and context paths (logs, output subdirs).

### Blueprint Examples (2‑Layer A/B, 3‑Layer C)
Pseudocode to convey the idea (constraints + dynamism), not full API calls.

```text
// A) Two‑Layer, Sequential (Conservative)
cfg_A:
  L1 (Directory): DeepDirectoryAnalysisAssistant -> L0
  L0 (Terminal):  DeepFileAnalysisAssistant
  include_kb: false
  max_iterations: 30
  tools per layer: whitelisted, fixed prompts

// B) Two‑Layer, Parallel (Broad & Fast)
cfg_B:
  L1 (Directory): ParallelDeepDirectoryAnalysisDelegator -> L0   // parallel dirs
  L0 (Terminal):  ParallelDeepFileAnalysisDelegator               // parallel files
  include_kb: true
  max_iterations: 40
  tip: sub‑agents may set run_in_background:true to overlap work

// C) Three‑Layer (Dir → File → Terminal)
cfg_C:
  L2 (Directory): ParallelDeepDirectoryAnalysisDelegator -> L1
  L1 (File):      ParallelDeepFileAnalysisDelegator -> L0
  L0 (Terminal):  DeepFileAnalysisAssistant
  include_kb: true
  max_iterations: 50
```

Effects & Guarantees:
- Predictable constraints: fixed prompts + tool whitelists per layer; bounded by per‑agent `max_iterations` → reproducible & debuggable.
- Dynamic behavior: agents decide whether/when to delegate, choose parallel vs. sequential, and can use `run_in_background:true`; PKH (if enabled) adds cross‑file recall without breaking layer isolation.
- A: Lowest overhead, small images finish quickly; good for smoke tests.
- B: High coverage and speed on large trees via parallelism; still bounded by budgets.
- C: Adds a file coordination layer for breadth+depth while keeping decisions local and explainable.

## Setup
- Python 3.8+
- radare2 (latest); optional: `r2pm init && r2pm install r2ghidra`
- Deps: `pip install -r requirements.txt`
- Dataset root (anonymized):
```bash
export KARONTE_DATASET_DIR=/path/to/karonte_dataset
```

## Run
- Hierarchical (our system):
```bash
bash scripts/run_hierarchical.sh --T5_COMPREHENSIVE_ANALYSIS
```

## Results
- Location: `results/<METHOD>/<TASK>/<FIRMWARE>/`
- Artifacts include: `knowledge_base.jsonl/md`, `verification_results.jsonl`, `verification_report.md`.

### Task Index
- T5 (Comprehensive Analysis): final, validated vulnerability reports live under:
  - `results/T5_COMPREHENSIVE_ANALYSIS/<FIRMWARE>/verification_report.md`
  - Detailed evidence: `verification_results.jsonl`; initial candidates: `knowledge_base.*`
- Other tasks (T1–T4): follow the same pattern under `results/<TASK>/...`.
