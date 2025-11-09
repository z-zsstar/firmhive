# FirmHive

FirmHive is a hierarchical multi‑agent framework for automated firmware analysis. This branch is an anonymized, artifact‑ready release focused on the framework itself: how agents collaborate, how the blueprint configures the system, and how tools are orchestrated.

## Architecture At A Glance
- Recursive Delegation Engine (RDE): Agents form a dynamic tree (directory → file → function). Delegation is explicit via Assistant tools and can be parallelized.
- Proactive Knowledge Hub (PKH): A dedicated agent stores and queries structured findings, enabling cross‑file linking and reuse.
- ReAct‑style Tooling: Agents decide actions each turn (`tool`/`wait`/`finish`) and call tools with typed parameters, receiving concrete evidence back into the context.
- Asynchronous Execution: Long‑running operations can run in the background (`run_in_background: true`), and agents can `wait` to merge results, reducing end‑to‑end latency on large scans.

## Code Map (Key Entry Points)
- Core Runtime
  - `agent/base.py`: BaseAgent loop (JSON schema I/O, tool execution, background jobs, message filters).
  - `agent/core/assistants.py`: Delegation tools (`TaskDelegator`, `ParallelTaskDelegator`) that spawn sub‑agents.
  - `agent/core/builder.py`: `AgentConfig`/`AssistantToolConfig` and `build_agent` factory for wiring agents + tools.
  - `agent/tools/basetool.py`: Tool interface (`ExecutableTool`) and shared `FlexibleContext`.
- Firmware Implementation
  - `firmhive/blueprint.py`: The configurable system blueprint (layers, prompts, tools, parallelization).
  - `firmhive/assistants.py`: Domain‑specific assistants (directory/file/function delegators and analyzers).
  - `firmhive/knowagent.py`: PKH agent and tools (store/query findings across the run).
  - `firmhive/tools.py`: Analysis tools (filesystem, radare2/r2ghidra wrappers, shell helpers).
  - `firmhive/utils/`: Utilities (finder, KB loader, report helpers).
- Scripts & Outputs
  - `scripts/run_hierarchical.sh`: Launch hierarchical analysis with task presets.
  - `scripts/run_baseline_*.sh`: Baseline agents/pipelines under `eval/`.
  - Outputs: `results/<METHOD>/<TASK>/<FIRMWARE>/` (`knowledge_base.*`, `verification_*.*`).

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
Minimal sketches showing how to assemble constrained‑yet‑dynamic blueprints using the same primitives as `firmhive/blueprint.py`.

```python
from agent.core.builder import AgentConfig, AssistantToolConfig, build_agent
from firmhive.blueprint import (
  create_file_analysis_config,
  ExecutorAgent,
  DEFAULT_WORKER_EXECUTOR_SYSTEM_PROMPT,
)
from firmhive.assistants import (
  ParallelDeepDirectoryAnalysisDelegator,
  ParallelDeepFileAnalysisDelegator,
  DeepDirectoryAnalysisAssistant,
  DeepFileAnalysisAssistant,
)
from firmhive.tools import GetContextInfoTool, ShellExecutorTool, Radare2FileTargetTool

# A) Two‑Layer, Sequential (Conservative)
file_cfg_A = create_file_analysis_config(include_kb=False, max_iterations=30)
terminal_A = AgentConfig(
  agent_class=ExecutorAgent,
  tool_configs=[
    GetContextInfoTool, ShellExecutorTool, Radare2FileTargetTool,
    AssistantToolConfig(assistant_class=DeepFileAnalysisAssistant, sub_agent_config=file_cfg_A), # sequential file analysis
  ],
  system_prompt=DEFAULT_WORKER_EXECUTOR_SYSTEM_PROMPT,
  max_iterations=30,
)
cfg_A = AgentConfig(
  agent_class=ExecutorAgent,
  tool_configs=[
    GetContextInfoTool, ShellExecutorTool,
    AssistantToolConfig(assistant_class=DeepDirectoryAnalysisAssistant, sub_agent_config=terminal_A), # sequential dirs
  ],
  system_prompt=DEFAULT_WORKER_EXECUTOR_SYSTEM_PROMPT,
  max_iterations=30,
)

# B) Two‑Layer, Parallel (Broad & Fast)
file_cfg_B = create_file_analysis_config(include_kb=True, max_iterations=40)
terminal_B = AgentConfig(
  agent_class=ExecutorAgent,
  tool_configs=[
    GetContextInfoTool, ShellExecutorTool, Radare2FileTargetTool,
    AssistantToolConfig(assistant_class=ParallelDeepFileAnalysisDelegator, sub_agent_config=file_cfg_B), # parallel files
  ],
  system_prompt=DEFAULT_WORKER_EXECUTOR_SYSTEM_PROMPT,
  max_iterations=40,
)
cfg_B = AgentConfig(
  agent_class=ExecutorAgent,
  tool_configs=[
    GetContextInfoTool, ShellExecutorTool,
    AssistantToolConfig(assistant_class=ParallelDeepDirectoryAnalysisDelegator, sub_agent_config=terminal_B), # parallel dirs
  ],
  system_prompt=DEFAULT_WORKER_EXECUTOR_SYSTEM_PROMPT,
  max_iterations=40,
)

# C) Three‑Layer (Dir → File → Terminal)
file_cfg_C = create_file_analysis_config(include_kb=True, max_iterations=50)
terminal_C = AgentConfig(
  agent_class=ExecutorAgent,
  tool_configs=[GetContextInfoTool, ShellExecutorTool, Radare2FileTargetTool,
    AssistantToolConfig(assistant_class=DeepFileAnalysisAssistant, sub_agent_config=file_cfg_C)],
  system_prompt=DEFAULT_WORKER_EXECUTOR_SYSTEM_PROMPT,
  max_iterations=50,
)
mid_file_level = AgentConfig(
  agent_class=ExecutorAgent,
  tool_configs=[GetContextInfoTool, ShellExecutorTool,
    AssistantToolConfig(assistant_class=ParallelDeepFileAnalysisDelegator, sub_agent_config=terminal_C)],
  system_prompt=DEFAULT_WORKER_EXECUTOR_SYSTEM_PROMPT,
  max_iterations=50,
)
cfg_C = AgentConfig(
  agent_class=ExecutorAgent,
  tool_configs=[GetContextInfoTool, ShellExecutorTool,
    AssistantToolConfig(assistant_class=ParallelDeepDirectoryAnalysisDelegator, sub_agent_config=mid_file_level)],
  system_prompt=DEFAULT_WORKER_EXECUTOR_SYSTEM_PROMPT,
  max_iterations=50,
)

# Build with your context
# agent = build_agent(cfg_A, context=your_context)
```

Effects & Guarantees:
- Predictable Constraints: Each layer has fixed prompts and whitelisted tools; per‑agent `max_iterations` bounds execution. This makes behavior reproducible and debuggable.
- Dynamic Behavior: Within those bounds, agents choose when to delegate, whether to use parallel delegators, and can set `run_in_background: true` to overlap work. PKH (when enabled) adds cross‑file context without breaking isolation.
- A: Deterministic, lowest overhead; ideal for quick, small‑image scans.
- B: Broader coverage and faster on large trees (parallel dirs/files); still bounded by per‑layer budgets.
- C: Adds an intermediate file layer to coordinate terminal workers, balancing breadth and depth while keeping decisions local and explainable.

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

