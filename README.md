# HiveMind (FirmHive Implementation)

## Overview

**FirmHive** is an automated firmware vulnerability analysis system powered by LLM agents. It employs a hierarchical multi-agent architecture to systematically analyze firmware images, identify security vulnerabilities, and generate detailed, verified reports. It is the practical implementation of the HiveMind architecture described in our paper.

> **🌏 Chinese Version Available**: A fully localized Chinese version is available on the `hivemind_cn` branch. All system prompts, task descriptions, tool descriptions, and documentation have been translated to Chinese. To use it: `git checkout hivemind_cn`

### Key Features

- 🌳 **Recursive Delegation Engine (RDE)**: The core engine in `agent/core/` that dynamically spawns a tree of agents, enabling deep and broad analysis that adapts to the firmware's structure.
- 📚 **Proactive Knowledge Hub (PKH)**: A central knowledge base (`firmhive/knowagent.py`) that enables agents to store, query, and proactively link findings, creating a collective intelligence.
- ✅ **Two-Phase Analysis (Explore & Verify)**: A workflow that first explores the firmware to find a wide range of potential vulnerabilities and then launches a second, focused verification phase to filter out false positives and confirm findings.
- 🔧 **Customizable Analysis Blueprints**: The analysis strategy is not hardcoded. You can define your own hierarchical workflow, agent types, tools, and prompts in `firmhive/blueprint.py`.
- 🤖 **Specialized Agents**: A suite of agents in `firmhive/assitants.py` designed for specific tasks like directory traversal, file analysis, and deep binary function tracing.

## Project Structure

```
firmhive/
├── agent/                  # Core agent framework (The "Hive")
│   ├── base.py            # Core LLM/agent runtime, tool orchestration, async jobs
│   ├── core/              # 🏠 Recursive Delegation Engine (RDE) implementation
│   └── tools/             # Generic tool execution framework
│
├── firmhive/              # Domain-specific implementation for firmware analysis
│   ├── blueprint.py       # 🧬 Analysis hierarchy, agent configs, and system prompts
│   ├── knowagent.py       # 🧠 Proactive Knowledge Hub (PKH) agent
│   ├── assitants.py       # 🐝 Specialized analysis agents (directory, file, function)
│   └── tools.py           # 🛠️ Firmware analysis tools (fs, radare2 wrapper)
│
├── eval/                  # Evaluation & baseline agent implementations (SRA, MAS)
└── scripts/               # Execution scripts for running analysis and baselines
```

## Quick Start

### Prerequisites

- Python 3.8+
- [radare2](https://github.com/radareorg/radare2) (for binary analysis)
- [r2ghidra](https://github.com/radareorg/r2ghidra) (highly recommended for better decompilation)
- LLM API access (e.g., DeepSeek, OpenAI)

### Setup

```bash
# Install radare2 (Ubuntu/Debian example)
sudo apt-get install radare2

# For the latest version, install from source (recommended)
# git clone https://github.com/radareorg/radare2 && cd radare2 && sys/install.sh

# Install r2ghidra for superior decompilation quality
r2pm init
r2pm install r2ghidra

# Install Python dependencies
pip install -r requirements.txt

# Configure your LLM API key
cp config.ini.template config.ini
# Now, edit config.ini and add your API key and other settings.
```
**Why r2ghidra?** The Ghidra decompiler produces much more readable pseudo-code, which is critical for helping LLM agents understand complex binary logic. While `radare2` alone works, `r2ghidra` dramatically improves performance on binary analysis tasks.

### Run Your First Analysis

```bash
python -u firmhive/blueprint.py \
  --search_dir /path/to/extracted_firmware \
  --output ./output
```

## Understanding the Output

The analysis runs in two main phases: **Exploration** and **Verification**. The output directory reflects this.

### Output Structure

```
output/
├── knowledge_base.jsonl       # Raw candidates from the Exploration phase
├── knowledge_base.md          # Human-readable report of initial candidates
├── verification_results.jsonl # Detailed verification results (True/False for each candidate)
├── verification_report.md     # ⭐ FINAL REPORT: Summary of confirmed vulnerabilities
├── token_usage.jsonl          # LLM API usage and cost statistics
└── FirmwareMasterAgent_logs/  # Full, detailed message history for debugging
```

**Key takeaway**: Always start by reading `verification_report.md`. This file contains the final, high-confidence findings after the system has filtered out potential false positives.

### What to Expect During a Run

| Metric | Typical Range | Notes |
| :--- | :--- | :--- |
| **Analysis Time** | 30 mins - 2+ hours | Depends heavily on firmware size and complexity. |
| **Token Usage** | 5M - 50M tokens | Varies based on the number of files and analysis depth. |
| **Cost Estimate** | $1 - $10 USD | Using DeepSeek API. Monitor `token_usage.jsonl`. |
| **Initial Findings**| 10 - 100+ candidates| The Exploration phase is designed to be broad and will include false positives. |
| **Verified Findings**| ~20-50% of candidates| The Verification phase filters candidates down to a high-precision set of vulnerabilities. |

## Architecture Deep Dive

### The Hierarchical Blueprint (Fully Customizable)

**Current Configuration**: FirmHive is configured with a three-layer analysis strategy as a demonstration:

1. **Directory Layer**: Root agent surveys firmware structure
2. **File Layer**: Specialized agents analyze individual files (binaries, scripts, configs)
3. **Function Layer**: Binary analysis agents trace vulnerable code paths

**Flexible Design**: The blueprint in `firmhive/blueprint.py` is fully customizable. You can configure:
- 📊 **Number of Layers**: 2, 3, 4, or more hierarchical levels
- 💬 **System Prompts**: Task-specific instructions for each layer
- 🔄 **Max Iterations**: How deep each agent can recurse (per-layer control)
- 🛠️ **Tool Sets**: Which tools each layer's agents can access
- 🎯 **Agent Types**: Sequential, parallel, or mixed delegation strategies

The current three-layer setup is a powerful default but is just one example configuration. You can adapt it to your specific analysis needs by editing the `LAYER_CONFIGS` in the blueprint.

### Agent Scope Isolation

Each agent operates within a restricted scope:
- ✅ Can access: Current directory and all subdirectories (any depth)
- ❌ Cannot access: Parent directories, sibling directories
- 🔄 Escalation: Must report findings to parent agent for cross-scope analysis

### Asynchronous Task Execution (Experimental)

To accelerate analysis, FirmHive supports delegating tasks to **background jobs**:

```json
{
  "action": "ParallelDeepFileAnalysisDelegator",
  "action_input": {
    "file_names": ["file1.bin", "file2.sh"],
    "run_in_background": true  // ← This flag enables async execution
  }
}
```

**How it works**:
- Agents can delegate tasks to run in the background
- Parent agent continues other work while sub-agents analyze
- Results are collected and integrated asynchronously
- Reduces sequential waiting time and is crucial for analyzing large directories.

**⚠️ Experimental Feature**: This asynchronous mechanism has not been exhaustively tested. For maximum stability, you can disable it. If you encounter hangs, this is the first thing to check.

### Knowledge Hub

Agents proactively store and query findings:
- **Store**: Record vulnerabilities with structured metadata
- **Query**: Search for related findings across analysis sessions
- **Explore**: Discover connections between disparate discoveries

## Reproducing Evaluation Results

### Running Baselines

```bash
# Edit firmware path in scripts
vim scripts/run_hierarchical.sh  # Set FIRMWARE_BASE_DIR

# Run FirmHive (full system)
bash scripts/run_hierarchical.sh

# Run baselines
bash scripts/run_baseline_agent.sh        # SRA (Single ReAct Agent)
bash scripts/run_baseline_agent_kb.sh     # SRA + Knowledge Base
bash scripts/run_baseline_pipeline.sh     # MAS (Static Multi-Agent System)
bash scripts/run_baseline_pipeline_kb.sh  # MAS + Knowledge Base
```

### Results Location

All evaluation outputs are stored in the `results/` directory, organized by method.

```
results/
├── Hierarchical/              # ✅ FirmHive (our system)
│   └── <TASK>/<FIRMWARE>/
│       ├── knowledge_base.jsonl
│       ├── verification_report.md    # ⭐ Final verified findings are here
│       └── verification_results.jsonl
├── BaselineAgent/             # Single agent baseline
├── BaselineAgentKB/           # Single agent + KB
├── BaselinePipeline/          # Static multi-agent pipeline (MAS)
└── BaselinePipelineKB/        # Static multi-agent pipeline + KB (MAS+KB)
```

**Analysis Tip**: When comparing results, always use `verification_report.md` for FirmHive's final validated vulnerabilities, not the raw `knowledge_base.jsonl` of initial candidates.

## Customization and Configuration

### LLM API Configuration

Edit `config.ini`:

```ini
[llm]
api_key = your_api_key_here
model = deepseek-chat
base_url = https://api.deepseek.com
temperature = 0.0
```

### Message Filtering (Redacting Sensitive Data)

For security and privacy, you can add message filters to prevent leaking secrets (API keys, local paths) into logs or the LLM context. The agent runtime supports simple find/replace rules via the `messages_filters` argument.

```python
# Example: attach filters when constructing agents in blueprint.py
messages_filters = [
    {"from": "YOUR_REAL_API_KEY", "to": "REDACTED_API_KEY"},
    {"from": "/home/username/", "to": "/home/REDACTED/"},
    {"from": "192.168.", "to": "192.REDACTED."}
]
```

These rules are applied before messages are logged or sent to the LLM.

### Customizing the Analysis Blueprint

The entire hierarchical analysis workflow is defined in `firmhive/blueprint.py`. This is where you can exert the most control over the system's behavior.

#### What You Can Customize:
- **System Prompts** (line ~40 and in `LAYER_CONFIGS`): Define the core objective for each layer.
- **Layer Count**: The system is not limited to 3 layers—use 2, 4, or more.
- **Max Iterations**: Control agent recursion depth per layer (e.g., layer 1: 5 steps, layer 2: 15 steps).
- **Tool Sets**: Assign different tools to different layers (e.g., only file agents can use binary analysis tools).
- **Delegation Strategy**: Choose `sequential` (one-by-one) or `parallel` (concurrent) execution for child agents.
- **Knowledge Hub Prompts**: Modify prompts in `firmhive/knowagent.py` to change how agents store and retrieve information.

The default configuration is tuned for vulnerability hunting. If your goal is code review, compliance checking, or feature extraction, you should adapt these prompts and layer definitions.

## Example Output Snippets

### Initial Analysis Candidate (from `knowledge_base.jsonl`)

```json
{
  "name": "Hardcoded_Credentials_Admin",
  "location": "etc/config/default_config.xml line 42",
  "description": "Hardcoded admin credentials found in default configuration...",
  "code_snippet": "<admin><username>admin</username><password>admin123</password></admin>",
  "risk_score": 9.0,
  "confidence": 9.5,
  "file_path": "etc/config/default_config.xml"
}
```

### Verification Result (from `verification_results.jsonl`)

```json
{
  "name": "Hardcoded_Credentials_Admin",
  "is_real_vulnerability": true,
  "risk_level": "Critical",
  "detailed_reason": "Confirmed: The default credentials 'admin/admin123' are hardcoded in the default configuration file and are used for authentication without any mechanism to force a change.",
  "verification_duration": 45.2,
  "token_usage": 12450
}
```

**Key Difference**: The verification result provides a definitive confirmation (`is_real_vulnerability: true/false`) and should be your source of truth.

## Troubleshooting

### Common Issues

**radare2 not found**

```bash
# Verify radare2 installation
r2 -v

# Check r2ghidra installation (recommended)
r2pm -l | grep r2ghidra

# If r2ghidra not installed
r2pm init
r2pm install r2ghidra

# Test decompilation
echo 'int main() { return 0; }' | gcc -x c - -o /tmp/test
r2 -qc 'aa; pdg' /tmp/test
# Should show decompiled output
```

**API rate limits**
- Add delays in `agent/llmclient.py` if you hit rate limits
- Consider using a higher-tier API plan for large-scale analysis


## Important Notes

### Task Adaptation
This system is currently tuned for vulnerability discovery. If you adapt FirmHive for other tasks (like code summarization or compliance checking), be sure to adjust the system prompts in `firmhive/blueprint.py` to match your goals. Otherwise, agents may fail to recognize and preserve important findings.

### Asynchronous Execution
The `run_in_background` feature enables agents to delegate time-consuming tasks asynchronously. **This is an experimental feature** introduced to handle multi-agent collaboration overhead. We have not thoroughly tested this mechanism across all scenarios. If you encounter issues:
- Disable all async mechanisms.
- Adjust timeout values in agent configurations
- Report any bugs or unexpected behavior for future improvements

## Disclaimer

The vulnerability reports generated by this tool are for educational and research purposes only. We do not guarantee the accuracy or completeness of all findings. Please manually verify any reported vulnerabilities before taking corrective actions.

### For Best Results:

- **Read `verification_report.md` First**: This is the most important file. It contains the filtered, validated vulnerabilities. Start your review here.
- **Expect Initial False Positives**: The exploration phase casts a wide net by design. It is normal for 50-80% of initial candidates to be filtered out during verification.