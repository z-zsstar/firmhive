# FirmHive

## 1. Project Overview

`FirmHive` is a recursive agent hive. The core of our system lies in its ability to dynamically generate a Tree of Agents (ToA) to adaptively solve complex analysis tasks, supported by a Proactive Knowledge Hub (PKH) for collective reasoning.

Main directories:
- `agent/`: Contains the fundamental building blocks for all agents.
- `firmhive/`: Implements the core logic of the FirmHive system.

## 2. The Role of the Knowledge Hub (KB)

A critical component of any long-term analysis system is the ability to maintain state and context. In complex, multi-step tasks like firmware analysis, an agent's limited context window can lead to the **loss of crucial intermediate findings**. For example, a password discovered in an early step might be forgotten and not included by the time the agent summarizes all key findings at the end.

The **Knowledge Hub (KB)**, and specifically our Proactive Knowledge Hub (PKH), solves this problem by acting as an external, persistent memory. It allows agents to:
- **Preserve Key Findings**: Agents can proactively offload important discoveries to the KB, preventing them from being lost as the conversation history grows.
- **Enable Collective Reasoning**: In a multi-agent setting, the shared KB becomes a central point for information exchange, allowing one agent's discovery to inform another's strategy.
- **Correlate Disparate Information**: It facilitates the connection of seemingly unrelated pieces of information gathered from different files and at different times, which is essential for uncovering complex, cross-component vulnerabilities.

## 3. Directory and File Descriptions

Here is a detailed breakdown of the key files and directories:

### 📂 `agent/` - Agent Foundations
This directory contains the generic components shared by all agents in our system and the baselines.

- `agent/base.py`: Defines the `BaseAgent` class, which serves as the abstract base for all agents. It implements the fundamental ReAct (Reasoning and Acting) loop, state management, and interaction with tools.
- `agent/core/`: Contains the core implementation of our **Recursive Delegation Engine (RDE)**. It handles the logic for an agent to dynamically spawn and manage sub-agents, forming the Tree of Agents (ToA). This is a cornerstone of FirmHive's architecture.

### 📂 `firmhive/` - The FirmHive System
This directory contains the specialized components that constitute the FirmHive system itself.

- `firmhive/blueprint.py`: Central to FirmHive's domain-specific adaptation. It defines the **Hierarchical Blueprint** for firmware analysis (e.g., Directory Layer -> File Layer -> Call-Chain Layer). For each layer, it specifies agent configurations, including system prompts, available tools, and maximum recursion depth.
- `firmhive/knowagent.py`: Implements the **Proactive Knowledge Agent** and its interaction protocols. This agent manages the Proactive Knowledge Hub (PKH), defining how agents `store`, `query`, and `explore` structured findings. It embodies the collective memory of the hive.
- `firmhive/assitants.py`: Contains implementations of specialized agents defined in the blueprint, such as `DirectoryAnalyzer`, `FileAnalyzer`, and `FunctionAnalyzer`.
- `firmhive/tools.py`: Defines the basic tools available to agents, such as file system operations (`ls`, `cat`, `file`) and binary analysis wrappers (`radare2`).

### 📂 `eval/` - Evaluation Scripts
This directory contains the Python scripts for running the baseline comparisons and ablation studies presented in our paper.

- `eval/baseline_agent.py`: Implements the **SRA (Single ReAct Agent)** baseline.
- `eval/baseline_agent_kb.py`: Implements the **SRA+KB (Single ReAct Agent with Knowledge Base)** baseline.
- `eval/baseline_pipeline.py`: Implements the **MAS (Multi-Agent System)** baseline with a static, pre-defined workflow.
- `eval/baseline_pipeline_kb.py`: Implements the **MAS+KB (Multi-Agent System with Knowledge Base)** baseline, our strongest baseline.
- `eval/no_kb.py`: A script for running the ablation study of FirmHive **without** the Knowledge Hub; the absence of a knowledge base often causes the top-level agent to lose a large number of key findings during higher-level communication.
- `eval/passive_kb.py`: A script for running the ablation study of FirmHive with a **passive** Knowledge Hub.

### 📂 `scripts/` - Execution Scripts
This directory provides convenient shell scripts to run all evaluations.

- `scripts/run_hierarchical.sh`: **(Main Evaluation)** Executes the full FirmHive system.
- `scripts/run_baseline_*.sh`: A set of scripts to run the four baseline agent architectures.
- `scripts/run_verification.sh`: Executes the vulnerability verification stage on a given set of findings.

## 4. Evaluations

### Prerequisites

1.  Clone the repository and navigate into the project directory.
2.  Install Python dependencies:
    ```bash
    pip install -r requirements.txt
    ```
3.  Set up your LLM API key in `config.ini`.
4.  **Important:** To run the evaluations, edit the shell scripts in `scripts/` (e.g., `run_hierarchical.sh`, `run_baseline_*.sh`) to set the internal `FIRMWARE_BASE_DIR` variable to the root path where your firmware samples are located (e.g., `FIRMWARE_BASE_DIR="./firmware_dataset"`).

### Viewing Results

All analysis results, including those from our FirmHive system and all baselines, are stored in the `results/` directory. The structure is as follows:

```
results/
└── <METHOD_NAME>/
    └── <TASK_NAME>/
        └── <FIRMWARE_DIRECTORY_NAME>/
            └── ... (analysis logs and findings)
```

-   **`<METHOD_NAME>`**: The analysis method.
    -   `Hierarchical`: **Our system (FirmHive)**.
    -   `BaselineAgent`: SRA (Single ReAct Agent) baseline.
    -   `BaselineAgentKB`: SRA with Knowledge Base.
    -   `BaselinePipeline`: MAS (Multi-Agent System) baseline.
    -   `BaselinePipelineKB`: MAS with Knowledge Base.
-   **`<TASK_NAME>`**: The task performed, e.g., `T1_HARDCODED_CREDENTIALS`.
-   **`<FIRMWARE_DIRECTORY_NAME>`**: The directory name of the analyzed firmware sample.

For the comprehensive analysis task (`T5_COMPREHENSIVE_ANALYSIS`), you can find the detailed **vulnerability exploration and verification reports** from our system in the following directory:
`results/Hierarchical/T5_COMPREHENSIVE_ANALYSIS/`