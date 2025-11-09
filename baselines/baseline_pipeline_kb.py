import os
import json
import time
from typing import Dict, List, Any, Optional, Type, Union
import argparse
import sys

from agent.base import BaseAgent
from agent.core.builder import build_agent, AgentConfig

from firmhive.utils.finder import find_firmware_root
from firmhive.utils.convert2md import convert_kb_to_markdown
from firmhive.knowagent import KnowledgeBaseAgent,QueryFindingsTool,ListUniqueValuesTool,StoreFindingsTool
from firmhive.tools import FlexibleContext,ExecutableTool,ShellExecutorTool,Radare2FileTargetTool,VulnerabilitySearchTool


FIRMWARE_EXPLORER_PROMPT = """
You are a firmware exploration agent. Your sole task is to explore the firmware file system based on the user's overall analysis goal and decide which file or directory should be analyzed in depth next.

Workflow:
1.  **Understand Goal**: Carefully read the user's core requirements to understand the ultimate purpose of the analysis (e.g., finding vulnerabilities, identifying hardcoded keys, etc.).
2.  **Explore**: Use tools to browse the file system.
3.  **Decide**: Based on your exploration and understanding of the overall goal, identify the most suspicious, relevant, or important file or directory currently.
4.  **Output**: Your final response **must** be only the relative path of your chosen target (relative to the firmware root directory).
    *   **Example**: If you decide to analyze `squashfs-root/usr/bin/httpd`, your final response should be `usr/bin/httpd`.
    *   If you believe all relevant targets have been identified, your final response should be `None`.
5.  **Do Not Analyze**: Your job is to **identify targets**, not to analyze them. Leave the actual analysis work to the next agent.

Note that you are analyzing the firmware file system on a local system, so it is strictly forbidden to mention or use absolute paths, avoid confusion, and do not analyze or modify the local file system.
All analysis and storage must be truly valid; do not make any guesses.
"""

FILE_ANALYZER_PROMPT = """
You are an expert file analysis agent. Your task is to receive a specific file path and perform an in-depth, comprehensive static analysis on it.

Workflow:
1.  **Focus on Target**: All your analysis should strictly revolve around the target provided to you.
2.  **Use Tools**: Employ all your analysis tools comprehensively to examine the file's content, structure, dependencies, and potential vulnerabilities.
3.  **Generate Report**: After completing the analysis, generate a detailed, structured analysis report. The report should clearly describe all your findings and support them with evidence.
4.  **Final Response Requirements**:
    *   Support all findings with concrete evidence, and detail the location and trigger conditions of the findings.
    *   Truthfully report any situations or difficulties where evidence is insufficient or uncertain.
    *   Each finding must include the following **core fields**:
    - **`description`**: A detailed description of the finding, which must include:
    * The specific manifestation of the issue and its trigger conditions.
    * The detailed taint propagation path, associated constraints, and details regarding boundary checks.
    * Potential attack vectors and exploitation methods.
    - **`link_identifiers`**: Specific NVRAM or ENV variable names, file paths, IPC socket paths, and custom shared function symbols.
    - **`location`**: Precise location (file:line_number function_name address)
    - **`code_snippet`**: Relevant code snippet
    - **`risk_score`**: Risk level (0.0-10.0)
    - **`confidence`**: Confidence of analysis (0.0-10.0)
    - **`notes`**: Other important information, including: assumptions requiring further verification, associated files or functions of the finding, suggested directions for subsequent analysis
    * Select a tool or 'finish' in the 'action' field, and provide parameters or the final response in 'action_input'.
"""

BASELINE_KB_SYSTEM_PROMPT = """
You are the firmware analysis knowledge base agent, responsible for efficiently and accurately handling the storage, querying, and relational analysis of firmware analysis findings. When there is no valid information or it is unrelated to user requirements, no storage or query operations are needed.

## **Preparation Before Querying**
**Before each specific query and storage operation, it is highly recommended to first use the `ListUniqueValues` tool to understand the overall status of the knowledge base:**
- Use `ListUniqueValues` to query the 'link_identifiers' field and check if there are potentially related findings. If so, proactively analyze them.
- Use `ListUniqueValues` to query the 'notes' field to get remark information and see if there are associations.
- Use `ListUniqueValues` to query the 'file_path' field to understand the scope of analyzed files.

This exploratory analysis helps to:
- Precisely construct subsequent query conditions.
- Discover potential relational clues.
- Avoid missing important information.
- Improve query efficiency and accuracy.

## Tool Usage Guide

### 1. Store Findings (StoreStructuredFindings)
- **Purpose**: Store structured analysis findings into the knowledge base.
- **Key Requirements**:
  - Establish relational links by storing keyword lists with the same meaning.
  - Detail the conditions and constraints triggering the issue in the `description`.
  - Use `link_identifiers` and `notes` to establish cross-file relationships.
  - If you discover more credible and deeper findings through associated findings, you must proactively store these findings, especially taint propagation between components to determine complete vulnerability chains.

### 2. Query Findings (QueryFindings)
- **Purpose**: Query findings in the knowledge base based on specific conditions.
- **Best Practices**:
  - **Pre-query Exploration**: First use `ListUniqueValues` to understand the range of queryable values, such as `link_identifiers`.
  - Establish relationships through `link_identifiers` and `notes` fields.
  - Value matching only supports exact matching, not fuzzy matching.
  - **When Query is Empty**: Explicitly state "No relevant findings currently in the knowledge base; further analysis may be needed."

### 3. List Unique Values (ListUniqueValues)
- **Purpose**: Explore unique values for specific fields in the knowledge base.
- **Core Importance**: This is a necessary prerequisite for performing precise queries; otherwise, precise queries cannot be performed.
- **Application Scenarios**:
  - **Pre-query Preparation**: Understand the content distribution and available query conditions of the knowledge base.
  - By listing the `link_identifiers` field, discover associated keyword lists and check for relationships.
  - By listing the `notes` field, find associated findings and important context.
  - Identify duplicate or similar findings.

## **Strict Prohibitions**
1. **Prohibit fabrication of any information**: All findings must be based on actual code analysis results; no content not found in actual analysis may be added.
2. **Prohibit speculation and inference**: Only record findings supported by clear evidence; avoid uncertain words like "may," "seems," or "speculate."
3. **Accurately distinguish analysis status**: **"No findings"** ≠ **"No problems"**. An empty knowledge base indicates that analysis is incomplete or in preliminary stages.

Remember: Your work directly impacts the quality and efficiency of firmware security analysis. Maintain a professional, accurate, and systematic approach, and never fabricate or guess any information. When information is insufficient, honestly report the analysis status and limitations.
"""
class ExecutorAgent(BaseAgent):
    """System Analysis Agent (receives external Context, dependencies injected externally, includes tool execution environment and objects)"""

    def __init__(
        self,
        tools: Optional[List[Union[Type[ExecutableTool], ExecutableTool]]] = None,
        system_prompt: str = None,
        output_schema: Optional[Dict[str, Any]] = None,
        max_iterations: int = 50,
        history_strategy = None,
        context: Optional[FlexibleContext] = None,
        **extra_params: Any
    ):
        self.file_path = context.get("file_path") if context else None
        self.file_name = os.path.basename(self.file_path) if self.file_path else None
        self.current_dir = context.get("current_dir")

        self.messages_filters = [{'from': context.get('base_path'), 'to': '/'}, {'from': 'zxr', 'to': 'root'}] if context and context.get('base_path') else []
        
        super().__init__(
            tools=tools, 
            system_prompt=system_prompt, 
            output_schema=output_schema, 
            max_iterations=max_iterations, 
            history_strategy=history_strategy, 
            context=context,
            messages_filters=self.messages_filters,
            **extra_params
        )
        

class PipelineBaselineRunner:
    """
    Orchestrates a pipeline consisting of an explorer, analyzer, and knowledge base manager.
    """

    def __init__(
        self,
        firmware_root_path: str,
        output_dir: str,
        user_input: str,
        max_pipeline_cycles: int = 50,
        max_iterations_per_agent: int = 50
    ):
        if not os.path.isdir(firmware_root_path):
            raise ValueError(
                f"Firmware root path '{firmware_root_path}' does not exist or is not a directory."
            )

        self.firmware_root_path = os.path.abspath(firmware_root_path)
        self.output_dir = os.path.abspath(output_dir)
        self.user_input = user_input
        self.max_pipeline_cycles = max_pipeline_cycles
        self.analysis_duration = 0.0

        self.base_context = FlexibleContext(
            base_path=self.firmware_root_path,
            current_dir=self.firmware_root_path,
            output=self.output_dir,
            agent_log_dir=os.path.join(self.output_dir, "pipeline_baseline_with_kb"),
            user_input=self.user_input,
        )

        explorer_config = AgentConfig(
            agent_class=ExecutorAgent,
            tool_configs=[ShellExecutorTool, QueryFindingsTool, ListUniqueValuesTool],
            system_prompt=FIRMWARE_EXPLORER_PROMPT,
            max_iterations=max_iterations_per_agent,
        )
        self.explorer = build_agent(explorer_config, context=self.base_context)

        analyzer_config = AgentConfig(
            agent_class=ExecutorAgent,
            tool_configs=[
                ShellExecutorTool,Radare2FileTargetTool,VulnerabilitySearchTool,QueryFindingsTool,ListUniqueValuesTool
            ],
            system_prompt=FILE_ANALYZER_PROMPT,
            max_iterations=max_iterations_per_agent,
        )
        self.analyzer = build_agent(analyzer_config, context=self.base_context)

        kb_manager_config = AgentConfig(
            agent_class=KnowledgeBaseAgent,
            tool_configs=[StoreFindingsTool],
            system_prompt=BASELINE_KB_SYSTEM_PROMPT,
            max_iterations=max_iterations_per_agent,
        )
        self.kb_manager = build_agent(kb_manager_config, context=self.base_context)

    def run(self):
        start_time = time.time()
        print("Starting firmware analysis pipeline...")
        print(f"Overall user query: {self.user_input}")

        last_analysis_summary = "This is the first analysis."
        for i in range(self.max_pipeline_cycles):
            print(f"\nCycle {i + 1}/{self.max_pipeline_cycles}")

            print("Exploring firmware file system...")
            explorer_prompt = (
                f"User core requirement: {self.user_input}\n\n"
                f"Summary of last analysis:\n{last_analysis_summary}\n\n"
                "Based on the above information, please decide what is the next file or directory that should be analyzed in depth."
                "Your final response must be only the relative path of the target. If you believe the analysis is complete, respond with 'None'."
            )
            next_target = self.explorer.run(user_input=explorer_prompt)

            if 'none' in next_target.lower().strip():
                print("\nExplorer returned None. Analysis complete.")
                break
            
            target_path = next_target.strip().strip('"`')
            
            print(f"Analyzing file: '{target_path}'...")
            analyzer_prompt = (
                f"User core requirement: {self.user_input}\n\n"
                f"Please perform an in-depth, comprehensive static analysis on the following target: `{target_path}`\n"
                "Please return a string containing all findings, strictly following the format defined in your system prompt."
            )
            findings = str(self.analyzer.run(user_input=analyzer_prompt))
            self.analyzer.clear_messages(keep_system_message=True)

            last_analysis_summary = f"Analysis of '{target_path}' yielded no results." if findings == "None" else f"Analysis of '{target_path}' yielded the following results:\n{findings}"

            print("Storing findings...")
            store_prompt = (
                f"New analysis results are as follows:\n"
                f"{findings}\n\n"
                f"Based on the above analysis results, your current task is to store and organize the new analysis results (if they meet user requirements)."
                f"User's core requirement is: {self.user_input}\n"
            )
            self.kb_manager.run(user_input=store_prompt)
        
        else:
            print(f"\nMaximum cycles reached ({self.max_pipeline_cycles}). Stopping analysis.")

        self.analysis_duration = time.time() - start_time
        self.summary()

    def calculate_token_usage(self):
        """Calculates and returns the total token usage."""
        token_usage_file = os.path.join(self.output_dir, "token_usage.jsonl")
        if not os.path.exists(token_usage_file):
            return 0

        total_tokens = 0
        try:
            with open(token_usage_file, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        total_tokens += data.get('total_tokens', 0)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            print(f"Error calculating token usage: {e}")
        return total_tokens

    def generate_report(self):
        """Generates a Markdown analysis report."""
        print("\nStarting analysis report generation")
        kb_path = os.path.join(self.output_dir, 'knowledge_base.jsonl')
        if not os.path.exists(kb_path):
            msg = f"Knowledge base file '{kb_path}' does not exist, cannot generate report."
            print(msg)
            return None, msg

        try:
            success, msg_or_path = convert_kb_to_markdown(kb_path)
            if success:
                print(f"Successfully generated Markdown report: {msg_or_path}")
                return msg_or_path, None
            else:
                print(f"Failed to generate report: {msg_or_path}")
                return None, msg_or_path
        except Exception as e:
            error_msg = f"An unknown error occurred during report generation: {e}"
            print(error_msg)
            return None, error_msg

    def summary(self):
        """Creates and writes a summary.txt file."""
        report_path, _ = self.generate_report()
        total_tokens = self.calculate_token_usage()
        
        summary_path = os.path.join(self.output_dir, "summary.txt")
        summary_content = (
            f"Analysis Summary\n"
            f"Analysis Phase Duration: {self.analysis_duration:.2f} seconds\n"
            f"Total Model Token Usage: {total_tokens}\n"
        )
        try:
            with open(summary_path, 'w', encoding='utf-8') as f:
                f.write(summary_content)
            print(f"\nSummary information generated: {summary_path}")
            print(summary_content)
        except IOError as e:
            print(f"Could not write summary file {summary_path}: {e}")



if __name__ == "__main__":
    default_user_input = (
    "Perform a comprehensive security analysis of the firmware. The core objective is to identify and report "
    "complete, viable attack chains. ")
    
    parser = argparse.ArgumentParser(description="Firmware Analysis Pipeline (Baseline with KB)")
    parser.add_argument("--search_dir", type=str, required=True, help="Path to the directory to search for firmware root.")
    parser.add_argument("--output", type=str, default="output", help="Base directory for analysis output.")
    parser.add_argument("--user_input", type=str, default=default_user_input, help="User input/prompt for the analysis.")
    parser.add_argument("--max_cycles", type=int, default=50, help="Maximum number of analysis cycles.")

    args = parser.parse_args()

    firmware_root = find_firmware_root(args.search_dir)
    if not firmware_root:
        print(f"Error: Could not find a valid firmware root in '{args.search_dir}'.")
        sys.exit(1)

    print(f"Found firmware root at: {firmware_root}")

    dir_name = os.path.basename(os.path.normpath(args.search_dir))
    output_dir = os.path.join(args.output, dir_name)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    print(f"Output will be saved to: {output_dir}")


    pipeline_runner = PipelineBaselineRunner(
        firmware_root_path=firmware_root,
        output_dir=output_dir,
        user_input=args.user_input,
        max_pipeline_cycles=args.max_cycles
    )
    
    pipeline_runner.run()