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

from firmhive.knowagent import StoreFindingsTool
from firmhive.tools import FlexibleContext,ExecutableTool,ShellExecutorTool,Radare2FileTargetTool,VulnerabilitySearchTool



FIRMWARE_EXPLORER_PROMPT = """
You are a firmware exploration agent. Your sole task is to explore the firmware file system based on the user's overall analysis goal, and decide the next file or directory that should be analyzed in depth.

Workflow:
1.  **Understand the Goal**: Carefully read the user's core requirements to understand the ultimate purpose of the analysis (e.g., finding vulnerabilities, identifying hardcoded keys).
2.  **Explore**: Use tools to browse the file system.
3.  **Decide**: Based on your exploration and understanding of the overall goal, identify the single most suspicious, relevant, or important file or directory currently.
4.  **Output**: Your final response **must** be only the relative path of your chosen target (relative to the firmware root directory).
    *   **Example**: If you decide to analyze the `usr/bin/httpd` file, your final response should be `usr/bin/httpd`.
    *   If you believe all relevant targets have been identified, your final response should be `None`.
5.  **Do Not Analyze**: Your job is to **find the target**, not to analyze it. Leave the actual analysis work to the next agent.
"""

FILE_ANALYZER_PROMPT = """
You are an expert file analysis agent. Your task is to receive a specific file path and perform an in-depth, comprehensive static analysis on it.

Workflow:
1.  **Focus on Target**: All your analysis should strictly revolve around the target provided to you.
2.  **Use Tools**: Employ all your analysis tools comprehensively to examine the file's content, structure, dependencies, and potential vulnerabilities.
3.  **Generate Report**: After completing the analysis, generate a detailed, structured analysis report. The report should clearly describe all your findings and support them with evidence.
4.  **Final Response Requirements**:
   * Support all findings with concrete evidence, and detail the location and trigger conditions of the findings.
   * Truthfully report any situations where evidence is insufficient or where certainty cannot be achieved, or any difficulties encountered.
   * Each finding must include the following **core fields**:
    - **`description`**: A detailed description of the finding, which must include:
    * The specific manifestation of the issue and its trigger conditions.
    * The detailed taint propagation path, associated constraints, and details regarding boundary checks.
    * Potential attack vectors and exploitation methods.
   
   - **`link_identifiers`**: A list of precise code identifiers, including:
   * Function names, variable names, macro definitions
   * Configuration item names, file paths
   * Protocol names, command strings
   * Data structure names, field names
   * Avoid using general terms and type descriptions; use specific code identifiers instead

   #### Optional Enhancement Fields
   - **`location`**: Precise location (file:line_number function_name address)
   - **`code_snippet`**: Relevant code snippet
   - **`relevance`**: Relevance to the user's core requirement (0.0-10.0)
   - **`risk_score`**: Risk level (0.0-10.0)
   - **`confidence`**: Analysis confidence (0.0-10.0)
   - **`notes`**: Other important information, including: assumptions needing further verification, associated files or functions found, suggested directions for subsequent analysis
   * Select a tool in the 'action' field or 'finish', and provide parameters or the final response in 'action_input'.
"""

FINDING_SCHEMA: Dict[str, Dict[str, Any]] = {
    "location": {
        "type": "string",
        "description": "Precise location of the code sink or key logic. Format: '<relative_file_path>:<line_number> [function_name] [address]'. Adapts to binary or script.\n"
    },
    "description": {
        "type": "string",
        "description": "A structured summary of the data flow, following the Source -> Path -> Sink model.\n"
    },
    "link_identifiers": {
        "type": "array",
        "items": {"type": "string"},
        "description": "List of specific identifiers (NVRAM vars, function names, file paths) that connect this finding to others. AVOID generic terms.\n"
    },
    "code_snippet": {
        "type": "string",
        "description": "The most relevant code snippet showing the sink or critical logic."
    },
    "type": {
        "type": "string",
        "description": "The most specific vulnerability classification. Use CWE ID if possible or use the following scope descriptors:\n"
                     "- single-file\n- across-file.If a finding fits multiple types, separate them with a comma (e.g., 'CWE-78, across-file').\n"
    },
    "risk_score": {
        "type": "number",
        "description": "Risk score (0.0-10.0)"
    },
    "confidence": {
        "type": "number",
        "description": "Confidence in the finding's accuracy and exploitability. (0.0-10.0)"
    },
    "notes": {
        "type": "string",
        "description": "For human analysts. Includes assumptions made, remaining questions, or suggestions for the next analysis step \n"
    }
}

FINAL_REPORT_SCHEMA = {
    "type": "array",
    "description": "Final report, containing a list of all findings. Each finding is a structured object.",
    "items": FINDING_SCHEMA
}


FINAL_REPORT_PROMPT = """
You are a senior security researcher, responsible for integrating analysis reports and generating final conclusions.

Your tasks are:
1.  **Review Initial Request**: Carefully read the user's original analysis requirements.
2.  **Synthesize Analysis Findings**: You will receive a series of findings from lower-level analysis agents. These findings are independent analysis results for different files and directories. Store these findings in the knowledge base.
3.  **Generate Final Report**: Based on all findings, write a comprehensive, coherent, and focused final report that directly addresses the user's initial request.
"""

ALL_TOOLS: List[Union[Type[ExecutableTool], ExecutableTool]] = [
    ShellExecutorTool,
    Radare2FileTargetTool,
    VulnerabilitySearchTool,
]

class ExecutorAgent(BaseAgent):
    """System analysis agent (receives external Context, depends on external injection, includes tool execution environment and objects)"""

    def __init__(
        self,
        tools: Optional[List[Union[Type[ExecutableTool], ExecutableTool]]] = None,
        system_prompt: str = None,
        output_schema: Optional[Dict[str, Any]] = None,
        max_iterations: int = 25,
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

class ReporterAgent(BaseAgent):
    """A single, all-in-one baseline analysis agent for experimental comparison."""

    def __init__(
        self,
        tools: Optional[List[Union[Type[ExecutableTool], ExecutableTool]]] = None,
        system_prompt: str = FINAL_REPORT_PROMPT,
        output_schema: Optional[Dict[str, Any]] = None,
        final_output_schema: Optional[Dict[str, Any]] = FINAL_REPORT_SCHEMA,
        max_iterations: int = 50,
        history_strategy=None,
        context: Optional[FlexibleContext] = None,
        **extra_params: Any,
    ):
        tools_to_pass = tools if tools is not None else ALL_TOOLS
        self.messages_filters = (
            [
                {"from": context.get("base_path"), "to": "/"},
                {"from": "zxr", "to": "root"},
            ]
            if context and context.get("base_path")
            else []
        )

        super().__init__(
            tools=tools_to_pass,
            system_prompt=system_prompt,
            output_schema=output_schema,
            final_output_schema=final_output_schema,
            max_iterations=max_iterations,
            history_strategy=history_strategy,
            context=context,
            **extra_params,
        )

class PipelineBaselineRunner:
    """
    Orchestrates a pipeline consisting of an explorer and an analyzer,
    and finally generates a summary report.
    """

    def __init__(
        self,
        firmware_root_path: str,
        output_dir: str,
        user_input: str,
        max_pipeline_cycles: int = 50,
        max_iterations_per_agent = 50
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
            agent_log_dir=os.path.join(self.output_dir, "pipeline_logs"),
            user_input=self.user_input,
        )

        explorer_config = AgentConfig(
            agent_class=ExecutorAgent,
            tool_configs=[ShellExecutorTool],
            system_prompt=FIRMWARE_EXPLORER_PROMPT,
            max_iterations=max_iterations_per_agent
        )
        self.explorer = build_agent(explorer_config, context=self.base_context)

        analyzer_config = AgentConfig(
            agent_class=ExecutorAgent,
            tool_configs=[
                ShellExecutorTool,Radare2FileTargetTool,VulnerabilitySearchTool
            ],
            system_prompt=FILE_ANALYZER_PROMPT,
            max_iterations=max_iterations_per_agent
        )
        self.analyzer = build_agent(analyzer_config, context=self.base_context)

        final_reporter_config = AgentConfig(
            agent_class=ReporterAgent,
            tool_configs=[StoreFindingsTool],
            system_prompt=FINAL_REPORT_PROMPT,
            max_iterations=25,
        )
        self.final_reporter = build_agent(final_reporter_config, context=self.base_context)

    def run(self):
        start_time = time.time()
        print(f"Overall user query: {self.user_input}")

        all_findings = []
        last_analysis_summary = "This is the first analysis."

        for i in range(self.max_pipeline_cycles):
            print(f"\n Cycle: {i + 1}/{self.max_pipeline_cycles}")

            print("Exploring firmware file system...")
            explorer_prompt = (
                f"User core requirement: {self.user_input}\n\n"
                f"Summary of last analysis:\n{last_analysis_summary}\n\n"
                "Based on the above information, please decide what the next most important file or directory to analyze is."
                "Your final response must be only the relative path of the target. If you think the analysis is complete, please reply 'None'."
            )
            next_target = self.explorer.run(user_input=explorer_prompt)

            if 'none' in next_target.lower().strip():
                print("\n Explorer returned None. Analysis complete.")
                break
            
            target_path = next_target.strip().strip('"`')

            print(f"Analyzing file: '{target_path}'...")
            analyzer_prompt = (
                f"User core requirement: {self.user_input}\n\n"
                f"Please perform an in-depth, comprehensive static analysis on the following target: `{target_path}`\n"
                "Please return the string containing all findings strictly according to the format defined in your system prompt."
            )
            findings = self.analyzer.run(user_input=analyzer_prompt)
            self.analyzer.clear_messages(keep_system_message=True)
            if not findings:
                print("    Analyzer returned empty result. Skipping.")
                last_analysis_summary = f"Analysis of '{target_path}' yielded no results."
                continue
            
            all_findings.append({
                "target": target_path,
                "findings": findings
            })

            findings_str = ""
            try:
                findings_str = json.dumps(findings, indent=2, ensure_ascii=False)
            except (TypeError, json.JSONDecodeError):
                findings_str = str(findings)

            last_analysis_summary = f"Analysis of '{target_path}' yielded the following results:\n{findings_str}"

        else:
            print(f"\n Maximum number of cycles reached ({self.max_pipeline_cycles}). Stopping analysis.")

        print("\nGenerating final report")
        if not all_findings:
            print("No findings were discovered, cannot generate report.")
            self.analysis_duration = time.time() - start_time
            self.summary()
            return

        all_findings_str = json.dumps(all_findings, indent=2, ensure_ascii=False)
        
        report_prompt = (
            f"User core requirement: {self.user_input}\n\n"
            "Here are all the findings we collected through multiple rounds of exploration and analysis:\n"
            f"{all_findings_str}\n\n"
            "Please generate a final comprehensive analysis report based on the above information."
        )
        
        final_report = self.final_reporter.run(user_input=report_prompt)

        print("\nFinal analysis report")
        print(final_report)

        if final_report and isinstance(final_report, list):
            kb_path = os.path.join(self.output_dir, "knowledge_base.jsonl")
            try:
                with open(kb_path, 'w', encoding='utf-8') as f:
                    for finding in final_report:
                        if isinstance(finding, dict):
                            f.write(json.dumps(finding, ensure_ascii=False) + '\n')
                print(f"Knowledge base saved to: {kb_path}")
            except Exception as e:
                print(f"Failed to save knowledge base: {e}")
        
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
    
    parser = argparse.ArgumentParser(description="Firmware Analysis Pipeline (Baseline)")
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