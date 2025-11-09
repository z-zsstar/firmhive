import os
import time
import json
from typing import Dict, List, Any, Optional, Type, Union
import argparse
import sys

from agent.base import BaseAgent
from agent.core.builder import build_agent, AgentConfig

from firmhive.utils.finder import find_firmware_root
from firmhive.utils.convert2md import convert_kb_to_markdown
from firmhive.tools import FlexibleContext, ExecutableTool, ShellExecutorTool, Radare2FileTargetTool, VulnerabilitySearchTool


FINDING_SCHEMA = {
    "type": "object",
    "properties": {
        "name": {
            "type": "string", 
            "description": "Define a unique identifier for the item. Suggested format: '<Type>-<Function/Module>-<Unique ID>'."
        },
        "description": {
            "type": "string",
            "description": "Detailed description of the finding, which must include: the specific manifestation and trigger conditions of the problem, detailed constraints and boundary check situations, potential security implications and exploitation methods."
        },
        "link_identifiers": {
            "type": "array",
            "items": {"type": "string"},
            "description": "A list of precise code identifiers, including: function names, variable names, macro definitions, configuration item names, file paths, protocol names, command strings, etc."
        },
        "location": {
            "type": "string",
            "description": "Precise location (file:line_number function_name address)."
        },
        "code_snippet": {
            "type": "string",
            "description": "Relevant code snippet."
        },
        "risk_score": {
            "type": "number",
            "description": "Risk level (0.0-10.0)."
        },
        "confidence": {
            "type": "number",
            "description": "Confidence of analysis (0.0-10.0)."
        },
        "notes": {
            "type": "string",
            "description": "For human analysts. Includes assumptions made, remaining questions, or suggestions for the next analysis step \n"
        }
    },
    "required": ["description", "location"]
}

FINAL_REPORT_SCHEMA = {
    "type": "array",
    "description": "The final report, containing a list of all findings. Each finding is a structured object.",
    "items": FINDING_SCHEMA
}


BASELINE_SYSTEM_PROMPT = """
You are a versatile firmware static analysis expert agent. Your task is to perform a comprehensive and in-depth static analysis of the firmware file system based on the user's core requirements.

# Core Workflow

1.  **Understand the Goal and Formulate a Plan**:
    *   First, deeply understand the user's overall needs and ultimate goal.
    *   Based on the goal, conceive a high-level analysis plan in your mind ('thought' field). Break down complex tasks into smaller, manageable steps. Detail your reasoning, strategic choices, and next actions.

2.  **Explore, Analyze, and Trace**:
    *   **Interact with the File System**: Use appropriate tools to explore the firmware. **Crucially: all shell commands are executed in the firmware's root directory.** Therefore, any path you provide must be relative to the root directory.
    *   **Deep File Analysis**: For files you deem important (such as binaries, configuration files, scripts), use your specialized analysis tools for in-depth research, such as disassembly, symbolic execution, or vulnerability database queries.
    *   **Taint Data Tracing**: When you identify potential external input sources (e.g., from network, NVRAM, or hardware interfaces), your core task is to trace the flow of this "tainted" data through the system. Follow this logic:
        *   Carefully analyze functions that receive input.
        *   Determine if tainted data is passed as parameters, return values, or via global variables to any child functions it calls.
        *   If data is passed, recursively analyze the next function. During this process, pay special attention to whether the data is validated, filtered, or transformed.
        *   If the data flow is interrupted (e.g., data is securely handled or no longer passed), or you believe it has reached a dangerous operation ("sink"), then end the current path tracing and summarize.
        *   Your goal is to find a **feasible** complete attack chain from "source" to "sink".

3.  **Finding Management**:
    *   When you discover any valuable information, immediately use the `save_finding` tool to structure and record it in the knowledge base.
    *   During the analysis, you can query the knowledge base at any time to correlate your stored findings for a broader perspective.

4.  **Reporting Results**:
    *   After completing all analysis steps or reaching the maximum number of iterations, you need to use the `finish` action to provide a comprehensive, detailed final report that directly addresses the user's core requirements.
    *   Your final report (`final_response`) **must** be a JSON list containing **all** findings you have identified throughout the analysis process.
    *   Each finding in the list must be a structured JSON object, following this format:
    - **`description`**: A concise summary of the vulnerability's data flow, structured as follows:
        * **`source`**: Where does the untrusted data come from? 
        * **`path`**: How does the data reach the sink? Mention key variables and functions.
        * **`sink`**: What is the dangerous function or operation? 
        * **`impact`**: What is the potential security risk?        
        - **`link_identifiers`**: Specific NVRAM or ENV variable names, file paths, IPC socket paths, and custom shared function symbols.
        - **`location`**: Precise location (file:line_number function_name address).
        - **`code_snippet`**: Relevant code snippet.
        - **`notes`**: For human analysts. Including: assumptions requiring further verification, associated files or functions, suggested directions for subsequent analysis.

    *   **Report Truthfully**: All your conclusions must be based on actual evidence returned by the tools. Guessing or unfounded assumptions are strictly forbidden. If you cannot determine something, clearly state the missing evidence or information.

# Guiding Principles

*   **Evidence-Based**: All conclusions must be substantiated by evidence.
*   **Context-Aware**: Always remember that you are analyzing a resource-constrained firmware environment, where the security model and risks differ from standard operating systems.
*   **Goal-Driven**: Always focus your analysis around the user's core requirements, avoiding unnecessary distractions.
*   **Think Before Acting**: Before taking any action (`action`), be sure to clearly plan your steps in your thought (`thought`).
"""

ALL_TOOLS: List[Union[Type[ExecutableTool], ExecutableTool]] = [
    ShellExecutorTool,
    Radare2FileTargetTool,
    VulnerabilitySearchTool,
]


class BaselineAgent(BaseAgent):
    """A single, general-purpose baseline analysis Agent for experimental comparison."""

    def __init__(
        self,
        tools: Optional[List[Union[Type[ExecutableTool], ExecutableTool]]] = None,
        system_prompt: str = BASELINE_SYSTEM_PROMPT,
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


class FirmwareBaseline:
    """A wrapper class to drive the baseline Agent to complete firmware analysis tasks."""

    def __init__(
        self,
        firmware_root_path: str,
        output_dir: str,
        user_input: str,
        max_iterations_per_agent: int = 50,
        agent_instance_name: Optional[str] = "FirmwareBaselineAgent",
    ):
        if not os.path.isdir(firmware_root_path):
            raise ValueError(
                f"Firmware root path '{firmware_root_path}' does not exist or is not a directory."
            )

        self.firmware_root_path = os.path.abspath(firmware_root_path)
        self.output_dir = os.path.abspath(output_dir)
        self.user_input = user_input
        self.duration = 0.0

        _context = FlexibleContext(
            base_path=self.firmware_root_path,
            current_dir=self.firmware_root_path,
            output=self.output_dir,
            agent_log_dir=os.path.join(
                self.output_dir, f"{agent_instance_name}_logs"
            ),
            user_input=self.user_input,
        )

        agent_config = AgentConfig(
            agent_class=BaselineAgent,
            tool_configs=ALL_TOOLS,
            system_prompt=BASELINE_SYSTEM_PROMPT,
            max_iterations=max_iterations_per_agent,
        )

        self.agent = build_agent(agent_config, context=_context)

    def run(self, **kwargs) -> str:
        initial_task = (
            f"Please conduct a comprehensive analysis of the firmware, integrating the user's core query. "
            f"Currently located in the firmware directory: {os.path.basename(self.firmware_root_path)}, "
            f"the user's core query is: {self.user_input}. "
            f"Please start from this directory and delve into files and subdirectories layer by layer."
        )
        start_time = time.time()
        findings = self.agent.run(user_input=initial_task)
        end_time = time.time()
        self.duration = end_time - start_time
        
        # The final result returned by the Agent is the authoritative list of all findings.
        # We need to ensure it's correctly written to knowledge_base.jsonl for subsequent steps.
        if findings and isinstance(findings, list):
            kb_path = os.path.join(self.output_dir, "knowledge_base.jsonl")
            try:
                print(f"Writing final findings to knowledge base: {kb_path}")
                with open(kb_path, 'w', encoding='utf-8') as f:
                    for finding in findings:
                        f.write(json.dumps(finding, ensure_ascii=False) + '\n')
                print(f"Knowledge base successfully generated.")

            except Exception as e:
                print(f"Failed to save final report or generate knowledge base: {e}")
        
        self.summary()
        return findings

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

        if convert_kb_to_markdown is None:
            error_msg = "Could not import report generation tool `convert_kb_to_markdown`, skipping Markdown report generation."
            print(error_msg)
            return None, error_msg
            
        try:
            success, msg_or_path = convert_kb_to_markdown(kb_path)
            if success:
                print(f"Successfully generated Markdown report: {msg_or_path}")
                return msg_or_path, None
            else:
                print(f"Report generation failed: {msg_or_path}")
                return None, msg_or_path
        except Exception as e:
            error_msg = f"An unknown error occurred during report generation: {e}"
            print(error_msg)
            return None, error_msg

    def summary(self):
        """Creates and writes the summary.txt file."""
        report_path, _ = self.generate_report()
        total_tokens = self.calculate_token_usage()
        
        summary_path = os.path.join(self.output_dir, "summary.txt")
        summary_content = (
            f"Analysis Summary\n"
            f"Analysis phase duration: {self.duration:.2f} seconds\n"
            f"Total model token usage: {total_tokens}\n"
            f"Markdown report: {report_path if report_path else 'Generation failed'}\n"
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
    
    parser = argparse.ArgumentParser(description="Firmware Baseline Analysis Agent")
    parser.add_argument("--search_dir", type=str, required=True, help="Path to the directory to search for firmware root.")
    parser.add_argument("--output", type=str, default="output", help="Base directory for analysis output.")
    parser.add_argument("--user_input", type=str, default=default_user_input, help="User input/prompt for the analysis.")

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

    baseline_runner = FirmwareBaseline(
        firmware_root_path=firmware_root,
        output_dir=output_dir,
        user_input=args.user_input,
    )
    
    baseline_runner.run()