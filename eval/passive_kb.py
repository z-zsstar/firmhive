import os
import sys
import json
import time
import argparse
from typing import Dict, List, Any, Optional, Type, Union

from agent.base import BaseAgent
from agent.core.assitants import BaseAssistant, ParallelBaseAssistant
from agent.core.builder import build_agent, AgentConfig, AssistantToolConfig

from firmhive.utils.finder import find_firmware_root

from firmhive.knowagent import KnowledgeBaseAgent
from firmhive.tools import FlexibleContext, ExecutableTool, ShellExecutorTool, Radare2Tool, GetContextInfoTool, VulnerabilitySearchTool
from firmhive.assitants import ParallelFunctionDelegator,ParallelDeepFileAnalysisDelegator,ParallelDeepDirectoryAnalysisDelegator,DeepFileAnalysisAssistant,DeepDirectoryAnalysisAssistant,ParallelDeepFileAnalysisDelegator,ParallelDeepDirectoryAnalysisDelegator

SHARED_RESPONSE_FORMAT_BLOCK = """
Each finding must include the following **core fields**:
- **`description`**: A detailed description of the finding, which must include:
* The specific manifestation of the issue and its trigger conditions.
* The detailed taint propagation path, associated constraints, and details regarding boundary checks.
* Potential attack vectors and exploitation methods.

- **`link_identifiers`**: Specific NVRAM or ENV variable names, file paths, IPC socket paths, and custom shared function symbols.
- **`location`**: Precise location of the code sink or key logic. 
- **`code_snippet`**: Return the complete relevant code snippet.
- **`risk_score`**: Risk score (0.0-10.0).
- **`confidence`**: Confidence of analysis in the finding's accuracy and exploitability.  (0.0-10.0).
- **`notes`**: For human analysts. Including: assumptions requiring further verification, associated files or functions, suggested directions for subsequent analysis.

#### Note
- Strictly prohibit fabricating any information; it must be based on actual evidence obtained by tools. If tools cannot obtain evidence, report it truthfully and explain the lack of information. Strictly prohibit making any unsubstantiated guesses.
"""

DEFAULT_WORKER_EXECUTOR_SYSTEM_PROMPT = f"""
You are a firmware file system static analysis agent. Your task is to explore and analyze based on the current analysis focus (a specific directory). Please concentrate on the current focus. When you believe your analysis of it is complete or no further progress can be made, proceed to the next task or end the task.

Working Method:

1. **Understand Requirements**
   * Always focus on the current analysis object or specific task, while also referring to the user's overall or initial requirements.
   * Carefully understand the firmware content and goals the user currently wants to analyze. Do not omit directories and files that meet the user's requirements, unless you are very certain they do not.
   * If user requirements are unclear, choose the best analysis path based on firmware characteristics and appropriately break down complex tasks, making reasonable calls to analysis assistants.

2. **Formulate an Analysis Plan**
   * Choose the best analysis path based on firmware characteristics.
   * For complex tasks, break them down into multiple sub-tasks with clear objectives and steps, and reasonably invoke analysis assistants and tools.
   * Reasonably adjust the analysis plan based on assistant feedback to ensure accuracy and completeness. If an assistant fails to complete a task, reformulate the analysis plan. If after two attempts, the assistant still fails, proceed to the next task.

3. **Handling Issues During Analysis**
   * Record technical challenges and specific difficulties encountered during the analysis process.
   * Evaluate the degree of impact of issues in the actual firmware environment.
   * Use certain tools cautiously to avoid excessively long results, which could directly lead to analysis failure, e.g., the `strings` tool.

4. **Submitting Analysis Results**
   * Summarize all analysis results and respond to questions corresponding to the current task.
   * Truthfully report any situations where evidence is insufficient or uncertainty exists (what evidence is missing, what information is missing).

**Core Workflow:**

1. **Understand Requirements**
   * Always focus on specific tasks, while also referring to the user's overall or initial requirements. Note that if the task does not match the current analysis focus, you need to stop the analysis and provide timely feedback to the user. Please do not perform cross-directory analysis.
   * Carefully understand the firmware content and goals the user currently wants to analyze. Do not omit directories and files that meet the user's requirements, unless you are very certain they do not. If user requirements are unclear, choose the best analysis path based on firmware characteristics, break down complex tasks, and reasonably invoke analysis assistants.

2.  **Understand Context**: Use tools to precisely understand your current analysis focus and location.

3.  **Delegate Tasks**: When in-depth analysis is required, call the corresponding analysis assistant:
    *   **Explore Directory**: Use a subdirectory analysis assistant or its parallel version to switch to the specified directory for analysis.
    *   **Analyze File**: Use a file analysis assistant or its parallel version to analyze the specified file.

4.  **Summarize and Complete**: After completing all analysis tasks for the current focus, summarize your findings. If all tasks are complete, use the `finish` action to conclude.

*   Select a tool in the 'action' field or 'finish', and provide parameters or the final response in 'action_input'.
"""

DEFAULT_TOOL_CLASSES: List[Union[Type[ExecutableTool], ExecutableTool]] = [
    GetContextInfoTool, ShellExecutorTool, Radare2Tool, VulnerabilitySearchTool
]

DEFAULT_FILE_SYSTEM_PROMPT = f"""
You are a dedicated file analysis agent. Your task is to deeply analyze the currently specified file and provide detailed, evidence-backed analysis results. Please focus on the current target file or current specific task. When you believe the analysis is complete or no further progress can be made, proceed to the next task or end the task.

**Working Principles:**
- **Evidence-based**: All analysis must be based on actual evidence obtained from tools; baseless speculation is prohibited.
- **Result Validation**: Critically evaluate the results returned by called sub-tasks (e.g., function analysis), always verifying their authenticity and reliability to avoid false results contaminating the final conclusion.
- **Impact Assessment**: When security issues are found, clearly state their trigger conditions and assess their actual security impact in conjunction with the firmware's operating environment.

**Workflow:**
1. **Understand Task**: Focus on the specific task for the current file analysis, and fully refer to the user's overall requirements. Note that if the task does not match the current analysis focus, you need to stop the analysis and provide timely feedback to the user. Please do not perform cross-directory analysis.
2. **Execute Analysis**: Note that your analysis must have a certain depth. For complex tasks, break them down into multiple sub-tasks with clear objectives and steps, and reasonably invoke analysis assistants or tools sequentially or in parallel. Choose the most suitable tool or assistant to obtain evidence. For complex call chains, use `FunctionAnalysisDelegator` and provide detailed taint information and context. Use certain tools cautiously to avoid excessively long results, which could directly lead to analysis failure, e.g., the `strings` tool.
3. **Complete and Report**: After the analysis is complete, use the `finish` action and submit your final report strictly in the following format.

**Final Response Requirements**:
*   Respond to all questions corresponding to the current task.
*   Support all findings with concrete evidence, and truthfully report any lack of evidence or difficulties.
{SHARED_RESPONSE_FORMAT_BLOCK}
*   Select a tool in the 'action' field or 'finish', and provide parameters or the final response in 'action_input'.
"""

DEFAULT_FUNCTION_SYSTEM_PROMPT = """
You are a specialized function call chain analysis assistant. Your core responsibility is to trace the flow path of tainted data within the current function. Please focus on the current function. When you believe the analysis is complete or no further progress can be made, proceed to the next task or end the task.

**Working Principles:**
- All analysis is based on actual evidence, without baseless speculation.
- When issues are found, clearly state their location, trigger conditions, and potential impact.

**Analysis Process:**
1.  **Focus on Current Function**:
    *   Analyze the function code, understand its parameters, return values, and how it processes incoming tainted data.

2.  **Taint Flow Judgment and Decision**:
    *   **Does taint flow into a sub-function?**
        *   **Yes**: Create a delegated task for that sub-function. In the task description, you must clearly specify:
            1.  **Target Function**: The address of the sub-function to be analyzed.
            2.  **Tainted Parameter**: Which parameter is tainted.
            3.  **Taint Transformation**: What processing or transformation the tainted data underwent before being passed.
        *   **No**: If the tainted data is eliminated in the current function, or not passed to a sub-function, terminate the analysis for this path.

3.  **Analysis Depth Control**:
    *   When tainted data has undergone sufficient validation and sanitization (e.g., strict boundary checks), tracing can be stopped.
    *   For known secure library function calls or complex situations that cannot be analyzed, stop delving deeper and report the current status.

4.  **Summarize Results**: 
    *   After all path analyses are complete, summarize the final results, including the complete taint propagation path, discovered vulnerabilities, and use `finish` to end the task.
"""

class ExecutorAgent(BaseAgent):
    """System analysis agent (receives external Context, depends on external injection, includes tool execution environment and objects)"""

    def __init__(
        self,
        tools: Optional[List[Union[Type[ExecutableTool], ExecutableTool]]] = None,
        system_prompt: str = DEFAULT_WORKER_EXECUTOR_SYSTEM_PROMPT,
        output_schema: Optional[Dict[str, Any]] = None,
        max_iterations: int = 25,
        history_strategy = None,
        context: Optional[FlexibleContext] = None,
        **extra_params: Any
    ):
        self.file_path = context.get("file_path") if context else None
        self.file_name = os.path.basename(self.file_path) if self.file_path else None
        self.current_dir = context.get("current_dir")

        tools_to_pass = tools if tools is not None else DEFAULT_TOOL_CLASSES
        self.messages_filters = [{'from': context.get('base_path')+os.path.sep, 'to': ''}, {'from': 'user', 'to': 'root'}] if context and context.get('base_path') else []
        
        super().__init__(
            tools=tools_to_pass, 
            system_prompt=system_prompt, 
            output_schema=output_schema, 
            max_iterations=max_iterations, 
            history_strategy=history_strategy, 
            context=context,
            messages_filters=self.messages_filters,
            **extra_params
        )

class PlannerAgent(BaseAgent):
    """File analysis agent (receives external Context, depends on external injection, includes tool execution environment and objects), and stores results after analysis."""

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

        kb_context = context.copy()
        kb_log_dir = os.path.join(context.get("output"), "KnowledgeBase_Storage_logs")
        kb_context.set("agent_log_dir", kb_log_dir)

        self.kb_storage_agent = KnowledgeBaseAgent(context=kb_context)
        tools_to_pass = tools if tools is not None else DEFAULT_TOOL_CLASSES
        self.messages_filters = [{'from': context.get('base_path')+os.path.sep, 'to': ''}, {'from': 'user', 'to': 'root'}] if context and context.get('base_path') else []
        
        super().__init__(
            tools=tools_to_pass, 
            system_prompt=system_prompt, 
            output_schema=output_schema, 
            max_iterations=max_iterations, 
            history_strategy=history_strategy, 
            context=context,
            messages_filters=self.messages_filters,
            **extra_params
        )
   
    def run(self, user_input: str = None) -> Any:

        findings = str(super().run(user_input=user_input))
        
        store_prompt = (
            f"New analysis results are as follows:\n"
            f"{findings}\n\n"
            f"Based on the above analysis results, your current task is to store and organize the new analysis results (if they meet user requirements)."
            f"User core requirement is: {self.context.get('user_input', 'Not provided')}\n"
        )
        self.kb_storage_agent.run(user_input=store_prompt)

        return findings
    
    
FUNCTION_ANALYSIS_TOOLS = [Radare2Tool]

def _create_nested_call_chain_config(max_iterations: int) -> AgentConfig:
    """Helper function to create a 4-layer configuration for ParallelStepAssistant.
       Each layer (L0-L2) uses ParallelStepAssistant to delegate to the next layer.
       All layers use the same system prompt focused on call chain analysis.
    """
    internal_l3_cfg = AgentConfig(
        agent_class=ExecutorAgent, 
        tool_configs=FUNCTION_ANALYSIS_TOOLS, 
        system_prompt=DEFAULT_FUNCTION_SYSTEM_PROMPT, 
        max_iterations=max_iterations
    )

    l2_delegator_tool = AssistantToolConfig(
        assistant_class=ParallelFunctionDelegator, 
        sub_agent_config=internal_l3_cfg, 
    )
    internal_l2_agent_tools = [*FUNCTION_ANALYSIS_TOOLS, l2_delegator_tool]
    internal_l2_cfg = AgentConfig(
        agent_class=ExecutorAgent, 
        tool_configs=internal_l2_agent_tools, 
        system_prompt=DEFAULT_FUNCTION_SYSTEM_PROMPT, 
        max_iterations=max_iterations
    )

    l1_delegator_tool = AssistantToolConfig(
        assistant_class=ParallelFunctionDelegator, 
        sub_agent_config=internal_l2_cfg, 
    )
    internal_l1_agent_tools = [*FUNCTION_ANALYSIS_TOOLS, l1_delegator_tool]
    internal_l1_cfg = AgentConfig(
        agent_class=ExecutorAgent,  
        tool_configs=internal_l1_agent_tools, 
        system_prompt=DEFAULT_FUNCTION_SYSTEM_PROMPT, 
        max_iterations=max_iterations
    )

    l0_delegator_tool = AssistantToolConfig(
        assistant_class=ParallelFunctionDelegator, 
        sub_agent_config=internal_l1_cfg, 
    )
    internal_l0_agent_tools = [*FUNCTION_ANALYSIS_TOOLS, l0_delegator_tool]
    internal_l0_cfg = AgentConfig(
        agent_class=ExecutorAgent, 
        tool_configs=internal_l0_agent_tools,
        system_prompt=DEFAULT_FUNCTION_SYSTEM_PROMPT, 
        max_iterations=max_iterations
    )

    return internal_l0_cfg



def create_file_analyze_config(
    max_iterations: int = 25,
    main_system_prompt: Optional[str] = None, 
    sub_level_one_system_prompt: Optional[str] = None,
    sub_level_two_system_prompt: Optional[str] = None, 
    sub_level_three_system_prompt: Optional[str] = None, 
) -> AgentConfig:
    """
    Blueprint for coordinating deep file analysis tasks (4 layers + Knowledge Base assistant + nested parallel call chain).
    L0: Planner (delegates)
    L1: Executor/Delegator (default tools + delegation + hierarchical KB manager if included)
    L2: Executor/Delegator (default tools + delegation + call chain analysis)
    L3: Executor (specific stage tools + call chain analysis)
    """
    effective_main_prompt = main_system_prompt or DEFAULT_FILE_SYSTEM_PROMPT

    final_sub_level_one_prompt = sub_level_one_system_prompt or DEFAULT_FILE_SYSTEM_PROMPT
    final_sub_level_two_prompt = sub_level_two_system_prompt or DEFAULT_FILE_SYSTEM_PROMPT
    final_sub_level_three_prompt = sub_level_three_system_prompt or DEFAULT_FILE_SYSTEM_PROMPT
    
    base_l3_tools: List[Union[Type[ExecutableTool], ExecutableTool]] = DEFAULT_TOOL_CLASSES.copy()


    nested_call_chain_sub_agent_config = _create_nested_call_chain_config(max_iterations)
    call_chain_assistant_tool_cfg = AssistantToolConfig(
        assistant_class=ParallelFunctionDelegator, 
        sub_agent_config=nested_call_chain_sub_agent_config,
    )

    l3_tools_with_cca = [*base_l3_tools, call_chain_assistant_tool_cfg]
    l3_agent_cfg = AgentConfig(
        agent_class=ExecutorAgent,
        tool_configs=l3_tools_with_cca, 
        system_prompt=final_sub_level_three_prompt,
        max_iterations=max_iterations
    )

    l2_tool_configs: List[Union[Type[ExecutableTool], AssistantToolConfig]] = [
        *DEFAULT_TOOL_CLASSES.copy(),
        VulnerabilitySearchTool(),
        call_chain_assistant_tool_cfg, 
        AssistantToolConfig(
            assistant_class=BaseAssistant,
            sub_agent_config=l3_agent_cfg,
        ),
        AssistantToolConfig(
            assistant_class=ParallelBaseAssistant,
            sub_agent_config=l3_agent_cfg,
        )
    ]
    l2_agent_cfg = AgentConfig(
        agent_class=ExecutorAgent,
        tool_configs=l2_tool_configs,
        system_prompt=final_sub_level_two_prompt,
        max_iterations=max_iterations
    )

    l1_tool_configs: List[Union[Type[ExecutableTool], AssistantToolConfig]] = [
        *DEFAULT_TOOL_CLASSES.copy(),
        VulnerabilitySearchTool(),
        AssistantToolConfig(
            assistant_class=BaseAssistant,
            sub_agent_config=l2_agent_cfg,
        ),
        AssistantToolConfig(
            assistant_class=ParallelBaseAssistant,
            sub_agent_config=l2_agent_cfg,
        )
    ]


    l1_agent_cfg = AgentConfig(
        agent_class=ExecutorAgent,
        tool_configs=l1_tool_configs,
        system_prompt=final_sub_level_one_prompt,
        max_iterations=max_iterations
    )
    
    l0_delegators: List[Union[Type[ExecutableTool], AssistantToolConfig]] = [
        GetContextInfoTool,
        AssistantToolConfig(
            assistant_class=BaseAssistant,
            sub_agent_config=l1_agent_cfg,
            description="Can interact with files to perform specific file analysis tasks."
        ),
        AssistantToolConfig(
            assistant_class=ParallelBaseAssistant,
            sub_agent_config=l1_agent_cfg,
            description="Each assistant can interact with files to execute multiple file analysis sub-tasks in parallel."
        )
    ]

    l0_final_tool_configs: List[Union[Type[ExecutableTool], AssistantToolConfig]] = [*l0_delegators]

    file_analyzer_config = AgentConfig(
        agent_class=PlannerAgent,
        tool_configs=l0_final_tool_configs,
        system_prompt=effective_main_prompt, 
        max_iterations=max_iterations
    )
    return file_analyzer_config


def create_firmware_analysis_blueprint(
    max_levels: int = 5,
    max_iterations_per_agent: int = 25,
) -> AgentConfig:
    """
    Creates a multi-layered, planner-executor nested firmware analysis agent configuration.
    Each planning level (Lx_planner) guides an Lx_executor.
    The Lx_executor explores its assigned directory and uses assistants to:
    - Delegate file analysis (Deep File Analysis Assistant -> Generic File Analyzer Config)
    - Delegate subdirectory analysis (Recursive Directory Analysis Assistant -> Deeper Layer Planner Config)
    The executor of the deepest planner level delegates subdirectories to a terminal executor.
    """
    if max_levels < 1:
        raise ValueError("max_levels must be at least 1.")

    file_analyzer_config = create_file_analyze_config(
        max_iterations=max_iterations_per_agent,
    )
    
    terminal_worker_config = AgentConfig(
        agent_class=ExecutorAgent,
        tool_configs=[
            GetContextInfoTool,
            ShellExecutorTool,
            AssistantToolConfig(
                assistant_class=DeepFileAnalysisAssistant,
                sub_agent_config=file_analyzer_config,
            ),
            AssistantToolConfig(
                assistant_class=ParallelDeepFileAnalysisDelegator,
                sub_agent_config=file_analyzer_config,
            )
        ],
        system_prompt=DEFAULT_WORKER_EXECUTOR_SYSTEM_PROMPT,
        max_iterations=max_iterations_per_agent
    )

    for _ in range(max_levels - 1, -1, -1):
        worker_tools = [
            GetContextInfoTool,
            ShellExecutorTool,
            AssistantToolConfig(
                assistant_class=DeepFileAnalysisAssistant,
                sub_agent_config=file_analyzer_config,
            ),
            AssistantToolConfig(
                assistant_class=DeepDirectoryAnalysisAssistant,
                sub_agent_config=terminal_worker_config,
            ),
            AssistantToolConfig(
                assistant_class=ParallelDeepFileAnalysisDelegator,
                sub_agent_config=file_analyzer_config,
            ),
            AssistantToolConfig(
                assistant_class=ParallelDeepDirectoryAnalysisDelegator,
                sub_agent_config=terminal_worker_config, 
            )
        ]
        
        current_worker_system_prompt = DEFAULT_WORKER_EXECUTOR_SYSTEM_PROMPT

        current_worker_config = AgentConfig(
            agent_class=ExecutorAgent,
            tool_configs=worker_tools,
            system_prompt=current_worker_system_prompt,
            max_iterations=max_iterations_per_agent
        )

        terminal_worker_config = current_worker_config

    return terminal_worker_config 

class FirmwareMasterAgent: 
    def __init__(
        self,
        firmware_root_path: str,
        output_dir: str,
        user_input: str,
        max_levels_for_blueprint: int = 5,
        max_iterations_per_agent: int = 25,
        agent_instance_name: Optional[str] = "FirmwareMasterAgent"
    ):
        if not os.path.isdir(firmware_root_path):
            raise ValueError(f"Firmware root path '{firmware_root_path}' does not exist or is not a directory.")
        
        self.firmware_root_path = os.path.abspath(firmware_root_path)
        self.output_dir = os.path.abspath(output_dir)
        self.user_input = user_input
        self.analysis_duration = 0.0

        self.context = FlexibleContext(
            base_path=self.firmware_root_path,
            current_dir=self.firmware_root_path,
            output=self.output_dir,
            agent_log_dir=os.path.join(self.output_dir, f"{agent_instance_name}_logs"),
            user_input=self.user_input
        )

        master_agent_config = create_firmware_analysis_blueprint(
            max_levels=max_levels_for_blueprint,
            max_iterations_per_agent=max_iterations_per_agent
        )
        
        self.master_agent = build_agent(master_agent_config, context=self.context)

    def run(self) -> str:
        initial_task = (
            f"Please perform a comprehensive analysis of the firmware, combining the user's core requirements. Currently located in firmware directory: {os.path.basename(self.firmware_root_path)}, user's core requirement is: {self.user_input} "
            f"Please start from this directory and delve into files and subdirectories layer by layer."
        )
        start_time = time.time()
        analysis_summary = self.master_agent.run(user_input=initial_task)
        end_time = time.time()
        self.analysis_duration = end_time - start_time
        print(f"Initial analysis completed, took {self.analysis_duration:.2f} seconds")
        
        self.summary()
        return analysis_summary

    def generate_report(self):
        """Generates a Markdown analysis report."""
        print("\nStarting analysis report generation")
        kb_path = os.path.join(self.output_dir, 'knowledge_base.jsonl')
        if not os.path.exists(kb_path):
            print(f"Knowledge base file '{kb_path}' does not exist, cannot generate report.")
            return None, "Knowledge base file does not exist"

        try:
            from firmhive.utils.convert2md import convert_kb_to_markdown
            success, msg_or_path = convert_kb_to_markdown(kb_path)
            if success:
                print(f"Successfully generated Markdown report: {msg_or_path}")
                return msg_or_path, None
            else:
                print(f"Failed to generate report: {msg_or_path}")
                return None, msg_or_path
        except ImportError:
            error_msg = "Could not import report generation tool, skipping Markdown report generation."
            print(error_msg)
            return None, error_msg
        except Exception as e:
            error_msg = f"An unknown error occurred during report generation: {e}"
            print(error_msg)
            return None, error_msg

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

    def summary(self):
        """Creates and writes a summary.txt file. Each call regenerates the report and overwrites the summary."""
        report_path, _ = self.generate_report()
        total_tokens = self.calculate_token_usage()
        
        summary_path = os.path.join(self.output_dir, "summary.txt")
        summary_content = (
            f"Analysis and Verification Summary\n"
            f"Analysis Phase Duration: {self.analysis_duration:.2f} seconds\n"
            f"Total Model Token Usage: {total_tokens}\n"
        )
        try:
            with open(summary_path, 'w', encoding='utf-8') as f:
                f.write(summary_content)
            print(f"\nSummary information updated: {summary_path}")
            print(summary_content)
        except IOError as e:
            print(f"Could not write summary file {summary_path}: {e}")

if __name__ == "__main__":
    import time
    default_user_input = (
    "Perform a comprehensive security analysis of the firmware. The core objective is to identify and report "
    "complete, viable attack chains. ")
    
    parser = argparse.ArgumentParser(description="Firmware Analysis Master Agent (Ablation: Passive KB, No Verification)")
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

    master_agent = FirmwareMasterAgent(
        max_levels_for_blueprint=5,
        firmware_root_path=firmware_root,
        output_dir=output_dir,
        user_input=args.user_input
    )
    master_agent.run()