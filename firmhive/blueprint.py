import os
import sys
import json
import time
import argparse
import threading

from typing import Dict, List, Any, Optional, Type, Union
from concurrent.futures import ThreadPoolExecutor, as_completed

from agent.base import BaseAgent
from agent.core.assistants import BaseAssistant, ParallelBaseAssistant
from agent.core.builder import build_agent, AgentConfig, AssistantToolConfig

from firmhive.utils.finder import find_firmware_root
from firmhive.utils.convert2md import load_knowledge_base
from firmhive.tools import FlexibleContext, ExecutableTool, GetContextInfoTool, ShellExecutorTool, Radare2Tool, Radare2FileTargetTool
    #  VulnerabilitySearchTool

from firmhive.knowagent import KnowledgeBaseAgent,QueryFindingsTool,ListUniqueValuesTool,StoreFindingsTool,DEFAULT_KB_SYSTEM_PROMPT
from firmhive.assistants import ParallelFunctionDelegator,ParallelDeepFileAnalysisDelegator,ParallelDeepDirectoryAnalysisDelegator,\
                            DeepFileAnalysisAssistant,DeepDirectoryAnalysisAssistant


DEFAULT_VERIFICATION_TASK_TEMPLATE = (
    "Your sole task is to strictly and objectively validate the following security alert. Your analysis must be entirely based on the provided evidence.\n\n"
    "**Core Principles**:\n"
    "1.  **Evidence-driven**: All assertions in the alert must be validated by analyzing the provided evidence. Guesswork or analyzing unrelated information and files is strictly prohibited.\n"
    "2.  **Logic Review**: Do not simply confirm the existence of the code; you must understand its execution logic. Carefully examine control flow statements, data sanitization, and other factors that determine reachability of code paths.\n"
    "3.  **Exploitation Verification**: Validate whether the vulnerability is **actually exploitable** by confirming:\n"
    "    - **Input Controllability**: The attacker can control the tainted input.\n"
    "    - **Path Reachability**: The vulnerable path is reachable under realistic conditions. In your analysis, clearly define and state the attacker model used for this vulnerability assessment (e.g., unauthenticated remote attacker, authenticated local user, etc.).\n"
    "    - **Practical Impact**: The operation can cause actual security harm.\n"
    "4.  **Complete Attack Chain**: - **Full path required**: Partial or conjectural paths are unacceptable. You must provide a complete, validated chain. The full propagation path from attacker-controlled input to the dangerous sink must be verified, supported by evidence at each step.\n\n"
    "**Note**: Function names in the alert may come from decompilation. Search thoroughly; do not hastily conclude that they do not exist just because they are not in the symbol table or strings.\n\n"
    "{verification_finding_details}\n"
)

DEFAULT_VERIFICATION_INSTRUCTION_TEMPLATE = (
    "{verification_task}\n"
    "**Provide a Conclusion**: At the end of your analysis, `final_response` must be a JSON object containing the following fields:\n"
    "    - `accuracy`: (string) Assessment of the alert's descriptive accuracy. Must be 'accurate', 'inaccurate', or 'partially'.\n"
    "    - `vulnerability`: (boolean) Whether the description is sufficient to constitute a real vulnerability. Must be True or False. Clearly explain the attacker assumptions on which you base your evaluation.\n"
    "    - `risk_level`: (string) If `vulnerability` is `true`, the risk level of the vulnerability. Must be 'Low', 'Medium', or 'High'.\n"
    "    - `reason`: (string) A detailed explanation supporting all the above conclusions. For findings confirmed as real vulnerabilities, this field must also include a reproducible attack payload or proof-of-concept (PoC) steps, clearly describing how to exploit the vulnerability.\n"
)


SHARED_RESPONSE_FORMAT_BLOCK = """
Each finding must include the following **core fields**:
- **`description`**: A detailed description of the finding, which must include:
* Specific manifestation and triggering conditions of the problem
* Detailed constraint and boundary check situations
* Potential attack and exploitation methods
* Relevant code logic or technical details

- **`link_identifiers`**: Specific NVRAM or ENV variable names, file paths, IPC socket paths, and custom shared function symbols to ensure accurate tracking of cross-file and cross-process data flow and interactions.
- **`location`**: Precise location (file:line_number function_name address)
- **`code_snippet`**: Return the complete relevant code segment, demonstrating vulnerability triggering conditions and exploitation methods.
- **`risk_score`**: Risk score (0.0-10.0). **Only findings with a complete, validated attack chain and clear security impact can score >= 7.0.**
- **`confidence`**: Confidence in the accuracy and exploitability analysis of the finding (0.0-10.0). **A score >= 8.0 requires a complete, verifiable attack chain from source to sink.**
- **`notes`**: Other important information for reference by human analysts, including: assumptions requiring further validation, associated files or functions of the finding, and recommended directions for further analysis.

#### Key Principles:
- **Exploitability is Mandatory**: If the user only requires reporting of actually exploitable attack chains, then theoretical weaknesses or bad practices (such as using `strcpy`) are not sufficient unless you can prove that they lead to a vulnerability.
- **Evidence Trumps Supposition**: All assertions must be supported by tool-generated evidence. If evidence is missing, state it explicitly. Do not speculate.
"""

DEFAULT_WORKER_EXECUTOR_SYSTEM_PROMPT = f"""
You are a firmware filesystem static analysis agent. Your task is to explore and analyze based on the current analysis focus (a specific directory). Please focus on the current focus, and when you believe your analysis of it is complete or cannot make further progress, continue to the next task or end the task.

Working Method:

1.  **Understand Requirements**
    *   Always focus on the current analysis object or specific task, while also referring to the user's overall or initial requirements.
    *   Carefully understand the firmware content and goals the user currently wants to analyze. Do not omit directories and files that meet user requirements unless you are very certain they do not.
    *   If user requirements are unclear, choose the best analysis path based on firmware characteristics, appropriately decompose complex tasks, and reasonably call analysis assistants.

2.  **Formulate Analysis Plan**
    *   Choose the best analysis path based on firmware characteristics.
    *   For complex tasks, decompose them into multiple sub-tasks with clear objectives and steps, and reasonably call analysis assistants and tools.
    *   Reasonably adjust the analysis plan based on assistant feedback to ensure the plan is accurate and complete. If the assistant cannot complete the task, reformulate the analysis plan. If the assistant still cannot complete the task after two attempts, proceed to analyze the next task.

3.  **Problem Handling during Analysis**
    *   Record technical difficulties and unique challenges encountered during the analysis.
    *   Assess the impact of the problem in the actual firmware environment.
    *   Use certain tools cautiously to avoid overly long results, which could lead to analysis failure, e.g., `strings` tool.

4.  **Submission of Analysis Results**
    *   Summarize all analysis results and answer questions corresponding to the current task.
    *   Truthfully report any situations or difficulties where evidence is insufficient or uncertain (what evidence is missing, what information is missing).

**Core Workflow:**

1.  **Understand Requirements**
    *   Always focus on the specific task, while also referring to the user's overall or initial requirements. Note that if the task does not match the current analysis focus, you need to stop the analysis and provide timely feedback to the user. Do not perform cross-directory analysis.
    *   Carefully understand the firmware content and goals the user currently wants to analyze. Do not omit directories and files that meet user requirements unless you are very certain they do not. If user requirements are unclear, choose the best analysis path based on firmware characteristics, decompose complex tasks, and reasonably call analysis assistants.

2.  **Understand Context**: Use tools to precisely understand your current analysis focus and location.

3.  **Delegate Tasks**: When in-depth analysis is required, call the appropriate analysis assistants:
    *   **Explore Directory**: Use subdirectory analysis assistant or its parallel version to switch to the specified directory for analysis.
    *   **Analyze File**: Use file analysis assistant or its parallel version to analyze the specified file.

4.  **Summarize and Complete**: After completing all analysis tasks for the current focus, summarize your findings. If all tasks are completed, use the `finish` action to end.

*   Select a tool or 'finish' in the 'action' field, and provide parameters or the final response in 'action_input'.
"""

DEFAULT_TOOL_CLASSES: List[Union[Type[ExecutableTool], ExecutableTool]] = [
    GetContextInfoTool, ShellExecutorTool, Radare2Tool
]


DEFAULT_FILE_SYSTEM_PROMPT = f"""
You are a dedicated file analysis agent. Your task is to deeply analyze the currently specified file and provide detailed, evidence-supported analysis results. Please focus on the current focal file or current specific task. When you believe your analysis is complete or cannot make further progress, continue to the next task or end the task.

**Working Principles:**
-   **Evidence-Based**: All analysis must be based on actual evidence obtained from tools; baseless speculation is prohibited.
-   **Result Validation**: Critically evaluate the results returned by delegated sub-tasks (e.g., function analysis) and always verify their authenticity and reliability to prevent false results from contaminating the final conclusion.

**Workflow:**
1.  **Understand Task**: Focus on the specific task for the current analysis file and fully refer to the user's overall requirements. Note that if the task does not match the current analysis focus, you need to stop the analysis and provide timely feedback to the user. Do not perform cross-directory analysis.
2.  **Perform Analysis**: Ensure your analysis has sufficient depth. For complex tasks, break them down into multiple sub-tasks with clear objectives and steps, and reasonably call analysis assistants or tools sequentially or in parallel. Choose the most suitable tool or assistant to obtain evidence. For complex call chains, use `FunctionAnalysisDelegator` and provide detailed taint information and context. Use certain tools cautiously to avoid overly long results, which could lead to analysis failure, e.g., `strings` tool.
3.  **Complete and Report**: After completing the analysis, use the `finish` action and submit your final report strictly according to the following format.

**Final Response Requirements**:
*   Answer all questions related to the current task, and your response must have complete evidence. Do not omit any valid information.
*   Support all findings with concrete evidence and truthfully report any insufficient evidence or difficulties.
{SHARED_RESPONSE_FORMAT_BLOCK}
*   Select a tool or 'finish' in the 'action' field, and provide parameters or the final response in 'action_input'.
"""


DEFAULT_FUNCTION_SYSTEM_PROMPT = """
You are a highly specialized firmware binary function call chain analysis assistant. Your task and only task is: starting from the currently specified function, strictly, unidirectionally, forward track the specified taint data until it reaches a sink (dangerous function).

**Strict Code of Conduct (Must Follow):**
1. **Absolute Focus**: Your analysis scope is **limited to** the currently specified function and its called subfunctions. **Strictly forbidden** to analyze any other functions or code paths unrelated to the current call chain.
2. **Unidirectional Tracking**: Your task is **forward tracking**. Once taint enters a subfunction, you must follow it in, **strictly forbidden** to return or perform reverse analysis.
3. **No Evaluation**: **Strictly forbidden** to provide any form of security assessment, remediation suggestions, or any subjective comments. Your only output is evidence-based, formatted taint paths.
4. **Complete Path**: You must provide **complete, reproducible** propagation paths from taint source to sink. If path breaks for any reason, must clearly state break location and reason.

**Analysis Process:**
1. **Analyze Current Function**: Use `r2` tool to analyze current function code, understand how taint data (usually in specific registers or memory addresses) is handled and passed.
2. **Decision: Deep Dive or Record**:
    * **Deep Dive**: If taint data is clearly passed to a subfunction, briefly preview subfunction logic, and create a new delegation task for subfunction. Task description must include: 1) **Target Function** (provide specific function address from disassembly if possible), 2) **Taint Entry** (which register/memory in subfunction contains taint), 3) **Taint Source** (how taint was produced in parent function), and 4) **Analysis Goal** (tracking requirements for new taint entry).
    * **Record**: If taint data is passed to a **sink** (like `system`, `sprintf`) and confirmed as dangerous operation (better construct a PoC), record this complete propagation path, this is what you need to report in detail.
3. **Path Break**: If taint is safely handled (like sanitization, validation) or not passed to any subfunction/sink within current function, terminate current path analysis and report clearly.

**Final Report Format:**
* At the end of analysis, you need to present all discovered complete taint propagation paths in a clear tree diagram.
* Each step **must** follow `'Step_number: address: three to five lines assembly code or pseudocode snippet --> step explanation'` format. **Code snippets must be real, verifiable, and critical to understanding data flow. Strictly forbidden to only provide explanations or conclusions without addresses and code.**
"""

class ExecutorAgent(BaseAgent):
    """System Analysis Agent (receives external Context, dependencies injected externally, includes tool execution environment and objects)"""

    def __init__(
        self,
        tools: Optional[List[Union[Type[ExecutableTool], ExecutableTool]]] = None,
        system_prompt: str = DEFAULT_WORKER_EXECUTOR_SYSTEM_PROMPT,
        output_schema: Optional[Dict[str, Any]] = None,
        max_iterations: int = 50,
        history_strategy = None,
        context: Optional[FlexibleContext] = None,
        messages_filters: List[Dict[str, str]] = None,
        **extra_params: Any
    ):
        self.file_path = context.get("file_path") if context else None
        self.file_name = os.path.basename(self.file_path) if self.file_path else None
        self.current_dir = context.get("current_dir")

        tools_to_pass = tools if tools is not None else DEFAULT_TOOL_CLASSES
        self.messages_filters = messages_filters if messages_filters else [{'from': context.get('base_path')+os.path.sep, 'to': ''}, {'from': 'user_name', 'to': 'user'}] if context and context.get('base_path') else []
        
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
    """File Analysis Agent (receives external Context, dependencies injected externally, includes tool execution environment and objects), and stores results after analysis."""

    def __init__(
        self,
        tools: Optional[List[Union[Type[ExecutableTool], ExecutableTool]]] = None,
        system_prompt: str = None,
        output_schema: Optional[Dict[str, Any]] = None,
        max_iterations: int = 50,
        history_strategy = None,
        context: Optional[FlexibleContext] = None,
        messages_filters: List[Dict[str, str]] = None,
        **extra_params: Any
    ):
        self.file_path = context.get("file_path") if context else None
        self.file_name = os.path.basename(self.file_path) if self.file_path else None
        self.current_dir = context.get("current_dir")

        tools_to_pass = tools if tools is not None else DEFAULT_TOOL_CLASSES
        self.messages_filters = messages_filters if messages_filters else [{'from': context.get('base_path')+os.path.sep, 'to': ''}, {'from': 'user_name', 'to': 'user'}] if context and context.get('base_path') else []
        
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

        kb_context = self.context.copy()
        self.kb_storage_agent = KnowledgeBaseAgent(context=kb_context)
   
    def run(self, user_input: str = None) -> Any:

        findings = str(super().run(user_input=user_input))
        
        store_prompt = (
            f"New analysis results are as follows:\n"
            f"{findings}\n\n"
            f"Based on the above analysis results, your current task is to determine if they has risk. "
            f"If they do, you need to store and organize the analysis results."
            f"User's core requirement is: {self.context.get('user_input', 'Not provided')}\n"
        )
        self.kb_storage_agent.run(user_input=store_prompt)

        return findings
    
    
FUNCTION_ANALYSIS_TOOLS = [Radare2Tool]

def _create_nested_call_chain_config(max_iterations: int, max_depth: int = 4) -> AgentConfig:
    """Helper function to create a nested configuration for ParallelFunctionDelegator.
       Each layer delegates to the next using ParallelFunctionDelegator.
       All layers use the same system prompt focused on call chain analysis.
    """
    if max_depth < 1:
        raise ValueError("max_depth must be at least 1 for call chain config.")

    current_config = AgentConfig(
        agent_class=ExecutorAgent, 
        tool_configs=FUNCTION_ANALYSIS_TOOLS, 
        system_prompt=DEFAULT_FUNCTION_SYSTEM_PROMPT, 
        max_iterations=max_iterations
    )

    for _ in range(max_depth - 1):
        delegator_tool = AssistantToolConfig(
            assistant_class=ParallelFunctionDelegator, 
            sub_agent_config=current_config, 
        )
        wrapper_tools = [*FUNCTION_ANALYSIS_TOOLS, delegator_tool]
        current_config = AgentConfig(
            agent_class=ExecutorAgent, 
            tool_configs=wrapper_tools, 
            system_prompt=DEFAULT_FUNCTION_SYSTEM_PROMPT, 
            max_iterations=max_iterations
        )

    return current_config

def create_kb_agent_config(
    max_iterations: int = 50,
) -> AgentConfig:

    kb_agent_cfg = AgentConfig(
        agent_class=KnowledgeBaseAgent,
        tool_configs=[QueryFindingsTool, ListUniqueValuesTool, StoreFindingsTool],
        system_prompt=DEFAULT_KB_SYSTEM_PROMPT,
        max_iterations=max_iterations
    )
    return kb_agent_cfg

def create_file_analysis_config(
    include_kb: bool,
    max_iterations: int = 50,
    main_system_prompt: Optional[str] = None, 
    sub_level_system_prompt: Optional[str] = None,
) -> AgentConfig:
    """
    Blueprint for file analysis tasks (2 layers only: one delegation level).
    L0: Planner (top level, can delegate to L1)
    L1: Executor (terminal level, cannot delegate further - only has tools and function call chain analysis)
    
    This ensures file analysis delegation is strictly one level deep.
    """
    effective_main_prompt = main_system_prompt or DEFAULT_FILE_SYSTEM_PROMPT
    final_sub_level_prompt = sub_level_system_prompt or DEFAULT_FILE_SYSTEM_PROMPT
    
    # Create nested call chain config for function analysis
    nested_call_chain_sub_agent_config = _create_nested_call_chain_config(max_iterations, max_depth=4)
    call_chain_assistant_tool_cfg = AssistantToolConfig(
        assistant_class=ParallelFunctionDelegator, 
        sub_agent_config=nested_call_chain_sub_agent_config,
    )

    # L1: Terminal executor - only has tools and function analysis, NO further delegation
    l1_tool_configs: List[Union[Type[ExecutableTool], AssistantToolConfig]] = [
        *DEFAULT_TOOL_CLASSES.copy(),
        call_chain_assistant_tool_cfg,
        # VulnerabilitySearchTool(),  # for CVE search if needed
    ]

    if include_kb:
        kb_config = create_kb_agent_config(max_iterations=max_iterations)
        hierarchical_kb_manager_tool_cfg = AssistantToolConfig(
            assistant_class=BaseAssistant, 
            sub_agent_config=kb_config,
            description="Used to query all known information about this firmware's file system. Can query known findings for files and known findings for other files. You can prioritize querying known findings for files, then link to known findings for other files via the results. Note that no findings means there are currently no findings."
        )
        l1_tool_configs.append(hierarchical_kb_manager_tool_cfg)

    l1_agent_cfg = AgentConfig(
        agent_class=ExecutorAgent,
        tool_configs=l1_tool_configs,
        system_prompt=final_sub_level_prompt,
        max_iterations=max_iterations
    )
    
    # L0: Top-level planner - can delegate to L1 via BaseAssistant/ParallelBaseAssistant
    l0_tool_configs: List[Union[Type[ExecutableTool], AssistantToolConfig]] = [
        GetContextInfoTool,
        ShellExecutorTool,
        Radare2Tool,
        AssistantToolConfig(
            assistant_class=BaseAssistant,
            sub_agent_config=l1_agent_cfg,
            description="The assistant can interact with files to perform specific file analysis tasks. Use case: When you need analysis results for a single-step task before deciding the next analysis task."
        ),
        AssistantToolConfig(
            assistant_class=ParallelBaseAssistant,
            sub_agent_config=l1_agent_cfg,
            description="Each assistant can interact with files, executing multiple file analysis sub-tasks in parallel. Use cases: 1. When a complex task needs to be broken down into multiple independent sub-tasks. 2. Sub-tasks have no strict execution order dependencies. 3. Recommended for large-scale and complex tasks to execute multiple sub-tasks in parallel, improving analysis efficiency."
        )
    ]

    file_analyzer_config = AgentConfig(
        agent_class=PlannerAgent,
        tool_configs=l0_tool_configs,
        system_prompt=effective_main_prompt, 
        max_iterations=max_iterations
    )
    return file_analyzer_config


def create_firmware_analysis_blueprint(
    include_kb: bool = True,
    max_levels: int = 4,
    max_iterations_per_agent: int = 50,
) -> AgentConfig:
    """
    Creates a multi-layered, planner-executor nested firmware analysis agent configuration.
    Each planning level (Lx_Planner) guides an Lx_Executor.
    The Lx_Executor explores its assigned directory and uses assistants to:
    - Delegate file analysis (Deep File Analysis Assistant -> Generic File Analyzer Config)
    - Delegate subdirectory analysis (Recursive Directory Analysis Assistant -> Deeper Level Planner Config)
    The deepest level planner's executor will delegate subdirectories to a terminal executor.
    """
    if max_levels < 1:
        raise ValueError("max_levels must be at least 1.")

    file_analyzer_config = create_file_analysis_config(
        include_kb=include_kb,
        max_iterations=max_iterations_per_agent,
    )
    kb_query_tool_cfg = create_kb_agent_config(
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
            Radare2FileTargetTool,
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
        if include_kb:
            worker_tools.append(AssistantToolConfig(
                assistant_class=BaseAssistant,
                sub_agent_config=kb_query_tool_cfg,
            ))
        
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
        max_levels_for_blueprint: int = 4,
        max_iterations_per_agent: int = 50,
        agent_instance_name: Optional[str] = "FirmwareMasterAgent",
    ):
        if not os.path.isdir(firmware_root_path):
            raise ValueError(f"Firmware root path '{firmware_root_path}' does not exist or is not a directory.")
        
        self.firmware_root_path = os.path.abspath(firmware_root_path)
        self.output_dir = os.path.abspath(output_dir)
        self.user_input = user_input
        self.max_levels = max_levels_for_blueprint
        self.max_iterations = max_iterations_per_agent
        self.agent_instance_name = agent_instance_name
        self.analysis_duration = 0.0
        self.verification_duration = 0.0
        self._verification_lock = threading.Lock()

        self.context = FlexibleContext(
            base_path=self.firmware_root_path,
            current_dir=self.firmware_root_path,
            output=self.output_dir,
            agent_log_dir=os.path.join(self.output_dir, f"{agent_instance_name}_logs"),
            user_input=self.user_input
        )

        master_agent_config = create_firmware_analysis_blueprint(
            max_levels=max_levels_for_blueprint,
            max_iterations_per_agent=max_iterations_per_agent,
        )
        
        self.master_agent = build_agent(master_agent_config, context=self.context)

    def run(self) -> str:
        initial_task = (
            f"Please analyze the firmware comprehensively, combining it with the user's core requirements. Currently located in firmware directory: {os.path.basename(self.firmware_root_path)}, user's core requirement is: {self.user_input} "
            f"Please start from this directory and analyze files and subdirectories layer by layer."
        )
        start_time = time.time()
        analysis_summary = self.master_agent.run(user_input=initial_task)
        end_time = time.time()
        self.analysis_duration = end_time - start_time
        print(f"Initial analysis completed, took {self.analysis_duration:.2f} seconds")
        
        self.summary()
        return analysis_summary

    def _get_findings_to_process(self, finding_to_verify: Optional[Union[Dict[str, Any], str]] = None) -> List[Dict[str, Any]]:
        """Loads all findings from the knowledge base, or processes a single specified finding."""
        if finding_to_verify:
            print("\n--- Starting verification of specified finding ---")
            if isinstance(finding_to_verify, str):
                return [{"description": finding_to_verify}] 
            elif isinstance(finding_to_verify, dict):
                return [finding_to_verify]
            return []
        
        print("\n--- Starting verification of all findings from knowledge base ---")
        kb_file_path = os.path.join(self.output_dir, "knowledge_base.jsonl")
        if not os.path.exists(kb_file_path):
            print(f"Knowledge base file '{kb_file_path}' does not exist, skipping verification.")
            return []
        
        all_findings = load_knowledge_base(kb_file_path)
        if not all_findings:
            print("Knowledge base is empty, no verification needed.")
            return []

        print(f"Loaded {len(all_findings)} findings from knowledge base for verification.")
        return all_findings

    def _verify_one_finding(self, finding: Dict[str, Any], verification_analyzer_config: AgentConfig):
        """
        Core logic for verifying a single finding.
        """
        finding_name_for_log = finding.get('name') or finding.get('description', 'untitled_finding')[:50].replace('/', '_')
        print(f"\n>> Starting verification: {finding_name_for_log}")
        
        finding_details = {k: v for k, v in finding.items() if k in ['location','description', 'file_path', 'code_snippet', 'risk_score']}
        verification_finding_details = (
            f"Verify the following finding:\n"
            f"```json\n"
            f"{json.dumps(finding_details, indent=2, ensure_ascii=False)}\n"
            f"```\n"
            f"**Requirements**:\n"
            f"1.  **Focused Verification**: All your operations must revolve around verifying this finding.\n"
            f"2.  **Evidence Support**: Your conclusions must be based on actual evidence returned by tools.\n"
            f"3.  **No Unrelated Analysis**: Do not explore any other potential issues outside of this finding.\n"
        )

        verification_task = DEFAULT_VERIFICATION_TASK_TEMPLATE.format(verification_finding_details=verification_finding_details)
        verification_prompt = DEFAULT_VERIFICATION_INSTRUCTION_TEMPLATE.format(verification_task=verification_task)
        
        task_context = self.context.copy()
        task_context.set("stage", f"verify_{finding_name_for_log}")
        task_context.set("user_input", verification_task)
        task_context.set("agent_log_dir", os.path.join(self.output_dir, "verify_tasks", f"verify_{finding_name_for_log}_logs"))
        
        task_start_time = time.time()
        tokens_before = self.calculate_token_usage()

        verification_analyzer_agent = build_agent(verification_analyzer_config, context=task_context)
        verification_result = verification_analyzer_agent.run(user_input=verification_prompt)
        
        task_end_time = time.time()
        tokens_after = self.calculate_token_usage()

        task_duration = task_end_time - task_start_time
        task_tokens = tokens_after - tokens_before

        print(f"<< Verification completed: {finding_name_for_log} (Time taken: {task_duration:.2f}s, Tokens: {task_tokens})")
        print(f"   Verification result: {verification_result}")

        verification_record = {
            'verification_task': finding_details,
            'verification_result': verification_result,
            'verification_duration_seconds': task_duration,
            'verification_token_usage': task_tokens
        }
        
        results_file_path = os.path.join(self.output_dir, "verification_results.jsonl")

        try:
            with self._verification_lock:
                with open(results_file_path, 'a', encoding='utf-8') as f:
                    f.write(json.dumps(verification_record, ensure_ascii=False) + '\n')
            print(f"   Verification results written to: {results_file_path}")
        except IOError as e:
            print(f"   Failed to write verification results file: {e}")

    def verify(self, finding_to_verify: Optional[Union[Dict[str, Any], str]] = None):
        """
        [Sequential] Verifies one or more findings.
        If `finding_to_verify` is provided, only that finding is verified (can be dict or string).
        Otherwise, findings are loaded, filtered, and sampled from the knowledge base for verification.
        Verification results will be saved to a separate "verification_results.jsonl" file.
        """
        start_time = time.time()
        
        findings_to_process = self._get_findings_to_process(finding_to_verify)

        if not findings_to_process:
            print("No findings selected for verification.")
            return

        print(f"Total of {len(findings_to_process)} findings will be verified [sequentially].")

        verification_analyzer_config = create_firmware_analysis_blueprint(
            include_kb=False,
            max_levels=self.max_levels,
            max_iterations_per_agent=self.max_iterations,
        )

        for i, finding in enumerate(findings_to_process):
            print(f"--- (Sequential) Verifying {i+1}/{len(findings_to_process)} ---")
            self._verify_one_finding(finding, verification_analyzer_config)

        end_time = time.time()
        self.verification_duration += (end_time - start_time)
        print(f"\nThis sequential verification took {end_time - start_time:.2f} seconds. Total verification time accumulated: {self.verification_duration:.2f} seconds.")
        
        self.summary()
        print("This round of sequential verification tasks is complete.")

    def verify_concurrently(self, max_workers: int = 5, finding_to_verify: Optional[Union[Dict[str, Any], str]] = None):
        """
        [Concurrent] Verifies one or more findings.
        """
        start_time = time.time()
        
        findings_to_process = self._get_findings_to_process(finding_to_verify)

        if not findings_to_process:
            print("No findings selected for verification.")
            return

        print(f"Total of {len(findings_to_process)} findings will be verified [concurrently], using {max_workers} worker threads.")

        verification_analyzer_config = create_firmware_analysis_blueprint(
            include_kb=False,
            max_levels=self.max_levels,
            max_iterations_per_agent=self.max_iterations,
        )

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [
                executor.submit(self._verify_one_finding, finding, verification_analyzer_config)
                for finding in findings_to_process
            ]
            for future in as_completed(futures):
                try:
                    future.result() 
                except Exception as exc:
                    print(f'A verification task generated an exception: {exc}')

        end_time = time.time()
        self.verification_duration += (end_time - start_time)
        print(f"\nThis concurrent verification took {end_time - start_time:.2f} seconds. Total verification time accumulated: {self.verification_duration:.2f} seconds.")
        
        self.summary()
        print("This round of concurrent verification tasks is complete.")

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
            error_msg = "Could not import report generation tools, skipping Markdown report generation."
            print(error_msg)
            return None, error_msg
        except Exception as e:
            error_msg = f"An unknown error occurred during report generation: {e}"
            print(error_msg)
            return None, error_msg

    def generate_verification_report(self):
        """Generates a Markdown verification report."""
        print("\nStarting verification report generation")
        
        try:
            from firmhive.utils.convert2md import generate_verification_report_md
            
            success, msg_or_path = generate_verification_report_md(self.output_dir)
            
            if success:
                print(f"Successfully generated Markdown verification report: {msg_or_path}")
                return [msg_or_path], None 
            else:
                if "No verification results file found" in msg_or_path:
                    print(f"No 'verification_results.jsonl' file found in '{self.output_dir}', skipping verification report generation.")
                else:
                    print(f"Failed to generate verification report: {msg_or_path}")
                return None, msg_or_path
                    
        except ImportError:
            error_msg = "Could not import report generation tools, skipping Markdown verification report generation."
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
        """Creates and writes a summary.txt file. Regenerates and overwrites the summary on each call."""
        self.generate_report()
        self.generate_verification_report()
        
        total_tokens = self.calculate_token_usage()
        
        summary_path = os.path.join(self.output_dir, "summary.txt")
        summary_content = (
            f"Analysis and Verification Summary\n"
            f"Analysis Phase Duration: {self.analysis_duration:.2f} seconds\n"
            f"Verification Phase Duration: {self.verification_duration:.2f} seconds\n"
            f"Total Duration: {self.analysis_duration + self.verification_duration:.2f} seconds\n"
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
    default_user_input = (
    "You must conduct a comprehensive analysis of the firmware file system, including binaries, configuration files, scripts, etc. The core objective is to identify and report complete, feasible, and actually exploitable attack chains from untrusted input points to dangerous operations. "
    "The analysis must focus on vulnerabilities with clear exploitable evidence, not merely theoretical flaws. Clearly and independently define and state the attacker model being evaluated.\n"
    "1. **Input Point Identification**: Identify all untrusted input sources in relevant files (binaries, configuration files, scripts, etc.), including but not limited to network interfaces (HTTP, API, sockets), IPC, NVRAM/environment variables, etc.\n"
    "2. **Data Flow Tracking**: Trace the propagation paths of untrusted data within the system and analyze whether there is a lack of proper validation, filtering, or boundary checking.\n"
    "3. **Component Interaction Analysis**: Focus on interactions between components (e.g., `nvram` get/set, IPC communication, front-end/back-end interaction), observing how externally controllable data flows within the system and affects other components.\n"
    "4. **Final Output**: The report should clearly describe the attack paths and security vulnerabilities most likely to be successfully exploited by attackers, assess their prerequisites, reproduction steps, and likelihood of success. For each finding, clearly indicate the attacker model and assumptions used (including authentication level, required privileges, exposed surface/reachability, etc.), and provide the rationale."
)

    
    parser = argparse.ArgumentParser(description="Firmware Analysis Master Agent")
    parser.add_argument("--search_dir", type=str, required=True, help="Path to the directory to search for firmware root.")
    parser.add_argument("--output", type=str, default="output", help="Base directory for analysis output.")
    parser.add_argument("--mode", type=str, choices=['analyze', 'verify', 'all'], default='all', 
                        help="Execution mode: 'analyze' only, 'verify' only, or 'all' (analyze then verify).")
    parser.add_argument("--user_input", type=str, default=default_user_input, help="User input/prompt for the analysis. Uses a default prompt if not provided in 'analyze' or 'all' mode.")
    parser.add_argument("--finding", type=str, help="A string describing a specific finding to verify. If not provided in 'verify' mode, findings are loaded from the knowledge base.")
    parser.add_argument("--concurrent", action="store_true", help="Run verification concurrently.")
    parser.add_argument("--max_workers", type=int, default=5, help="Max workers for concurrent verification.")
    
    args = parser.parse_args()

    firmware_root = find_firmware_root(args.search_dir)
    if not firmware_root:
        print(f"Error: Could not find a valid firmware root in '{args.search_dir}'.")
        sys.exit(1)
    
    print(f"Found firmware root at: {firmware_root}")

    output_dir = args.output
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    print(f"Output will be saved to: {output_dir}")

    master_agent = FirmwareMasterAgent(
        max_levels_for_blueprint=4,
        firmware_root_path=firmware_root,
        output_dir=output_dir,
        user_input=args.user_input,
    )
    
    if args.mode == 'analyze':
        print("\n--- Running in Analysis-Only Mode ---")
        master_agent.run()
        print("\n--- Analysis complete ---")

    elif args.mode == 'verify':
        print("\n--- Running in Verification-Only Mode ---")
        if args.concurrent:
            master_agent.verify_concurrently(
                max_workers=args.max_workers,
                finding_to_verify=args.finding
            )
        else:
            master_agent.verify(
                finding_to_verify=args.finding
            )
        print("\n--- Verification complete ---")

    elif args.mode == 'all':
        print("\n--- Running in Analysis and Verification Mode ---")
        summary = master_agent.run()
        
        if args.concurrent:
            master_agent.verify_concurrently(max_workers=args.max_workers, finding_to_verify=args.finding)
        else:
            master_agent.verify(finding_to_verify=args.finding)
        print("\n--- Analysis and Verification complete ---")
