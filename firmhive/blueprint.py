import os
import sys
import json
import time
import argparse
import threading

from typing import Dict, List, Any, Optional, Type, Union
from concurrent.futures import ThreadPoolExecutor, as_completed

from agent.base import BaseAgent
from agent.core.assitants import BaseAssistant, ParallelBaseAssistant
from agent.core.builder import build_agent, AgentConfig, AssistantToolConfig

from firmhive.utils.finder import find_firmware_root
from firmhive.utils.convert2md import load_knowledge_base
from firmhive.tools import FlexibleContext, ExecutableTool, GetContextInfoTool, ShellExecutorTool, Radare2Tool, Radare2FileTargetTool
    #  VulnerabilitySearchTool

from firmhive.knowagent import KnowledgeBaseAgent,QueryFindingsTool,ListUniqueValuesTool,StoreFindingsTool,DEFAULT_KB_SYSTEM_PROMPT
from firmhive.assitants import ParallelFunctionDelegator,ParallelDeepFileAnalysisDelegator,ParallelDeepDirectoryAnalysisDelegator,\
                            DeepFileAnalysisAssistant,DeepDirectoryAnalysisAssistant


DEFAULT_VERIFICATION_TASK_TEMPLATE = (
    "你的唯一任务是严格、客观地验证以下安全警报。你的分析必须完全基于所提供的证据。\n\n"
    "**核心原则**：\n"
    "1.  **证据驱动**：警报中的所有声明都必须通过分析所提供的证据来验证。严禁猜测或分析无关的信息和文件。\n"
    "2.  **逻辑审查**：不要仅仅确认代码的存在；你必须理解其执行逻辑。仔细检查条件语句、数据清理以及决定代码路径是否可达的其他因素。\n"
    "3.  **可利用性验证**：通过确认以下内容来验证漏洞是否**实际可利用**：\n"
    "    - **输入可控性**：攻击者可以控制污染的输入。\n"
    "    - **路径可达性**：在现实条件下可以到达易受攻击的路径。在你的分析中，请明确定义并陈述评估此漏洞所使用的攻击者模型（例如：未经身份验证的远程攻击者、已通过身份验证的本地用户等）。\n"
    "    - **实际影响**：操作可能造成实际的安全损害。\n"
    "4.  **完整攻击链**：- **需要完整路径**：部分或推测性路径是不可接受的。你必须提供完整、经过验证的链。验证从攻击者控制的输入到危险汇聚点的**完整传播路径**，每一步都有证据支持。\n\n"
    "**注意**：警报中的函数名可能来自反编译。请仔细搜索；不要仅仅因为它们不在符号表或字符串中就轻易断定它们不存在。\n\n"
    "{verification_finding_details}\n"
)

DEFAULT_VERIFICATION_INSTRUCTION_TEMPLATE = (
    "{verification_task}\n"
    "**提供结论**：在分析结束时，`final_response` 必须是包含以下字段的 JSON 对象：\n"
    "    - `accuracy`: (字符串) 对警报描述准确性的评估。必须是 'accurate'（准确）、'inaccurate'（不准确）或 'partially'（部分准确）。\n"
    "    - `vulnerability`: (布尔值) 判断该描述是否足以构成真实漏洞。必须是 True 或 False。在你的理由中，请明确说明你评估时所基于的攻击者前提条件。\n"
    "    - `risk_level`: (字符串) 如果 `vulnerability` 为 `true`，则为漏洞的风险级别。必须是 'Low'（低）、'Medium'（中）或 'High'（高）。\n"
    "    - `reason`: (字符串) 对你判断的详细解释，必须支持以上所有结论。对于确认为真实漏洞的发现，此字段还必须提供可重现的攻击载荷或概念验证（PoC）步骤，清楚地描述如何利用该漏洞。\n"
)


SHARED_RESPONSE_FORMAT_BLOCK = """
每个发现必须包含以下**核心字段**：
- **`description`**：对发现的详细描述，必须包括：
* 问题的具体表现和触发条件
* 详细的约束条件和边界检查情况
* 潜在的攻击和利用方式
* 相关的代码逻辑或技术细节

- **`link_identifiers`**：特定的 NVRAM 或 ENV 变量名、文件路径、IPC 套接字路径和自定义共享函数符号，确保精准追踪跨文件、跨进程的数据流与交互。
- **`location`**：精确位置（文件:行号 函数名 地址）
- **`code_snippet`**：返回完整的相关代码片段，展示漏洞的触发条件和利用方式。
- **`risk_score`**：风险评分（0.0-10.0）。**只有具有经过验证的完整攻击链和明确安全影响的发现才能得分 >= 7.0。**
- **`confidence`**：对发现准确性和可利用性分析的置信度（0.0-10.0）。**得分 >= 8.0 需要从源到汇聚点的完整、可验证的攻击链。**
- **`notes`**：其他重要信息，供人工分析师参考包括：需要进一步验证的假设，发现的关联文件或函数，建议的后续分析方向

#### 关键原则：
- **可利用性是必须的**：如果用户要求只报告实际可利用的攻击链，则理论上的弱点或不良实践（如使用 `strcpy`）是不够的，除非你能证明它们会导致漏洞。
- **证据优于推测**：所有声明都必须由工具的证据支持。如果缺少证据，请明确说明。不要猜测。
"""

DEFAULT_WORKER_EXECUTOR_SYSTEM_PROMPT = f"""
你是一个固件文件系统静态分析代理。你的任务是基于当前分析焦点（特定目录）进行探索和分析。请专注于当前焦点，当你认为对其分析已完成或无法进一步推进时，继续下一个任务或结束任务。

工作方法：

1.  **理解需求**
    *   始终关注当前分析对象或特定任务，同时也要参考用户的整体或初始需求。
    *   仔细理解用户当前想要分析的固件内容和目标。除非你非常确定不符合要求，否则不要遗漏符合用户要求的目录和文件。
    *   如果用户需求不清楚，根据固件特征选择最佳分析路径，适当分解复杂任务，合理调用分析助手。

2.  **制定分析计划**
    *   根据固件特征选择最佳分析路径。
    *   对于复杂任务，将其分解为多个具有明确目标和步骤的子任务，合理调用分析助手和工具。
    *   根据助手反馈合理调整分析计划，确保计划准确完整。如果助手无法完成任务，重新制定分析计划。如果助手尝试两次后仍无法完成任务，继续分析下一个任务。

3.  **分析期间的问题处理**
    *   记录分析过程中遇到的技术难点和独特挑战。
    *   评估问题在实际固件环境中的影响。
    *   谨慎使用某些工具，避免结果过长导致分析失败，例如 `strings` 工具。

4.  **提交分析结果**
    *   总结所有分析结果并回答当前任务对应的问题。
    *   如实报告证据不足或不确定的情况或困难（缺少什么证据，缺少什么信息）。

**核心工作流程：**

1.  **理解需求**
    *   始终关注具体任务，同时也要参考用户的整体或初始需求。注意，如果任务与当前分析焦点不匹配，你需要停止分析并及时向用户反馈。不要执行跨目录分析。
    *   仔细理解用户当前想要分析的固件内容和目标。除非你非常确定不符合要求，否则不要遗漏符合用户要求的目录和文件。如果用户需求不清楚，根据固件特征选择最佳分析路径，分解复杂任务，合理调用分析助手。

2.  **理解上下文**：使用工具精确了解你当前的分析焦点和位置。

3.  **委托任务**：需要深入分析时，调用适当的分析助手：
    *   **探索目录**：使用子目录分析助手或其并行版本切换到指定目录进行分析。
    *   **分析文件**：使用文件分析助手或其并行版本分析指定文件。

4.  **总结并完成**：完成当前焦点的所有分析任务后，总结你的发现。如果所有任务都已完成，使用 `finish` 动作结束。

*   在 'action' 字段中选择工具或 'finish'，并在 'action_input' 中提供参数或最终响应。
"""

DEFAULT_TOOL_CLASSES: List[Union[Type[ExecutableTool], ExecutableTool]] = [
    GetContextInfoTool, ShellExecutorTool, Radare2Tool
]


DEFAULT_FILE_SYSTEM_PROMPT = f"""
你是一个专门的文件分析代理。你的任务是深入分析当前指定的文件并提供详细的、有证据支持的分析结果。请专注于当前焦点文件或当前特定任务。当你认为你的分析已完成或无法进一步推进时，继续下一个任务或结束任务。

**工作原则：**
-   **基于证据**：所有分析都必须基于从工具获取的实际证据；禁止无根据的猜测。
-   **结果验证**：批判性地评估委托子任务（例如函数分析）返回的结果，并始终验证其真实性和可靠性，以防止虚假结果污染最终结论。

**工作流程：**
1.  **理解任务**：专注于当前分析文件的特定任务，并充分参考用户的整体要求。注意，如果任务与当前分析焦点不匹配，你需要停止分析并及时向用户反馈。不要执行跨目录分析。
2.  **执行分析**：确保你的分析有足够的深度。对于复杂任务，将其分解为多个具有明确目标和步骤的子任务，并合理地按顺序或并行调用分析助手或工具。选择最合适的工具或助手来获取证据。对于复杂的调用链，使用 `FunctionAnalysisDelegator` 并提供详细的污点信息和上下文。谨慎使用某些工具，避免结果过长导致分析失败，例如 `strings` 工具。
3.  **完成并报告**：完成分析后，使用 `finish` 动作并严格按照以下格式提交最终报告。

**最终响应要求**：
*   回答与当前任务相关的所有问题，你的响应必须有完整的证据。不要遗漏任何有效信息。
*   用具体证据支持所有发现，并如实报告任何证据不足或困难。
{SHARED_RESPONSE_FORMAT_BLOCK}
*   在 'action' 字段中选择工具或 'finish'，并在 'action_input' 中提供参数或最终响应。
"""


DEFAULT_FUNCTION_SYSTEM_PROMPT = """
你是一个高度专业化的固件二进制函数调用链分析助手。你的任务和唯一任务是：从当前指定的函数开始，严格、单向、正向追踪指定的污点数据，直到它到达汇聚点（危险函数）。

**严格行为准则（必须遵守）：**
1. **绝对专注**：你的分析范围**仅限于**当前指定的函数及其调用的子函数。**严禁**分析任何与当前调用链无关的其他函数或代码路径。
2. **单向追踪**：你的任务是**正向追踪**。一旦污点进入子函数，你必须跟进去，**严禁**返回或执行逆向分析。
3. **不做评估**：**严禁**提供任何形式的安全评估、修复建议或任何主观评论。你的唯一输出是基于证据的、格式化的污点路径。
4. **完整路径**：你必须提供从污点源到汇聚点的**完整、可重现**的传播路径。如果路径因任何原因中断，必须清楚说明中断位置和原因。

**分析过程：**
1. **分析当前函数**：使用 `r2` 工具分析当前函数代码，了解污点数据（通常在特定寄存器或内存地址中）如何被处理和传递。
2. **决策：深入或记录**：
    * **深入**：如果污点数据明确传递给子函数，简要预览子函数逻辑，并为子函数创建新的委托任务。任务描述必须包括：1) **目标函数**（如果可能，从反汇编中提供特定函数地址），2) **污点入口**（子函数中哪个寄存器/内存包含污点），3) **污点来源**（污点在父函数中如何产生），以及 4) **分析目标**（对新污点入口的追踪要求）。
    * **记录**：如果污点数据传递给**汇聚点**（如 `system`、`sprintf`）并确认为危险操作（最好构造 PoC），记录这个完整的传播路径，这是你需要详细报告的内容。
3. **路径中断**：如果污点被安全处理（如清理、验证）或在当前函数内未传递给任何子函数/汇聚点，终止当前路径分析并清楚报告。

**最终报告格式：**
* 在分析结束时，你需要以清晰的树状图呈现所有发现的完整污点传播路径。
* 每一步**必须**遵循 `'步骤编号: 地址: 三到五行汇编代码或伪代码片段 --> 步骤说明'` 格式。**代码片段必须是真实的、可验证的，并且对理解数据流至关重要。严禁只提供说明或结论而不提供地址和代码。**
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
        self.messages_filters = messages_filters if messages_filters else [{'from': context.get('base_path')+os.path.sep, 'to': ''}, {'from': 'zxr', 'to': 'user'}] if context and context.get('base_path') else []
        
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
        self.messages_filters = messages_filters if messages_filters else [{'from': context.get('base_path')+os.path.sep, 'to': ''}, {'from': 'zxr', 'to': 'user'}] if context and context.get('base_path') else []
        
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
            description="用于查询此固件文件系统的所有已知信息。可以查询文件的已知发现以及其他文件的已知发现。你可以优先查询文件的已知发现，然后通过结果链接到其他文件的已知发现。注意：没有发现意味着当前还没有发现。"
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
            description="助手可以与文件交互以执行特定的文件分析任务。使用场景：当你需要单步任务的分析结果后再决定下一个分析任务时。"
        ),
        AssistantToolConfig(
            assistant_class=ParallelBaseAssistant,
            sub_agent_config=l1_agent_cfg,
            description="每个助手可以与文件交互，并行执行多个文件分析子任务。使用场景：1. 当复杂任务需要分解为多个独立的子任务时。2. 子任务之间没有严格的执行顺序依赖。3. 建议对大规模和复杂任务并行执行多个子任务，提高分析效率。"
        )
    ]

    file_analyzer_config = AgentConfig(
        agent_class=PlannerAgent if include_kb else ExecutorAgent,
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
            f"请结合用户的核心需求对固件进行全面分析。当前位于固件目录：{os.path.basename(self.firmware_root_path)}，用户的核心需求是：{self.user_input} "
            f"请从此目录开始，逐层分析文件和子目录。"
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
        
        finding_details = {k: v for k, v in finding.items() if k in ['name', 'location', 'description', 'file_path', 'code_snippet', 'risk_score', 'notes']}
        verification_finding_details = (
            f"验证以下发现：\n"
            f"```json\n"
            f"{json.dumps(finding_details, indent=2, ensure_ascii=False)}\n"
            f"```\n"
            f"**要求**：\n"
            f"1.  **专注验证**：你的所有操作都必须围绕验证此发现进行。\n"
            f"2.  **证据支持**：你的结论必须基于工具返回的实际证据。\n"
            f"3.  **不做无关分析**：不要探索此发现之外的任何其他潜在问题。\n"
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
            with open(summary_path, 'a', encoding='utf-8') as f:
                f.write(summary_content)
            print(f"\nSummary information updated: {summary_path}")
            print(summary_content)
        except IOError as e:
            print(f"Could not write summary file {summary_path}: {e}")
    
if __name__ == "__main__":
    default_user_input = (
    "Perform a comprehensive security analysis of the firmware. The core objective is to identify and report "
    "complete, viable, and **practically exploitable** attack chains from untrusted input points to dangerous operations. "
    "The analysis must focus on vulnerabilities with clear evidence of exploitability, not theoretical flaws.\n"
    "1. **Input Point Identification**: Identify all potential sources of untrusted input, including but not limited "
    "to network interfaces (HTTP, API, sockets), IPC, NVRAM/environment variables, etc.\n"
    "2. **Data Flow Tracking**: Trace the propagation paths of untrusted data within the system and analyze whether "
    "there are any processes without proper validation, filtering, or boundary checks.\n"
    "3. **Component Interaction Analysis**: Focus on interactions between components (e.g., `nvram` get/set, IPC "
    "communication) to observe how externally controllable data flows within the system and affects other components.\n"
    "4. **Exploit Chain Evaluation**: For each potential attack chain discovered, evaluate its trigger conditions, "
    "reproduction steps, and the probability of successful exploitation. **A finding is only valid if a complete and verifiable chain is found.**\n"
    "5. **Final Output**: The report should clearly describe the attack paths and security vulnerabilities most likely "
    "to be successfully exploited by an attacker."
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