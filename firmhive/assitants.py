import os
from typing import Any, Dict, Optional, List, Union, Type

from agent.base import BaseAgent
from agent.tools.basetool import FlexibleContext, ExecutableTool
from agent.core.assitants import BaseAssistant, ParallelBaseAssistant

class ParallelFunctionDelegator(ParallelBaseAssistant):
    name = "FunctionDelegator"
    description = """
    函数分析委托器 - 专门分析二进制文件中函数调用链的代理。它的职责是正向追踪函数调用之间的污点数据流。你可以将潜在的外部入口点委托给此代理进行深入追踪。
    """

    parameters = {
        "type": "object",
        "properties": {
            "tasks": { 
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "task": {
                            "type": "string", 
                            "description": (
                                "为子函数创建分析任务时，你的描述必须清楚地包括以下四点：\n"
                                "1. **目标函数**：要分析的子函数的名称和地址。\n"
                                "2. **污点入口**：污点在子函数中所在的特定寄存器或栈地址（例如，'污点在第一个参数寄存器 r0 中'）。\n"
                                "3. **污点来源**：这个污点数据在父函数中是如何产生的（例如，'这个值是父函数 main 通过调用 nvram_get(\"lan_ipaddr\") 获取的'）。\n"
                                "4. **分析目标**：清楚地指出新任务应该追踪这个新的污点入口（例如，'在子函数内追踪 r0'）。"
                            )
                        },
                        "task_context": {
                            "type": "string", 
                            "description": (
                                "（可选）提供可能影响分析的补充上下文。这些信息不是污点流本身的一部分，但可能影响子函数的执行路径。例如：\n"
                                "- '此时寄存器 r2 的值为 0x100，表示最大缓冲区长度。'\n"
                                "- '在此调用之前，全局变量 `is_admin` 被设置为 1。'\n"
                                "- '在分析期间假设文件已成功打开。'"
                            )
                        }
                    },
                    "required": ["task"]
                },
                "description": "要执行的函数分析任务列表。"
            },
            "run_in_background": {
                "type": "boolean",
                "description": "是否在后台运行此任务。",
                "default": False
            }
        },
        "required": ["tasks"]
    }

    def __init__(self, 
                 context: FlexibleContext,
                 agent_class_to_create: Type[BaseAgent] = BaseAgent,
                 default_sub_agent_tool_classes: Optional[List[Union[Type[ExecutableTool], ExecutableTool]]] = None,
                 default_sub_agent_max_iterations: int = 10,
                 sub_agent_system_prompt: Optional[str] = None,
                 name: Optional[str] = None,
                 description: Optional[str] = None,
                 timeout: Optional[int] = None
                ):
        final_name = name or ParallelFunctionDelegator.name
        final_description = description or ParallelFunctionDelegator.description
        
        super().__init__(
            context=context,
            agent_class_to_create=agent_class_to_create,
            default_sub_agent_tool_classes=default_sub_agent_tool_classes,
            default_sub_agent_max_iterations=default_sub_agent_max_iterations,
            sub_agent_system_prompt=sub_agent_system_prompt,
            name=final_name,
            description=final_description,
            timeout=timeout
        )

    def _get_sub_agent_task_details(self, **task_item: Any) -> Dict[str, Any]:
        task = task_item.get("task", "")
        task_context = task_item.get("task_context", "")
        return {
            "task": task,
            "task_context": task_context
        }
    
    def _build_sub_agent_prompt(self, usr_init_msg: Optional[str], **task_details: Any) -> str:
        task = task_details.get("task")
        task_context = task_details.get("task_context")

        usr_init_msg_content = usr_init_msg if usr_init_msg else "未提供用户初始请求"
        task_content = task if task else "未提供任务"

        prompt_parts = [
            f"用户核心请求：\n{usr_init_msg_content}",
            f"当前具体任务：\n{task_content}"
        ]

        if task_context:
            prompt_parts.append(f"补充上下文：\n{task_context}")

        return "\n\n".join(prompt_parts)
    
    def _extract_task_list(self, **kwargs: Any) -> List[Dict[str, Any]]:
        tasks = kwargs.get("tasks", [])
        if not isinstance(tasks, list):
            return []
        return [task for task in tasks if isinstance(task, dict)]


class DeepFileAnalysisAssistant(BaseAssistant):
    name = "DeepFileAnalysisAssistant"
    description = """
    用于对当前目录范围内指定文件进行深度分析的代理。
    只能分析当前目录或其子目录（任意深度）中的文件。
    对于你作用域内的文件，使用简单的相对路径，如 'config.php' 或 'subdir/file.txt'。
    适用于单个文件的深度分析任务。你可以在观察单步结果后决定下一个分析任务。对于验证任务等有针对性的分析，强烈建议使用此代理。
    """
    parameters = {
        "type": "object",
        "properties": {
            "file_name": {
                "type": "string",
                "description": "相对于你当前目录的文件路径（例如，'config.php'、'hnap/Login.xml'）。你只能访问当前目录或其子目录中的文件。"
            },
            "run_in_background": {
                "type": "boolean",
                "description": "是否在后台运行此任务。",
                "default": False
            }
        },
        "required": ["file_name"],
        "description": "包含文件分析目标的对象。使用相对于当前工作目录的路径。"
    }
    timeout = 7200  

    def __init__(
        self,
        context: FlexibleContext,
        agent_class_to_create: Type[BaseAgent] = BaseAgent,
        default_sub_agent_tool_classes: Optional[List[Union[Type[ExecutableTool], ExecutableTool]]] = None,
        default_sub_agent_max_iterations: int = 10,
        sub_agent_system_prompt: Optional[str] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
        timeout: Optional[int] = None,
    ):
        final_name = name or DeepFileAnalysisAssistant.name
        final_description = description or DeepFileAnalysisAssistant.description

        super().__init__(
            context=context,
            agent_class_to_create=agent_class_to_create,
            default_sub_agent_tool_classes=default_sub_agent_tool_classes,
            default_sub_agent_max_iterations=default_sub_agent_max_iterations,
            sub_agent_system_prompt=sub_agent_system_prompt,
            name=final_name,
            description=final_description,
            timeout=timeout
        )

    def _get_sub_agent_task_details(self, **kwargs: Any) -> Dict[str, Any]:
        file_name = kwargs.get("file_name")
        if not file_name or not isinstance(file_name, str):
            return {"task": "错误：分析需要一个有效的文件名。"}
        
        return {
            "task": f"专注于分析文件 '{file_name}' 的内容，寻找可利用的信息。",
            "file_name": file_name
        }

    def _prepare_sub_agent_context(self, sub_agent_context: FlexibleContext, **task_details: Any) -> FlexibleContext:
        file_name = task_details.get("file_name")

        if not file_name or not isinstance(file_name, str):
            raise ValueError("错误：分析需要一个有效的文件路径。")
        
        file_name = file_name.lstrip('/')

        firmware_root = self.context.get("base_path")
        if not firmware_root or not os.path.isdir(firmware_root):
            raise ValueError("上下文中缺少有效的固件根目录 'base_path'，无法解析路径。")

        scope_dir = self.context.get("current_dir")
        if not scope_dir or not os.path.isdir(scope_dir):
            raise ValueError("上下文中缺少有效的工作目录 'current_dir'，无法执行范围检查。")

        resolved_path_from_current = os.path.normpath(os.path.join(scope_dir, file_name))
        resolved_path_from_root = os.path.normpath(os.path.join(firmware_root, file_name))
        
        if os.path.exists(resolved_path_from_current) and os.path.isfile(resolved_path_from_current):
            resolved_path = resolved_path_from_current
        elif os.path.exists(resolved_path_from_root) and os.path.isfile(resolved_path_from_root):
            resolved_path = resolved_path_from_root
        else:
            resolved_path = resolved_path_from_current
        
        real_firmware_root = os.path.realpath(firmware_root)
        real_scope_dir = os.path.realpath(scope_dir)

        try:
            real_resolved_path = os.path.realpath(resolved_path)
        except FileNotFoundError:
             raise ValueError(f"在固件中未找到文件 '{file_name}'。")

        if not os.path.commonpath([real_resolved_path, real_firmware_root]) == real_firmware_root:
            raise ValueError(f"提供的路径 '{file_name}' 无效，可能包含 '..' 或指向固件根目录之外。")

        if not os.path.commonpath([real_resolved_path, real_scope_dir]) == real_scope_dir:
            current_dir_name = os.path.relpath(scope_dir, firmware_root)
            basename_only = os.path.basename(file_name)
            potential_correct_path = os.path.join(current_dir_name, basename_only)
            potential_full_path = os.path.join(firmware_root, potential_correct_path)
            
            if os.path.exists(potential_full_path) and os.path.isfile(potential_full_path):
                raise ValueError(
                    f"路径格式错误：你提供了 '{file_name}'，但必须使用相对于固件根目录的完整路径。"
                    f"你在目录 '{current_dir_name}' 中。要分析此目录中的文件 '{basename_only}'，"
                    f"请使用完整路径：'{potential_correct_path}'（而不是仅 '{basename_only}'）。"
                )
            else:
                raise ValueError(
                    f"访问被拒绝：文件 '{file_name}' 不在你的当前工作目录 '{current_dir_name}' 中。"
                    f"你严格限制在 '{current_dir_name}' 内分析文件。"
                    f"不允许跨目录分析。如果需要分析其他目录中的文件，"
                    f"请报告此限制并建议由具有适当范围的其他代理处理。"
                )

        if not os.path.isfile(resolved_path):
            raise ValueError(f"指定的路径 '{file_name}' 不是有效的文件。")

        sub_agent_context.set("file_path", resolved_path)
        sub_agent_context.set("file_name", os.path.basename(resolved_path))
        sub_agent_context.set("current_dir", os.path.dirname(resolved_path))
        return sub_agent_context

    def _build_sub_agent_prompt(self, usr_init_msg: Optional[str], **task_details: Any) -> str:
        task = task_details.get("task", "No file analysis task provided.")
        
        usr_init_msg_content = usr_init_msg if usr_init_msg else "未提供用户初始请求"
        
        return (
            f"用户初始请求：\n{usr_init_msg_content}\n\n"
            f"当前任务：\n{task}"
        )


class DeepDirectoryAnalysisAssistant(BaseAssistant):
    name = "DeepDirectoryAnalysisAssistant"
    description = """
    用于对当前目录范围内指定子目录进行深度分析的代理。
    只能分析当前目录中的子目录（直接子目录或更深层的嵌套目录）。
    对于你作用域内的目录，使用简单的相对路径，如 'hnap' 或 'subdir/nested'。
    适用于单个子目录的深度分析任务。你可以在观察单步结果后决定下一个分析任务。对于验证任务等有针对性的分析，强烈建议使用此代理。
    """
    parameters = {
        "type": "object",
        "properties": {
            "dir_name": {
                "type": "string",
                "description": "相对于你当前目录的目录路径（例如，'hnap'、'init.d'）。你只能访问当前目录范围内的子目录。"
            },
            "run_in_background": {
                "type": "boolean",
                "description": "是否在后台运行此任务。",
                "default": False
            }
        },
        "required": ["dir_name"],
        "description": "包含目录分析目标的对象。使用相对于当前工作目录的路径。"
    }
    timeout = 9600

    def __init__(
        self,
        context: FlexibleContext,
        agent_class_to_create: Type[BaseAgent] = BaseAgent,
        default_sub_agent_tool_classes: Optional[List[Union[Type[ExecutableTool], ExecutableTool]]] = None,
        default_sub_agent_max_iterations: int = 10,
        sub_agent_system_prompt: Optional[str] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
        timeout: Optional[int] = None,
    ):
        final_name = name or DeepDirectoryAnalysisAssistant.name
        final_description = description or DeepDirectoryAnalysisAssistant.description

        super().__init__(
            context=context,
            agent_class_to_create=agent_class_to_create,
            default_sub_agent_tool_classes=default_sub_agent_tool_classes,
            default_sub_agent_max_iterations=default_sub_agent_max_iterations,
            sub_agent_system_prompt=sub_agent_system_prompt,
            name=final_name,
            description=final_description,
            timeout=timeout
        )
        
    def _get_sub_agent_task_details(self, **kwargs: Any) -> Dict[str, Any]:
        dir_name = kwargs.get("dir_name")
        if not dir_name or not isinstance(dir_name, str):
            return {"task": "错误：分析需要一个有效的目录名。"}
        
        return {
            "task": f"专注于分析目录 '{dir_name}' 的内容，寻找可利用的信息和线索。",
            "dir_name": dir_name
        }

    def _prepare_sub_agent_context(self, sub_agent_context: FlexibleContext, **task_details: Any) -> FlexibleContext:
        dir_name = task_details.get("dir_name")

        if not dir_name or not isinstance(dir_name, str):
            raise ValueError("错误：分析需要一个有效的目录路径。")

        dir_name = dir_name.lstrip('/')

        firmware_root = self.context.get("base_path")
        if not firmware_root or not os.path.isdir(firmware_root):
            raise ValueError("上下文中缺少有效的固件根目录 'base_path'，无法解析路径。")

        scope_dir = self.context.get("current_dir")
        if not scope_dir or not os.path.isdir(scope_dir):
            raise ValueError("上下文中缺少有效的工作目录 'current_dir'，无法执行范围检查。")

        resolved_path_from_current = os.path.normpath(os.path.join(scope_dir, dir_name))
        resolved_path_from_root = os.path.normpath(os.path.join(firmware_root, dir_name))
        
        if os.path.exists(resolved_path_from_current) and os.path.isdir(resolved_path_from_current):
            resolved_path = resolved_path_from_current
        elif os.path.exists(resolved_path_from_root) and os.path.isdir(resolved_path_from_root):
            resolved_path = resolved_path_from_root
        else:
            resolved_path = resolved_path_from_current

        real_firmware_root = os.path.realpath(firmware_root)
        real_scope_dir = os.path.realpath(scope_dir)
        try:
            real_resolved_path = os.path.realpath(resolved_path)
        except FileNotFoundError:
            raise ValueError(f"在固件中未找到目录 '{dir_name}'。")

        if not os.path.commonpath([real_resolved_path, real_firmware_root]) == real_firmware_root:
            raise ValueError(f"提供的路径 '{dir_name}' 无效，可能包含 '..' 或指向固件根目录之外。")

        if not os.path.commonpath([real_resolved_path, real_scope_dir]) == real_scope_dir:
            current_dir_name = os.path.relpath(scope_dir, firmware_root)
            basename_only = os.path.basename(dir_name)
            potential_correct_path = os.path.join(current_dir_name, basename_only)
            potential_full_path = os.path.join(firmware_root, potential_correct_path)
            
            if os.path.exists(potential_full_path) and os.path.isdir(potential_full_path):
                raise ValueError(
                    f"路径格式错误：你提供了 '{dir_name}'，但必须使用相对于固件根目录的完整路径。"
                    f"你在目录 '{current_dir_name}' 中。要分析其子目录 '{basename_only}'，"
                    f"请使用完整路径：'{potential_correct_path}'（而不是仅 '{basename_only}'）。"
                )
            else:
                raise ValueError(
                    f"访问被拒绝：目录 '{dir_name}' 不在你的当前工作目录 '{current_dir_name}' 中。"
                    f"你严格限制在 '{current_dir_name}' 内分析子目录。"
                    f"不允许跨目录和向上目录分析。如果需要分析其他目录，"
                    f"请报告此限制并建议由具有适当范围的其他代理处理。"
                )

        if not os.path.isdir(resolved_path):
            raise ValueError(f"指定的路径 '{dir_name}' 不是有效的目录。")

        sub_agent_context.set("current_dir", resolved_path)
        sub_agent_context.set("file_path", None)
        return sub_agent_context

    def _build_sub_agent_prompt(self, usr_init_msg: Optional[str], **task_details: Any) -> str:
        task = task_details.get("task", "No directory analysis task provided.")
        
        usr_init_msg_content = usr_init_msg if usr_init_msg else "未提供用户初始请求"
        
        return (
            f"用户初始请求：\n{usr_init_msg_content}\n\n"
            f"当前任务：\n{task}"
        )


class ParallelDeepFileAnalysisDelegator(ParallelBaseAssistant):
    name = "ParallelDeepFileAnalysisDelegator"
    description = """
    深度文件分析委托器 - 将当前目录范围内多个文件的分析任务分配给子代理并行处理。
    只能分析当前目录或其子目录（任意深度）中的文件。
    对于你作用域内的文件，使用简单的相对路径。
    适用于同时对多个文件进行深度分析的任务。对于复杂任务或全面分析，强烈建议使用此委托器。
    """
    parameters = {
        "type": "object",
        "properties": {
            "file_names": {
                "type": "array",
                "items": {
                    "type": "string",
                    "description": "相对于你当前目录的文件路径（例如，'config.php'、'hnap/Login.xml'）。你只能访问当前目录或其子目录中的文件。"
                },
                "description": "要并行分析的文件路径列表。使用相对于当前工作目录的路径。"
            },
            "run_in_background": {
                "type": "boolean",
                "description": "是否在后台运行此任务。",
                "default": False
            }
        },
        "required": ["file_names"],
        "description": "包含当前目录范围内文件分析目标列表的对象。"
    }
    timeout = 9600

    def __init__(
        self,
        context: FlexibleContext,
        agent_class_to_create: Type[BaseAgent] = BaseAgent,
        default_sub_agent_tool_classes: Optional[List[Union[Type[ExecutableTool], ExecutableTool]]] = None,
        default_sub_agent_max_iterations: int = 10,
        sub_agent_system_prompt: Optional[str] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
        timeout: Optional[int] = None,
    ):
        final_name = name or ParallelDeepFileAnalysisDelegator.name
        final_description = description or ParallelDeepFileAnalysisDelegator.description

        super().__init__(
            context=context,
            agent_class_to_create=agent_class_to_create,
            default_sub_agent_tool_classes=default_sub_agent_tool_classes,
            default_sub_agent_max_iterations=default_sub_agent_max_iterations,
            sub_agent_system_prompt=sub_agent_system_prompt,
            name=final_name,
            description=final_description,
            timeout=timeout
        )

    def _extract_task_list(self, **kwargs: Any) -> List[Dict[str, Any]]:
        file_names = kwargs.get("file_names", [])
        return [{"file_name": file_name} for file_name in file_names]

    def _get_sub_agent_task_details(self, **task_item: Any) -> Dict[str, Any]:
        file_name = task_item.get("file_name")
        if not file_name or not isinstance(file_name, str):
            return {"task": "错误：并行分析需要一个有效的文件名。"}

        return {
            "task": f"专注于分析文件 '{file_name}' 的内容，寻找可利用的信息和线索。",
            "file_name": file_name
        }

    def _prepare_sub_agent_context(self, sub_agent_context: FlexibleContext, **task_details: Any) -> FlexibleContext:
        file_name = task_details.get("file_name")

        if not file_name or not isinstance(file_name, str):
            raise ValueError("错误：分析需要一个有效的文件路径。")

        file_name = file_name.lstrip('/')

        firmware_root = self.context.get("base_path")
        if not firmware_root or not os.path.isdir(firmware_root):
            raise ValueError("上下文中缺少有效的固件根目录 'base_path'，无法解析路径。")

        scope_dir = self.context.get("current_dir")
        if not scope_dir or not os.path.isdir(scope_dir):
            raise ValueError("上下文中缺少有效的工作目录 'current_dir'，无法执行范围检查。")
        
        resolved_path_from_current = os.path.normpath(os.path.join(scope_dir, file_name))
        resolved_path_from_root = os.path.normpath(os.path.join(firmware_root, file_name))
        
        if os.path.exists(resolved_path_from_current) and os.path.isfile(resolved_path_from_current):
            resolved_path = resolved_path_from_current
        elif os.path.exists(resolved_path_from_root) and os.path.isfile(resolved_path_from_root):
            resolved_path = resolved_path_from_root
        else:
            resolved_path = resolved_path_from_current

        real_firmware_root = os.path.realpath(firmware_root)
        real_scope_dir = os.path.realpath(scope_dir)
        try:
            real_resolved_path = os.path.realpath(resolved_path)
        except FileNotFoundError:
            raise ValueError(f"在固件中未找到文件 '{file_name}'。")

        if not os.path.commonpath([real_resolved_path, real_firmware_root]) == real_firmware_root:
            raise ValueError(f"提供的路径 '{file_name}' 无效，可能包含 '..' 或指向固件根目录之外。")

        if not os.path.commonpath([real_resolved_path, real_scope_dir]) == real_scope_dir:
            current_dir_name = os.path.relpath(scope_dir, firmware_root)
            basename_only = os.path.basename(file_name)
            potential_correct_path = os.path.join(current_dir_name, basename_only)
            potential_full_path = os.path.join(firmware_root, potential_correct_path)
            
            if os.path.exists(potential_full_path) and os.path.isfile(potential_full_path):
                raise ValueError(
                    f"路径格式错误：你提供了 '{file_name}'，但必须使用相对于固件根目录的完整路径。"
                    f"你在目录 '{current_dir_name}' 中。要分析此目录中的文件 '{basename_only}'，"
                    f"请使用完整路径：'{potential_correct_path}'（而不是仅 '{basename_only}'）。"
                )
            else:
                raise ValueError(
                    f"访问被拒绝：文件 '{file_name}' 不在你的当前工作目录 '{current_dir_name}' 中。"
                    f"你严格限制在 '{current_dir_name}' 内分析文件。"
                    f"不允许跨目录分析。如果需要分析其他目录中的文件，"
                    f"请报告此限制并建议由具有适当范围的其他代理处理。"
                )

        if not os.path.isfile(resolved_path):
            raise ValueError(f"指定的路径 '{file_name}' 不是有效的文件。")
        
        sub_agent_context.set("file_path", resolved_path)
        sub_agent_context.set("file_name", os.path.basename(resolved_path))
        sub_agent_context.set("current_dir", os.path.dirname(resolved_path))
        return sub_agent_context

    def _build_sub_agent_prompt(self, usr_init_msg: Optional[str], **task_details: Any) -> str:
        task = task_details.get("task", f"未提供文件分析任务 #{task_details.get('task_index',-1)+1}。")

        usr_init_msg_content = usr_init_msg if usr_init_msg else "未提供用户初始请求"
        
        return (
            f"用户初始请求：\n{usr_init_msg_content}\n\n"
            f"当前任务：\n{task}"
        )


class ParallelDeepDirectoryAnalysisDelegator(ParallelBaseAssistant):
    name = "ParallelDeepDirectoryAnalysisDelegator"
    description = """
    深度目录分析委托器 - 将当前目录范围内多个子目录的分析任务分配给子代理并行处理。
    只能分析当前目录中的子目录（直接子目录或更深层的嵌套目录）。
    对于你作用域内的目录，使用简单的相对路径。
    适用于同时对多个子目录进行深度分析的任务。对于复杂任务或全面分析，强烈建议使用此委托器。
    """
    parameters = {
        "type": "object",
        "properties": {
            "dir_names": {
                "type": "array",
                "items": {
                    "type": "string",
                    "description": "相对于你当前目录的目录路径（例如，'hnap'、'init.d'）。你只能访问当前目录范围内的子目录。"
                },
                "description": "要并行分析的目录路径列表。使用相对于当前工作目录的路径。"
            },
            "run_in_background": {
                "type": "boolean",
                "description": "是否在后台运行此任务。",
                "default": False
            }
        },
        "required": ["dir_names"],
        "description": "包含当前目录范围内目录分析目标列表的对象。"
    }
    timeout = 9600

    def __init__(
        self,
        context: FlexibleContext,
        agent_class_to_create: Type[BaseAgent] = BaseAgent,
        default_sub_agent_tool_classes: Optional[List[Union[Type[ExecutableTool], ExecutableTool]]] = None,
        default_sub_agent_max_iterations: int = 10,
        sub_agent_system_prompt: Optional[str] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
        timeout: Optional[int] = None,
    ):
        final_name = name or ParallelDeepDirectoryAnalysisDelegator.name
        final_description = description or ParallelDeepDirectoryAnalysisDelegator.description

        super().__init__(
            context=context,
            agent_class_to_create=agent_class_to_create,
            default_sub_agent_tool_classes=default_sub_agent_tool_classes,
            default_sub_agent_max_iterations=default_sub_agent_max_iterations,
            sub_agent_system_prompt=sub_agent_system_prompt,
            name=final_name,
            description=final_description,
            timeout=timeout
        )

    def _extract_task_list(self, **kwargs: Any) -> List[Dict[str, Any]]:
        dir_names = kwargs.get("dir_names", [])
        return [{"dir_name": dir_name} for dir_name in dir_names]

    def _get_sub_agent_task_details(self, **task_item: Any) -> Dict[str, Any]:
        dir_name = task_item.get("dir_name")
        if not dir_name or not isinstance(dir_name, str):
            return {"task": "错误：并行分析需要一个有效的目录名。"}
        
        return {
            "task": f"专注于分析目录 '{dir_name}' 的内容，寻找可利用的信息和线索。",
            "dir_name": dir_name
        }

    def _prepare_sub_agent_context(self, sub_agent_context: FlexibleContext, **task_details: Any) -> FlexibleContext:
        dir_name = task_details.get("dir_name")

        if not dir_name or not isinstance(dir_name, str):
            raise ValueError("错误：分析需要一个有效的目录路径。")
        
        dir_name = dir_name.lstrip('/')

        firmware_root = self.context.get("base_path")
        if not firmware_root or not os.path.isdir(firmware_root):
            raise ValueError("上下文中缺少有效的固件根目录 'base_path'，无法解析路径。")

        scope_dir = self.context.get("current_dir")
        if not scope_dir or not os.path.isdir(scope_dir):
            raise ValueError("上下文中缺少有效的工作目录 'current_dir'，无法执行范围检查。")

        resolved_path_from_current = os.path.normpath(os.path.join(scope_dir, dir_name))
        resolved_path_from_root = os.path.normpath(os.path.join(firmware_root, dir_name))
        
        if os.path.exists(resolved_path_from_current) and os.path.isdir(resolved_path_from_current):
            resolved_path = resolved_path_from_current
        elif os.path.exists(resolved_path_from_root) and os.path.isdir(resolved_path_from_root):
            resolved_path = resolved_path_from_root
        else:
            resolved_path = resolved_path_from_current

        real_firmware_root = os.path.realpath(firmware_root)
        real_scope_dir = os.path.realpath(scope_dir)
        try:
            real_resolved_path = os.path.realpath(resolved_path)
        except FileNotFoundError:
            raise ValueError(f"在固件中未找到目录 '{dir_name}'。")

        if not os.path.commonpath([real_resolved_path, real_firmware_root]) == real_firmware_root:
            raise ValueError(f"提供的路径 '{dir_name}' 无效，可能包含 '..' 或指向固件根目录之外。")

        if not os.path.commonpath([real_resolved_path, real_scope_dir]) == real_scope_dir:
            current_dir_name = os.path.relpath(scope_dir, firmware_root)
            basename_only = os.path.basename(dir_name)
            potential_correct_path = os.path.join(current_dir_name, basename_only)
            potential_full_path = os.path.join(firmware_root, potential_correct_path)
            
            if os.path.exists(potential_full_path) and os.path.isdir(potential_full_path):
                raise ValueError(
                    f"路径格式错误：你提供了 '{dir_name}'，但必须使用相对于固件根目录的完整路径。"
                    f"你在目录 '{current_dir_name}' 中。要分析其子目录 '{basename_only}'，"
                    f"请使用完整路径：'{potential_correct_path}'（而不是仅 '{basename_only}'）。"
                )
            else:
                raise ValueError(
                    f"访问被拒绝：目录 '{dir_name}' 不在你的当前工作目录 '{current_dir_name}' 中。"
                    f"你严格限制在 '{current_dir_name}' 内分析子目录。"
                    f"不允许跨目录和向上目录分析。如果需要分析其他目录，"
                    f"请报告此限制并建议由具有适当范围的其他代理处理。"
                )

        if not os.path.isdir(resolved_path):
            raise ValueError(f"指定的路径 '{dir_name}' 不是有效的目录。")

        sub_agent_context.set("current_dir", resolved_path)
        return sub_agent_context

    def _build_sub_agent_prompt(self, usr_init_msg: Optional[str], **task_details: Any) -> str:
        task = task_details.get("task", f"未提供目录分析任务 #{task_details.get('task_index',-1)+1}。")

        usr_init_msg_content = usr_init_msg if usr_init_msg else "未提供用户初始请求"
        
        return (
            f"用户初始请求：\n{usr_init_msg_content}\n\n"
            f"当前任务：\n{task}"
        )


class DescriptiveFileAnalysisAssistant(BaseAssistant):
    name = "DescriptiveFileAnalysisAssistant"
    description = """
    用于对当前目录范围内指定文件进行深度分析的代理，带有自定义任务描述。
    只能分析当前目录或其子目录（任意深度）中的文件。
    对于你作用域内的文件，使用简单的相对路径。
    适用于具有特定指令的单个文件深度分析任务。你可以在观察单步结果后决定下一个分析任务。对于验证任务等有针对性的分析，强烈建议使用此代理。
    """
    parameters = {
        "type": "object",
        "properties": {
            "file_name": {
                "type": "string",
                "description": "相对于你当前目录的文件路径（例如，'config.php'、'hnap/Login.xml'）。你只能访问当前目录或其子目录中的文件。"
            },
            "task": {
                "type": "string",
                "description": "关于如何分析文件的具体任务描述。"
            },
            "run_in_background": {
                "type": "boolean",
                "description": "是否在后台运行此任务。",
                "default": False
            }
        },
        "required": ["file_name", "task"],
        "description": "包含文件分析目标和详细任务描述的对象。使用相对于当前工作目录的路径。"
    }

    def __init__(
        self,
        context: FlexibleContext,
        agent_class_to_create: Type[BaseAgent] = BaseAgent,
        default_sub_agent_tool_classes: Optional[List[Union[Type[ExecutableTool], ExecutableTool]]] = None,
        default_sub_agent_max_iterations: int = 10,
        sub_agent_system_prompt: Optional[str] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
        timeout: Optional[int] = None,
    ):
        final_name = name or DescriptiveFileAnalysisAssistant.name
        final_description = description or DescriptiveFileAnalysisAssistant.description

        super().__init__(
            context=context,
            agent_class_to_create=agent_class_to_create,
            default_sub_agent_tool_classes=default_sub_agent_tool_classes,
            default_sub_agent_max_iterations=default_sub_agent_max_iterations,
            sub_agent_system_prompt=sub_agent_system_prompt,
            name=final_name,
            description=final_description,
            timeout=timeout
        )

    def _get_sub_agent_task_details(self, **kwargs: Any) -> Dict[str, Any]:
        file_name = kwargs.get("file_name")
        task = kwargs.get("task")

        if not file_name or not isinstance(file_name, str):
            return {"task": "错误：分析需要一个有效的文件名。"}
        if not task:
            task = f"专注于分析文件 '{file_name}' 的内容，寻找可利用的信息。"
        
        return {
            "task": task,
            "file_name": file_name
        }

    def _prepare_sub_agent_context(self, sub_agent_context: FlexibleContext, **task_details: Any) -> FlexibleContext:
        file_name = task_details.get("file_name")

        if not file_name or not isinstance(file_name, str):
            raise ValueError("错误：分析需要一个有效的文件路径。")
        
        file_name = file_name.lstrip('/')

        firmware_root = self.context.get("base_path")
        if not firmware_root or not os.path.isdir(firmware_root):
            raise ValueError("上下文中缺少有效的固件根目录 'base_path'，无法解析路径。")

        scope_dir = self.context.get("current_dir")
        if not scope_dir or not os.path.isdir(scope_dir):
            raise ValueError("上下文中缺少有效的工作目录 'current_dir'，无法执行范围检查。")

        resolved_path_from_current = os.path.normpath(os.path.join(scope_dir, file_name))
        resolved_path_from_root = os.path.normpath(os.path.join(firmware_root, file_name))
        
        if os.path.exists(resolved_path_from_current) and os.path.isfile(resolved_path_from_current):
            resolved_path = resolved_path_from_current
        elif os.path.exists(resolved_path_from_root) and os.path.isfile(resolved_path_from_root):
            resolved_path = resolved_path_from_root
        else:
            resolved_path = resolved_path_from_current
        
        real_firmware_root = os.path.realpath(firmware_root)
        real_scope_dir = os.path.realpath(scope_dir)

        try:
            real_resolved_path = os.path.realpath(resolved_path)
        except FileNotFoundError:
             raise ValueError(f"在固件中未找到文件 '{file_name}'。")

        if not os.path.commonpath([real_resolved_path, real_firmware_root]) == real_firmware_root:
            raise ValueError(f"提供的路径 '{file_name}' 无效，可能包含 '..' 或指向固件根目录之外。")

        if not os.path.commonpath([real_resolved_path, real_scope_dir]) == real_scope_dir:
            current_dir_name = os.path.relpath(scope_dir, firmware_root)
            basename_only = os.path.basename(file_name)
            potential_correct_path = os.path.join(current_dir_name, basename_only)
            potential_full_path = os.path.join(firmware_root, potential_correct_path)
            
            if os.path.exists(potential_full_path) and os.path.isfile(potential_full_path):
                raise ValueError(
                    f"路径格式错误：你提供了 '{file_name}'，但必须使用相对于固件根目录的完整路径。"
                    f"你在目录 '{current_dir_name}' 中。要分析此目录中的文件 '{basename_only}'，"
                    f"请使用完整路径：'{potential_correct_path}'（而不是仅 '{basename_only}'）。"
                )
            else:
                raise ValueError(
                    f"访问被拒绝：文件 '{file_name}' 不在你的当前工作目录 '{current_dir_name}' 中。"
                    f"你严格限制在 '{current_dir_name}' 内分析文件。"
                    f"不允许跨目录分析。如果需要分析其他目录中的文件，"
                    f"请报告此限制并建议由具有适当范围的其他代理处理。"
                )

        if not os.path.isfile(resolved_path):
            raise ValueError(f"指定的路径 '{file_name}' 不是有效的文件。")

        sub_agent_context.set("file_path", resolved_path)
        sub_agent_context.set("file_name", os.path.basename(resolved_path))
        sub_agent_context.set("current_dir", os.path.dirname(resolved_path))
        return sub_agent_context

    def _build_sub_agent_prompt(self, usr_init_msg: Optional[str], **task_details: Any) -> str:
        task = task_details.get("task", "No file analysis task provided.")
        
        usr_init_msg_content = usr_init_msg if usr_init_msg else "未提供用户初始请求"
        
        return (
            f"用户初始请求：\n{usr_init_msg_content}\n\n"
            f"当前任务：\n{task}"
        )



class DescriptiveDirectoryAnalysisAssistant(BaseAssistant):
    name = "DescriptiveDirectoryAnalysisAssistant"
    description = """
    用于对当前目录范围内指定子目录进行深度分析的代理，带有自定义任务描述。
    只能分析当前目录中的子目录（直接子目录或更深层的嵌套目录）。
    对于你作用域内的目录，使用简单的相对路径。
    适用于具有特定指令的单个子目录深度分析任务。你可以在观察单步结果后决定下一个分析任务。对于验证任务等有针对性的分析，强烈建议使用此代理。
    """
    parameters = {
        "type": "object",
        "properties": {
            "dir_name": {
                "type": "string",
                "description": "相对于你当前目录的目录路径（例如，'hnap'、'init.d'）。你只能访问当前目录范围内的子目录。"
            },
            "task": {
                "type": "string",
                "description": "关于如何分析目录的具体任务描述。"
            },
            "run_in_background": {
                "type": "boolean",
                "description": "是否在后台运行此任务。",
                "default": False
            }
        },
        "required": ["dir_name", "task"],
        "description": "包含目录分析目标和详细任务描述的对象。使用相对于当前工作目录的路径。"
    }

    def __init__(
        self,
        context: FlexibleContext,
        agent_class_to_create: Type[BaseAgent] = BaseAgent,
        default_sub_agent_tool_classes: Optional[List[Union[Type[ExecutableTool], ExecutableTool]]] = None,
        default_sub_agent_max_iterations: int = 10,
        sub_agent_system_prompt: Optional[str] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
        timeout: Optional[int] = None,
    ):
        final_name = name or DescriptiveDirectoryAnalysisAssistant.name
        final_description = description or DescriptiveDirectoryAnalysisAssistant.description

        super().__init__(
            context=context,
            agent_class_to_create=agent_class_to_create,
            default_sub_agent_tool_classes=default_sub_agent_tool_classes,
            default_sub_agent_max_iterations=default_sub_agent_max_iterations,
            sub_agent_system_prompt=sub_agent_system_prompt,
            name=final_name,
            description=final_description,
            timeout=timeout
        )

    def _get_sub_agent_task_details(self, **kwargs: Any) -> Dict[str, Any]:
        dir_name = kwargs.get("dir_name")
        task = kwargs.get("task")

        if not dir_name or not isinstance(dir_name, str):
            return {"task": "错误：分析需要一个有效的目录名。"}
        
        if not task:
            task = f"专注于分析目录 '{dir_name}' 的内容，寻找可利用的信息和线索。"
        
        return {
            "task": task,
            "dir_name": dir_name
        }

    def _prepare_sub_agent_context(self, sub_agent_context: FlexibleContext, **task_details: Any) -> FlexibleContext:
        dir_name = task_details.get("dir_name")

        if not dir_name or not isinstance(dir_name, str):
            raise ValueError("错误：分析需要一个有效的目录路径。")

        dir_name = dir_name.lstrip('/')

        firmware_root = self.context.get("base_path")
        if not firmware_root or not os.path.isdir(firmware_root):
            raise ValueError("上下文中缺少有效的固件根目录 'base_path'，无法解析路径。")

        scope_dir = self.context.get("current_dir")
        if not scope_dir or not os.path.isdir(scope_dir):
            raise ValueError("上下文中缺少有效的工作目录 'current_dir'，无法执行范围检查。")

        resolved_path_from_current = os.path.normpath(os.path.join(scope_dir, dir_name))
        resolved_path_from_root = os.path.normpath(os.path.join(firmware_root, dir_name))
        
        if os.path.exists(resolved_path_from_current) and os.path.isdir(resolved_path_from_current):
            resolved_path = resolved_path_from_current
        elif os.path.exists(resolved_path_from_root) and os.path.isdir(resolved_path_from_root):
            resolved_path = resolved_path_from_root
        else:
            resolved_path = resolved_path_from_current

        real_firmware_root = os.path.realpath(firmware_root)
        real_scope_dir = os.path.realpath(scope_dir)
        try:
            real_resolved_path = os.path.realpath(resolved_path)
        except FileNotFoundError:
            raise ValueError(f"在固件中未找到目录 '{dir_name}'。")

        if not os.path.commonpath([real_resolved_path, real_firmware_root]) == real_firmware_root:
            raise ValueError(f"提供的路径 '{dir_name}' 无效，可能包含 '..' 或指向固件根目录之外。")

        if not os.path.commonpath([real_resolved_path, real_scope_dir]) == real_scope_dir:
            current_dir_name = os.path.relpath(scope_dir, firmware_root)
            basename_only = os.path.basename(dir_name)
            potential_correct_path = os.path.join(current_dir_name, basename_only)
            potential_full_path = os.path.join(firmware_root, potential_correct_path)
            
            if os.path.exists(potential_full_path) and os.path.isdir(potential_full_path):
                raise ValueError(
                    f"路径格式错误：你提供了 '{dir_name}'，但必须使用相对于固件根目录的完整路径。"
                    f"你在目录 '{current_dir_name}' 中。要分析其子目录 '{basename_only}'，"
                    f"请使用完整路径：'{potential_correct_path}'（而不是仅 '{basename_only}'）。"
                )
            else:
                raise ValueError(
                    f"访问被拒绝：目录 '{dir_name}' 不在你的当前工作目录 '{current_dir_name}' 中。"
                    f"你严格限制在 '{current_dir_name}' 内分析子目录。"
                    f"不允许跨目录和向上目录分析。如果需要分析其他目录，"
                    f"请报告此限制并建议由具有适当范围的其他代理处理。"
                )

        if not os.path.isdir(resolved_path):
            raise ValueError(f"指定的路径 '{dir_name}' 不是有效的目录。")

        sub_agent_context.set("current_dir", resolved_path)
        sub_agent_context.set("file_path", None)
        return sub_agent_context

    def _build_sub_agent_prompt(self, usr_init_msg: Optional[str], **task_details: Any) -> str:
        task = task_details.get("task", "No directory analysis task provided.")
        
        usr_init_msg_content = usr_init_msg if usr_init_msg else "未提供用户初始请求"
        
        return (
            f"用户初始请求：\n{usr_init_msg_content}\n\n"
            f"当前任务：\n{task}"
        )