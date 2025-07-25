import os
from typing import Any, Dict, Optional, List, Union, Type

from agent.base import BaseAgent
from agent.tools.basetool import FlexibleContext, ExecutableTool
from agent.core.assitants import BaseAssistant, ParallelBaseAssistant

class ParallelFunctionDelegator(ParallelBaseAssistant):
    name = "FunctionDelegator"
    description = """
    Function Analysis Delegator - An agent specialized in analyzing function call chains in binary files. Its responsibility is to forward-trace the flow path of tainted data between function calls. You can delegate potential external entry points to this agent for in-depth tracking.
    """

    parameters = {
        "type": "object",
        "properties": {
            "tasks": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "task_description": {
                            "type": "string",
                            "description": "Detailed description of the function analysis task, must include:\n- Target function address and signature\n- Complete call context\n- Known parameter values and constraints\n- Taint source or data flow to be traced"
                        },
                        "task_context": {
                            "type": "string",
                            "description": "(Optional) Analysis context summary, including:\n- Call chain history\n- Known variable states\n- Precondition assumptions\n- Relevant memory/register states"
                        }
                    },
                    "required": ["task_description"]
                },
                "description": "A list of function tasks that need to be analyzed."
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
                 description: Optional[str] = None
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
            description=final_description
        )


class DeepFileAnalysisAssistant(BaseAssistant):
    name = "DeepFileAnalysisAssistant"
    description = """
    An agent for in-depth analysis of a specified file in the current directory.
    The parameter is the file path relative to the firmware root directory.
    Suitable for in-depth analysis tasks of a single file. You can decide the next analysis step after observing the result of a single step. This agent is highly recommended for targeted analysis, such as verification tasks.
    """
    parameters = {
        "type": "object",
        "properties": {
            "file_name": {
                "type": "string",
                "description": "The path of the file to be analyzed (e.g., 'etc/passwd'), relative to the firmware root directory."
            }
        },
        "required": ["file_name"],
        "description": "An object containing the file analysis target, with the file path relative to the firmware root directory."
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
        description: Optional[str] = None
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
            description=final_description
        )

    def _get_sub_agent_task_details(self, **kwargs: Any) -> Dict[str, Any]:
        file_name = kwargs.get("file_name")
        if not file_name or not isinstance(file_name, str):
            return {"task_description": "Error: A valid file name is required for analysis."}

        return {
            "task_description": f"Focus on analyzing the content of the file '{file_name}' to find exploitable information.",
            "file_name": file_name
        }

    def _prepare_sub_agent_context(self, sub_agent_context: FlexibleContext, **task_details: Any) -> FlexibleContext:
        file_name = task_details.get("file_name")

        if not file_name or not isinstance(file_name, str):
            raise ValueError("Error: A valid file path is required for analysis.")

        file_name = file_name.lstrip('/')

        firmware_root = self.context.get("base_path")
        if not firmware_root or not os.path.isdir(firmware_root):
            raise ValueError("Missing a valid firmware root directory 'base_path' in the context, cannot resolve path.")

        scope_dir = self.context.get("current_dir")
        if not scope_dir or not os.path.isdir(scope_dir):
            raise ValueError("Missing a valid working directory 'current_dir' in the context, cannot perform scope check.")

        resolved_path = os.path.normpath(os.path.join(firmware_root, file_name))

        real_firmware_root = os.path.realpath(firmware_root)
        real_scope_dir = os.path.realpath(scope_dir)

        try:
            real_resolved_path = os.path.realpath(resolved_path)
        except FileNotFoundError:
             raise ValueError(f"File '{file_name}' not found in the firmware.")


        if not os.path.commonpath([real_resolved_path, real_firmware_root]) == real_firmware_root:
            raise ValueError(f"The provided path '{file_name}' is invalid, it may contain '..' or point outside the firmware root directory.")

        if not os.path.commonpath([real_resolved_path, real_scope_dir]) == real_scope_dir:
            raise ValueError(f"The specified file '{file_name}' is not within the current working directory '{os.path.relpath(scope_dir, firmware_root)}'.")

        if not os.path.isfile(resolved_path):
            raise ValueError(f"The specified path '{file_name}' is not a valid file.")

        sub_agent_context.set("file_path", resolved_path)
        sub_agent_context.set("file_name", os.path.basename(resolved_path))
        sub_agent_context.set("current_dir", os.path.dirname(resolved_path))
        return sub_agent_context

    def _build_sub_agent_prompt(self, usr_init_msg: Optional[str], **task_details: Any) -> str:
        task_description = task_details.get("task_description", "No file analysis task description provided.")

        usr_init_msg_content = usr_init_msg if usr_init_msg else "No user initial request provided"

        return (
            f"The user's initial request is:\n{usr_init_msg_content}\n\n"
            f"Current task:\n{task_description}"
        )

class DeepDirectoryAnalysisAssistant(BaseAssistant):
    name = "DeepDirectoryAnalysisAssistant"
    description = """
    An agent for in-depth analysis of a specified subdirectory in the current directory.
    The parameter is the directory path relative to the firmware root directory.
    Suitable for in-depth analysis tasks of a single direct subdirectory. You can decide the next analysis step after observing the result of a single step. This agent is highly recommended for targeted analysis, such as verification tasks.
    """
    parameters = {
        "type": "object",
        "properties": {
            "dir_name": {
                "type": "string",
                "description": "The path of the directory to be analyzed (e.g., 'etc/init.d'), relative to the firmware root directory."
            }
        },
        "required": ["dir_name"],
        "description": "An object containing the directory analysis target, with the directory path relative to the firmware root directory."
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
        description: Optional[str] = None
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
            description=final_description
        )

    def _get_sub_agent_task_details(self, **kwargs: Any) -> Dict[str, Any]:
        dir_name = kwargs.get("dir_name")
        if not dir_name or not isinstance(dir_name, str):
            return {"task_description": "Error: A valid directory name is required for analysis."}

        return {
            "task_description": f"Focus on analyzing the content of the directory '{dir_name}' to find exploitable information and clues.",
            "dir_name": dir_name
        }

    def _prepare_sub_agent_context(self, sub_agent_context: FlexibleContext, **task_details: Any) -> FlexibleContext:
        dir_name = task_details.get("dir_name")

        if not dir_name or not isinstance(dir_name, str):
            raise ValueError("Error: A valid directory path is required for analysis.")

        dir_name = dir_name.lstrip('/')

        firmware_root = self.context.get("base_path")
        if not firmware_root or not os.path.isdir(firmware_root):
            raise ValueError("Missing a valid firmware root directory 'base_path' in the context, cannot resolve path.")

        scope_dir = self.context.get("current_dir")
        if not scope_dir or not os.path.isdir(scope_dir):
            raise ValueError("Missing a valid working directory 'current_dir' in the context, cannot perform scope check.")

        resolved_path = os.path.normpath(os.path.join(firmware_root, dir_name))

        real_firmware_root = os.path.realpath(firmware_root)
        real_scope_dir = os.path.realpath(scope_dir)
        try:
            real_resolved_path = os.path.realpath(resolved_path)
        except FileNotFoundError:
            raise ValueError(f"Directory '{dir_name}' not found in the firmware.")

        if not os.path.commonpath([real_resolved_path, real_firmware_root]) == real_firmware_root:
            raise ValueError(f"The provided path '{dir_name}' is invalid, it may contain '..' or point outside the firmware root directory.")

        if not os.path.commonpath([real_resolved_path, real_scope_dir]) == real_scope_dir:
            raise ValueError(f"The specified directory '{dir_name}' is not within the current working directory '{os.path.relpath(scope_dir, firmware_root)}'.")

        if not os.path.isdir(resolved_path):
            raise ValueError(f"The specified path '{dir_name}' is not a valid directory.")

        sub_agent_context.set("current_dir", resolved_path)
        sub_agent_context.set("file_path", None)
        return sub_agent_context

    def _build_sub_agent_prompt(self, usr_init_msg: Optional[str], **task_details: Any) -> str:
        task_description = task_details.get("task_description", "No directory analysis task description provided.")

        usr_init_msg_content = usr_init_msg if usr_init_msg else "No user initial request provided"

        return (
            f"The user's initial request is:\n{usr_init_msg_content}\n\n"
            f"Current task:\n{task_description}"
        )

class ParallelDeepFileAnalysisDelegator(ParallelBaseAssistant):
    name = "ParallelDeepFileAnalysisDelegator"
    description = """
    Deep File Analysis Delegator - Dispatches analysis tasks for multiple files in the current directory to sub-agents for parallel processing.
    The parameter is a list of file paths relative to the firmware root directory.
    Suitable for in-depth analysis tasks of multiple files in the current directory simultaneously. This delegator is highly recommended for complex tasks or comprehensive analysis.
    """
    parameters = {
        "type": "object",
        "properties": {
            "file_names": {
                "type": "array",
                "items": {
                    "type": "string",
                    "description": "The path of the file to be analyzed (e.g., 'etc/rcS'), relative to the firmware root directory."
                },
                "description": "A list of file paths to be analyzed in parallel, relative to the firmware root directory."
            }
        },
        "required": ["file_names"],
        "description": "An object containing a list of file analysis targets."
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
        description: Optional[str] = None
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
            description=final_description
        )

    def _extract_task_list(self, **kwargs: Any) -> List[Dict[str, Any]]:
        file_names = kwargs.get("file_names", [])
        return [{"file_name": file_name} for file_name in file_names]

    def _get_sub_agent_task_details(self, **task_item: Any) -> Dict[str, Any]:
        file_name = task_item.get("file_name")
        if not file_name or not isinstance(file_name, str):
            return {"task_description": "Error: A valid file name is required for parallel analysis."}

        return {
            "task_description": f"Focus on analyzing the content of the file '{file_name}' to find exploitable information and clues.",
            "file_name": file_name
        }

    def _prepare_sub_agent_context(self, sub_agent_context: FlexibleContext, **task_details: Any) -> FlexibleContext:
        file_name = task_details.get("file_name")

        if not file_name or not isinstance(file_name, str):
            raise ValueError("Error: A valid file path is required for analysis.")

        file_name = file_name.lstrip('/')

        firmware_root = self.context.get("base_path")
        if not firmware_root or not os.path.isdir(firmware_root):
            raise ValueError("Missing a valid firmware root directory 'base_path' in the context, cannot resolve path.")

        scope_dir = self.context.get("current_dir")
        if not scope_dir or not os.path.isdir(scope_dir):
            raise ValueError("Missing a valid working directory 'current_dir' in the context, cannot perform scope check.")

        resolved_path = os.path.normpath(os.path.join(firmware_root, file_name))

        real_firmware_root = os.path.realpath(firmware_root)
        real_scope_dir = os.path.realpath(scope_dir)
        try:
            real_resolved_path = os.path.realpath(resolved_path)
        except FileNotFoundError:
            raise ValueError(f"File '{file_name}' not found in the firmware.")

        if not os.path.commonpath([real_resolved_path, real_firmware_root]) == real_firmware_root:
            raise ValueError(f"The provided path '{file_name}' is invalid, it may contain '..' or point outside the firmware root directory.")

        if not os.path.commonpath([real_resolved_path, real_scope_dir]) == real_scope_dir:
            raise ValueError(f"The specified file '{file_name}' is not within the current working directory '{os.path.relpath(scope_dir, firmware_root)}'.")

        if not os.path.isfile(resolved_path):
            raise ValueError(f"The specified path '{file_name}' is not a valid file.")

        sub_agent_context.set("file_path", resolved_path)
        sub_agent_context.set("file_name", os.path.basename(resolved_path))
        sub_agent_context.set("current_dir", os.path.dirname(resolved_path))
        return sub_agent_context

    def _build_sub_agent_prompt(self, usr_init_msg: Optional[str], **task_details: Any) -> str:
        task_description = task_details.get("task_description", f"No file analysis task description provided for task #{task_details.get('task_index',-1)+1}.")

        usr_init_msg_content = usr_init_msg if usr_init_msg else "No user initial request provided"

        return (
            f"The user's initial request is:\n{usr_init_msg_content}\n\n"
            f"Current task:\n{task_description}"
        )

class ParallelDeepDirectoryAnalysisDelegator(ParallelBaseAssistant):
    name = "ParallelDeepDirectoryAnalysisDelegator"
    description = """
    Deep Directory Analysis Delegator - Dispatches analysis tasks for multiple subdirectories in the current directory to sub-agents for parallel processing.
    The parameter is a list of directory paths relative to the firmware root directory.
    Suitable for in-depth analysis tasks of multiple subdirectories in the current directory simultaneously. This delegator is highly recommended for complex tasks or comprehensive analysis.
    """
    parameters = {
        "type": "object",
        "properties": {
            "dir_names": {
                "type": "array",
                "items": {
                    "type": "string",
                    "description": "The path of the directory to be analyzed (e.g., 'etc/init.d'), relative to the firmware root directory."
                },
                "description": "A list of directory paths to be analyzed in parallel, relative to the firmware root directory."
            }
        },
        "required": ["dir_names"],
        "description": "An object containing a list of directory analysis targets."
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
        description: Optional[str] = None
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
            description=final_description
        )

    def _extract_task_list(self, **kwargs: Any) -> List[Dict[str, Any]]:
        dir_names = kwargs.get("dir_names", [])
        return [{"dir_name": dir_name} for dir_name in dir_names]

    def _get_sub_agent_task_details(self, **task_item: Any) -> Dict[str, Any]:
        dir_name = task_item.get("dir_name")
        if not dir_name or not isinstance(dir_name, str):
            return {"task_description": "Error: A valid directory name is required for parallel analysis."}

        return {
            "task_description": f"Focus on analyzing the content of the directory '{dir_name}' to find exploitable information and clues.",
            "dir_name": dir_name
        }

    def _prepare_sub_agent_context(self, sub_agent_context: FlexibleContext, **task_details: Any) -> FlexibleContext:
        dir_name = task_details.get("dir_name")

        if not dir_name or not isinstance(dir_name, str):
            raise ValueError("Error: A valid directory path is required for analysis.")

        dir_name = dir_name.lstrip('/')

        firmware_root = self.context.get("base_path")
        if not firmware_root or not os.path.isdir(firmware_root):
            raise ValueError("Missing a valid firmware root directory 'base_path' in the context, cannot resolve path.")

        scope_dir = self.context.get("current_dir")
        if not scope_dir or not os.path.isdir(scope_dir):
            raise ValueError("Missing a valid working directory 'current_dir' in the context, cannot perform scope check.")

        resolved_path = os.path.normpath(os.path.join(firmware_root, dir_name))

        real_firmware_root = os.path.realpath(firmware_root)
        real_scope_dir = os.path.realpath(scope_dir)
        try:
            real_resolved_path = os.path.realpath(resolved_path)
        except FileNotFoundError:
            raise ValueError(f"Directory '{dir_name}' not found in the firmware.")

        if not os.path.commonpath([real_resolved_path, real_firmware_root]) == real_firmware_root:
            raise ValueError(f"The provided path '{dir_name}' is invalid, it may contain '..' or point outside the firmware root directory.")

        if not os.path.commonpath([real_resolved_path, real_scope_dir]) == real_scope_dir:
            raise ValueError(f"The specified directory '{dir_name}' is not within the current working directory '{os.path.relpath(scope_dir, firmware_root)}'.")

        if not os.path.isdir(resolved_path):
            raise ValueError(f"The specified path '{dir_name}' is not a valid directory.")

        sub_agent_context.set("current_dir", resolved_path)
        return sub_agent_context

    def _build_sub_agent_prompt(self, usr_init_msg: Optional[str], **task_details: Any) -> str:
        task_description = task_details.get("task_description", f"No directory analysis task description provided for task #{task_details.get('task_index',-1)+1}.")

        usr_init_msg_content = usr_init_msg if usr_init_msg else "No user initial request provided"

        return (
            f"The user's initial request is:\n{usr_init_msg_content}\n\n"
            f"Current task:\n{task_description}"
        )

class DescriptiveFileAnalysisAssistant(BaseAssistant):
    name = "DescriptiveFileAnalysisAssistant"
    description = """
    An agent for in-depth analysis of a specified file in the current directory.
    The parameter is the file path relative to the firmware root directory.
    Suitable for in-depth analysis of a single file where a specific task description is required. You can decide the next analysis step after observing the result of a single step. This agent is highly recommended for targeted analysis, such as verification tasks.
    """
    parameters = {
        "type": "object",
        "properties": {
            "file_name": {
                "type": "string",
                "description": "The path of the file to be analyzed (e.g., 'etc/passwd'), relative to the firmware root directory."
            },
            "task_description": {
                "type": "string",
                "description": "A specific task description on how to analyze the file."
            }
        },
        "required": ["file_name", "task_description"],
        "description": "An object containing the file analysis target and a detailed task description."
    }

    def __init__(
        self,
        context: FlexibleContext,
        agent_class_to_create: Type[BaseAgent] = BaseAgent,
        default_sub_agent_tool_classes: Optional[List[Union[Type[ExecutableTool], ExecutableTool]]] = None,
        default_sub_agent_max_iterations: int = 10,
        sub_agent_system_prompt: Optional[str] = None,
        name: Optional[str] = None,
        description: Optional[str] = None
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
            description=final_description
        )

    def _get_sub_agent_task_details(self, **kwargs: Any) -> Dict[str, Any]:
        file_name = kwargs.get("file_name")
        task_description = kwargs.get("task_description")

        if not file_name or not isinstance(file_name, str):
            return {"task_description": "Error: A valid file name is required for analysis."}
        if not task_description:
            task_description = f"Focus on analyzing the content of the file '{file_name}' to find exploitable information."

        return {
            "task_description": task_description,
            "file_name": file_name
        }

    def _prepare_sub_agent_context(self, sub_agent_context: FlexibleContext, **task_details: Any) -> FlexibleContext:
        file_name = task_details.get("file_name")

        if not file_name or not isinstance(file_name, str):
            raise ValueError("Error: A valid file path is required for analysis.")

        file_name = file_name.lstrip('/')

        firmware_root = self.context.get("base_path")
        if not firmware_root or not os.path.isdir(firmware_root):
            raise ValueError("Missing a valid firmware root directory 'base_path' in the context, cannot resolve path.")

        scope_dir = self.context.get("current_dir")
        if not scope_dir or not os.path.isdir(scope_dir):
            raise ValueError("Missing a valid working directory 'current_dir' in the context, cannot perform scope check.")

        resolved_path = os.path.normpath(os.path.join(firmware_root, file_name))

        real_firmware_root = os.path.realpath(firmware_root)
        real_scope_dir = os.path.realpath(scope_dir)

        try:
            real_resolved_path = os.path.realpath(resolved_path)
        except FileNotFoundError:
             raise ValueError(f"File '{file_name}' not found in the firmware.")


        if not os.path.commonpath([real_resolved_path, real_firmware_root]) == real_firmware_root:
            raise ValueError(f"The provided path '{file_name}' is invalid, it may contain '..' or point outside the firmware root directory.")

        if not os.path.commonpath([real_resolved_path, real_scope_dir]) == real_scope_dir:
            raise ValueError(f"The specified file '{file_name}' is not within the current working directory '{os.path.relpath(scope_dir, firmware_root)}'.")

        if not os.path.isfile(resolved_path):
            raise ValueError(f"The specified path '{file_name}' is not a valid file.")

        sub_agent_context.set("file_path", resolved_path)
        sub_agent_context.set("file_name", os.path.basename(resolved_path))
        sub_agent_context.set("current_dir", os.path.dirname(resolved_path))
        return sub_agent_context

    def _build_sub_agent_prompt(self, usr_init_msg: Optional[str], **task_details: Any) -> str:
        task_description = task_details.get("task_description", "No file analysis task description provided.")

        usr_init_msg_content = usr_init_msg if usr_init_msg else "No user initial request provided"

        return (
            f"The user's initial request is:\n{usr_init_msg_content}\n\n"
            f"Current task:\n{task_description}"
        )


class DescriptiveDirectoryAnalysisAssistant(BaseAssistant):
    name = "DescriptiveDirectoryAnalysisAssistant"
    description = """
    An agent for in-depth analysis of a specified subdirectory in the current directory.
    The parameter is the directory path relative to the firmware root directory.
    Suitable for in-depth analysis of a single direct subdirectory where a specific task description is required. You can decide the next analysis step after observing the result of a single step. This agent is highly recommended for targeted analysis, such as verification tasks.
    """
    parameters = {
        "type": "object",
        "properties": {
            "dir_name": {
                "type": "string",
                "description": "The path of the directory to be analyzed (e.g., 'etc/init.d'), relative to the firmware root directory."
            },
            "task_description": {
                "type": "string",
                "description": "A specific task description on how to analyze the directory."
            }
        },
        "required": ["dir_name", "task_description"],
        "description": "An object containing the directory analysis target and a detailed task description."
    }

    def __init__(
        self,
        context: FlexibleContext,
        agent_class_to_create: Type[BaseAgent] = BaseAgent,
        default_sub_agent_tool_classes: Optional[List[Union[Type[ExecutableTool], ExecutableTool]]] = None,
        default_sub_agent_max_iterations: int = 10,
        sub_agent_system_prompt: Optional[str] = None,
        name: Optional[str] = None,
        description: Optional[str] = None
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
            description=final_description
        )

    def _get_sub_agent_task_details(self, **kwargs: Any) -> Dict[str, Any]:
        dir_name = kwargs.get("dir_name")
        task_description = kwargs.get("task_description")

        if not dir_name or not isinstance(dir_name, str):
            return {"task_description": "Error: A valid directory name is required for analysis."}

        if not task_description:
            task_description = f"Focus on analyzing the content of the directory '{dir_name}' to find exploitable information and clues."

        return {
            "task_description": task_description,
            "dir_name": dir_name
        }

    def _prepare_sub_agent_context(self, sub_agent_context: FlexibleContext, **task_details: Any) -> FlexibleContext:
        dir_name = task_details.get("dir_name")

        if not dir_name or not isinstance(dir_name, str):
            raise ValueError("Error: A valid directory path is required for analysis.")

        dir_name = dir_name.lstrip('/')

        firmware_root = self.context.get("base_path")
        if not firmware_root or not os.path.isdir(firmware_root):
            raise ValueError("Missing a valid firmware root directory 'base_path' in the context, cannot resolve path.")

        scope_dir = self.context.get("current_dir")
        if not scope_dir or not os.path.isdir(scope_dir):
            raise ValueError("Missing a valid working directory 'current_dir' in the context, cannot perform scope check.")

        resolved_path = os.path.normpath(os.path.join(firmware_root, dir_name))

        real_firmware_root = os.path.realpath(firmware_root)
        real_scope_dir = os.path.realpath(scope_dir)
        try:
            real_resolved_path = os.path.realpath(resolved_path)
        except FileNotFoundError:
            raise ValueError(f"Directory '{dir_name}' not found in the firmware.")

        if not os.path.commonpath([real_resolved_path, real_firmware_root]) == real_firmware_root:
            raise ValueError(f"The provided path '{dir_name}' is invalid, it may contain '..' or point outside the firmware root directory.")

        if not os.path.commonpath([real_resolved_path, real_scope_dir]) == real_scope_dir:
            raise ValueError(f"The specified directory '{dir_name}' is not within the current working directory '{os.path.relpath(scope_dir, firmware_root)}'.")

        if not os.path.isdir(resolved_path):
            raise ValueError(f"The specified path '{dir_name}' is not a valid directory.")

        sub_agent_context.set("current_dir", resolved_path)
        sub_agent_context.set("file_path", None)
        return sub_agent_context

    def _build_sub_agent_prompt(self, usr_init_msg: Optional[str], **task_details: Any) -> str:
        task_description = task_details.get("task_description", "No directory analysis task description provided.")

        usr_init_msg_content = usr_init_msg if usr_init_msg else "No user initial request provided"

        return (
            f"The user's initial request is:\n{usr_init_msg_content}\n\n"
            f"Current task:\n{task_description}"
        )
