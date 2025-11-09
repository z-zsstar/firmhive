import json
import traceback
import threading

from typing import Optional, List, Type, Union, Any, Dict

from agent.base import BaseAgent
from agent.core.builder import AgentConfig, build_agent
from agent.tools.basetool import FlexibleContext, ExecutableTool

class BaseAssistant(ExecutableTool):
    name = "TaskDelegator"
    description = """
    任务委托器 - 用于将子任务委托给子代理进行处理。

    适用场景：
    在获得单步任务的结果后再决定下一个分析步骤。
    """
    parameters = {
        "type": "object",
        "properties": {
            "task": {
                "type": "string",
                "description": "要执行的子任务的详细描述。请指定分析对象。"
            },
            "run_in_background": {
                "type": "boolean",
                "description": "是否在后台运行此任务。",
                "default": False
            }
        },
        "required": ["task"]
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
        super().__init__(context)
        self.agent_class_to_create = agent_class_to_create
        self.default_sub_agent_tool_classes = default_sub_agent_tool_classes if default_sub_agent_tool_classes is not None else []
        self.default_sub_agent_max_iterations = default_sub_agent_max_iterations
        self.sub_agent_system_prompt = sub_agent_system_prompt

        if name is not None:
            self.name = name
        if description is not None:
            self.description = description

        if timeout is not None:
            self.timeout = timeout

    def _get_sub_agent_task_details(self, **kwargs: Any) -> Dict[str, Any]:
        """
        Extract and process the details of a single task from **kwargs of the execute method.
        Subclasses should override this method to extract task details from their specific parameters.
        The returned dict will be passed to _prepare_sub_agent_context and _build_sub_agent_prompt.
        It must contain at least a 'task' key.
        """
        task = kwargs.get("task", "")
        if not isinstance(task, str):
            return {"task": ""}
        return {"task": task}

    def _prepare_sub_agent_context(self, sub_agent_context: FlexibleContext, **task_details: Any) -> FlexibleContext:
        """
        Prepare the context for the sub-agent before creation.
        **task_details contains processed task parameters returned from _get_sub_agent_task_details.
        Subclasses can override this method to add task-specific information to the context.
        """
        return sub_agent_context

    def _build_sub_agent_prompt(self, usr_init_msg: Optional[str], **task_details: Any) -> str:
        """
        Build the full task prompt for the sub-agent.
        It uses the processed task details returned from _get_sub_agent_task_details.
        """
        task = task_details.get("task")

        usr_init_msg_content = usr_init_msg if usr_init_msg else "未提供用户初始请求"
        task_content = task if task else "未提供任务"

        return (
            f"用户初始请求：\n{usr_init_msg_content}\n"
            f"当前具体任务：\n{task_content}"
        )

    def execute(self, **kwargs: Any) -> str:
        # Check if this should run in background
        run_in_background = kwargs.get("run_in_background", False)
        if run_in_background:
            self.is_background_task = True
        
        usr_init_msg = self.context.get("user_input")
        task_for_error_log: Optional[str] = "Unknown task"

        try:
            task_details = self._get_sub_agent_task_details(**kwargs)
            task = task_details.get("task")
            task_for_error_log = str(task) if task else "Not extracted"

            if not task:
                return "错误：无法从任务输入中为子代理提取 'task'。"

            full_task_prompt = self._build_sub_agent_prompt(usr_init_msg, **task_details)

            sub_agent_base_context = self.context.copy()
            try:
                sub_agent_prepared_context = self._prepare_sub_agent_context(sub_agent_base_context, **task_details)
            except Exception as e:
                return f"错误：{str(e)}"

            sub_agent_instance_name = f"{self.name}_sub_agent"

            sub_agent_config = AgentConfig(
                agent_class=self.agent_class_to_create,
                tool_configs=self.default_sub_agent_tool_classes,
                system_prompt=self.sub_agent_system_prompt,
                max_iterations=self.default_sub_agent_max_iterations,
                agent_instance_name=sub_agent_instance_name,
            )

            sub_agent = build_agent(
                agent_config=sub_agent_config,
                context=sub_agent_prepared_context,
            )

            result_from_sub_agent = sub_agent.run(full_task_prompt)
            return result_from_sub_agent

        except Exception as e:
            error_snippet = task_for_error_log[:70]
            error_message_for_return = f"错误：{self.name} 执行子任务失败（任务片段：'{error_snippet}'）：{type(e).__name__} - {str(e)}"

            log_error_message = f"{self.name} 在子任务准备或委托期间出错（任务片段：'{error_snippet}...'）：{type(e).__name__} - {str(e)}"
            logger = getattr(self, 'logger', None)
            if logger:
                logger.error(log_error_message, exc_info=True)
            else:
                print(f"{self.name} 错误：{log_error_message}")
                print(traceback.format_exc())
            return f"执行子任务时发生错误：{error_message_for_return}"


class ParallelBaseAssistant(ExecutableTool):
    name = "ParallelTaskDelegator"
    description = """
    任务委托器 - 用于将多个子任务分配给子代理并行执行。

    适用场景：
    1. 需要将复杂任务分解为多个独立的子任务进行处理。
    2. 子任务之间没有严格的执行顺序依赖。
    3. 建议用于大规模和复杂任务，可以并行执行多个子任务以提高效率。
    """
    parameters = {
        "type": "object",
        "properties": {
            "tasks": {
                "type": "array",
                "items": {
                    "type": "string",
                    "description": "要执行的子任务的详细描述。每个任务描述都是独立的，应指定分析对象。"
                },
                "description": "要分配给子代理并行执行的独立任务描述列表。"
            },
            "run_in_background": {
                "type": "boolean",
                "description": "是否在后台运行此任务。",
                "default": False
            }
        },
        "required": ["tasks"]
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
        super().__init__(context)
        self.agent_class_to_create = agent_class_to_create
        self.default_sub_agent_tool_classes = default_sub_agent_tool_classes if default_sub_agent_tool_classes is not None else []
        self.default_sub_agent_max_iterations = default_sub_agent_max_iterations
        self.sub_agent_system_prompt = sub_agent_system_prompt

        if name is not None:
            self.name = name
        if description is not None:
            self.description = description

        if timeout is not None:
            self.timeout = timeout

    def _extract_task_list(self, **kwargs: Any) -> List[str]:
        """
        Extract the list of tasks to be processed in parallel from **kwargs of the execute method.
        Subclasses can override this method to handle different input parameter formats (e.g., 'file_paths' instead of 'tasks').
        """
        tasks = kwargs.get("tasks", [])
        if not isinstance(tasks, list):
            return []
        return [str(task) for task in tasks if task]

    def _get_sub_agent_task_details(self, task: str, **extra: Any) -> Dict[str, Any]:
        """
        Process a single parallel task string to create a task details dict to be passed to other methods.
        The default implementation wraps the task string in a dict with 'task' key.
        """
        return {"task": task}

    def _prepare_sub_agent_context(self, sub_agent_context: FlexibleContext, **task_details: Any) -> FlexibleContext:
        """
        Prepare the context for the sub-agent before creation (parallel version).
        **task_details contains the processed parameters for a single parallel task.
        Subclasses can override this method to add task-specific information to the context.
        """
        return sub_agent_context

    def _build_sub_agent_prompt(self, usr_init_msg: Optional[str], **task_details: Any) -> str:
        """
        Build the full task prompt for the sub-agent to be executed in parallel.
        """
        task = task_details.get("task")

        usr_init_msg_content = usr_init_msg if usr_init_msg else "未提供用户初始请求"
        task_content = task if task else "未提供任务"

        return (
            f"用户初始请求：\n{usr_init_msg_content}\n\n"
            f"当前具体任务：\n{task_content}"
        )

    def _execute_single_task_in_thread(self, task: Union[str, Dict[str, Any]], task_index: int, results_list: list):
        usr_init_msg = self.context.get("user_input")
        task_for_error_log: Optional[str] = f"Task #{task_index + 1} unknown"

        try:
            # Handle both string tasks and dict tasks
            if isinstance(task, dict):
                task_details = self._get_sub_agent_task_details(**task)
            else:
                task_details = self._get_sub_agent_task_details(task=task)
            task_str = task_details.get("task")
            task_for_error_log = str(task_str) if task_str else f"Task #{task_index + 1} failed to extract"

            if not task_str:
                error_message = f"错误：无法在并行任务列表项 #{task_index + 1} 中为子代理提取 'task'。"
                logger = getattr(self, 'logger', None)
                if logger: logger.error(error_message)
                else: print(error_message)
                results_list[task_index] = error_message
                return

            task_details_with_index = task_details.copy()
            task_details_with_index['task_index'] = task_index

            full_task_prompt = self._build_sub_agent_prompt(
                usr_init_msg,
                **task_details_with_index
            )

            sub_agent_base_context = self.context.copy()
            try:
                sub_agent_prepared_context = self._prepare_sub_agent_context(
                    sub_agent_base_context,
                    **task_details_with_index
                )
            except Exception as e:
                results_list[task_index] = f"错误：{str(e)}"
                return

            sub_agent_instance_name = f"{self.name}_task{task_index+1}"

            sub_agent_config = AgentConfig(
                agent_class=self.agent_class_to_create,
                tool_configs=self.default_sub_agent_tool_classes,
                max_iterations=self.default_sub_agent_max_iterations,
                system_prompt=self.sub_agent_system_prompt,
                agent_instance_name=sub_agent_instance_name
            )

            sub_agent = build_agent(
                agent_config=sub_agent_config,
                context=sub_agent_prepared_context
            )

            result = sub_agent.run(full_task_prompt)
            results_list[task_index] = result

        except Exception as e:
            error_snippet = str(task_for_error_log)[:50]
            error_string_for_result = f"错误：{self.name} 的并行子任务 #{task_index + 1} 失败（{type(e).__name__}）：{str(e)}"
            results_list[task_index] = error_string_for_result

            log_error_message = f"{self.name} 在并行子任务 #{task_index + 1} 期间出错（片段：'{error_snippet}...'）：{type(e).__name__} - {str(e)}"
            logger = getattr(self, 'logger', None)
            if logger:
                logger.error(log_error_message, exc_info=True)
            else:
                print(f"{self.name}（任务 #{task_index+1}）错误：{log_error_message}")

    def execute(self, **kwargs: Any) -> str:
        # Check if this should run in background
        run_in_background = kwargs.get("run_in_background", False)
        if run_in_background:
            self.is_background_task = True
        
        tasks = self._extract_task_list(**kwargs)

        if not tasks:
            return json.dumps([], ensure_ascii=False)

        threads = []
        results_list = [None] * len(tasks)

        for i, task in enumerate(tasks):
            thread = threading.Thread(
                target=self._execute_single_task_in_thread,
                args=(task, i, results_list),
                name=f"SubAgent-{self.name}-{i+1}"
            )
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        final_results_for_json = []
        for i, original_task in enumerate(tasks):
            task_result_or_error = results_list[i]

            task_entry = {
                "task": original_task
            }

            if task_result_or_error is None:
                task_entry["error_details"] = "获取任务结果失败（线程可能未正确返回值）"
            elif isinstance(task_result_or_error, str) and task_result_or_error.startswith("错误："):
                task_entry["error_message"] = task_result_or_error
            else:
                task_entry["result"] = task_result_or_error

            final_results_for_json.append(task_entry)

        return json.dumps(final_results_for_json, ensure_ascii=False, indent=2)
