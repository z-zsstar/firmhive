import json
import traceback
import threading
from typing import Optional, List, Type, Union, Any, Dict

from agent.base import BaseAgent
from agent.tools.basetool import FlexibleContext, ExecutableTool
from agent.core.builder import AgentConfig, build_agent

class BaseAssistant(ExecutableTool):
    name = "TaskDelegator"
    description = """
    Task Delegator - Used to delegate a sub-task to a sub-agent for processing.
    
    Applicable scenarios:
    When the next analysis task can only be decided after obtaining the analysis result of a single-step task.

    """
    parameters = {
        "type": "object",
        "properties": {
            "task": {
                "type": "object",
                "properties": {
                    "task_description": {
                        "type": "string",
                        "description": "A detailed description of the sub-task to be executed, be sure to specify the analysis target."
                    }
                },
                "required": ["task_description"],
                "description": "A task item containing a single task description."
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

    def _get_sub_agent_task_details(self, **kwargs: Any) -> Dict[str, Any]:
        task_details_input = kwargs.get("task", {})
        if not isinstance(task_details_input, dict):
            return {}
        return task_details_input

    def _prepare_sub_agent_context(self, sub_agent_context: FlexibleContext, **task_details: Any) -> FlexibleContext:
        return sub_agent_context

    def _build_sub_agent_prompt(self, usr_init_msg: Optional[str], **task_details: Any) -> str:
        task_description = task_details.get("task_description")

        usr_init_msg_content = usr_init_msg if usr_init_msg else "No initial user request provided"
        task_description_content = task_description if task_description else "No task description provided"

        return (
            f"The user's initial request is:\n{usr_init_msg_content}\n"
            f"Current specific task:\n{task_description_content}"
        )

    def execute(self, **kwargs: Any) -> str:
        usr_init_msg = self.context.get("user_input")
        task_description_for_error_log: Optional[str] = "Unknown task description"

        try:
            task_details = self._get_sub_agent_task_details(**kwargs)
            
            task_description = task_details.get("task_description")
            task_description_for_error_log = str(task_description) if task_description else "Failed to extract"

            if not task_description:
                return "Error: Failed to extract 'task_description' from task input for the sub-agent."

            full_task_prompt = self._build_sub_agent_prompt(usr_init_msg, **task_details)
            
            sub_agent_base_context = self.context.copy()
            try:
                sub_agent_prepared_context = self._prepare_sub_agent_context(sub_agent_base_context, **task_details)
            except Exception as e:
                return f"Error: {str(e)}"
            
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
            error_desc_snippet = task_description_for_error_log[:70]
            error_message_for_return = f"Error: {self.name} failed while executing sub-task (task description snippet: '{error_desc_snippet}'): {type(e).__name__} - {str(e)}"
            
            log_error_message = f"Error in {self.name} during sub-task preparation or delegation (task description snippet: '{error_desc_snippet}...'): {type(e).__name__} - {str(e)}"
            logger = getattr(self, 'logger', None)
            if logger:
                logger.error(log_error_message, exc_info=True)
            else:
                print(f"ERROR in {self.name}: {log_error_message}")
                print(traceback.format_exc())
            return f"An error occurred while executing the sub-task: {error_message_for_return}"


class ParallelBaseAssistant(ExecutableTool):
    name = "ParallelTaskDelegator"
    description = """
    Task Delegator - Used to distribute multiple sub-tasks to sub-agents for parallel execution.
    
    Applicable scenarios:
    1. When a complex task needs to be broken down into multiple independent sub-tasks for processing.
    2. When there are no strict execution order dependencies between sub-tasks.
    3. Recommended for large-scale and complex tasks to improve analysis efficiency by executing multiple sub-tasks in parallel.
    
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
                            "description": "A detailed description of the sub-task to be executed. Note that each sub-task description is independent and should specify the analysis target."
                        }
                    },
                    "required": ["task_description"],
                    "description": "A task item containing a single task description."
                },
                "description": "A list of independent sub-tasks to be distributed to sub-agents for execution."
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

    def _extract_task_list(self, **kwargs: Any) -> List[Dict[str, Any]]:
        return kwargs.get("tasks", [])

    def _get_sub_agent_task_details(self, **task_item: Any) -> Dict[str, Any]:
        return task_item

    def _prepare_sub_agent_context(self, sub_agent_context: FlexibleContext, **task_details: Any) -> FlexibleContext:
        return sub_agent_context

    def _build_sub_agent_prompt(self, usr_init_msg: Optional[str], **task_details: Any) -> str:
        task_description = task_details.get("task_description")

        usr_init_msg_content = usr_init_msg if usr_init_msg else "No initial user request provided"
        task_description_content = task_description if task_description else "No task description provided"

        return (
            f"The user's initial request is:\n{usr_init_msg_content}\n\n"
            f"Current specific task:\n{task_description_content}"
        )

    def _execute_single_task_in_thread(self, task_item: Dict[str, Any], task_index: int, results_list: list):
        usr_init_msg = self.context.get("user_input")
        task_description_for_error_log: Optional[str] = f"Task #{task_index + 1} unknown description"

        try:
            task_details = self._get_sub_agent_task_details(**task_item)
            task_description = task_details.get("task_description")
            task_description_for_error_log = str(task_description) if task_description else f"Task #{task_index + 1} failed to extract description"

            if not task_description:
                error_message = f"Error: Task #{task_index + 1} in the parallel task list failed to extract 'task_description' for the sub-agent."
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
                results_list[task_index] = f"Error: {str(e)}"
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
            error_desc_snippet = str(task_description_for_error_log)[:50]
            error_string_for_result = f"Error: Parallel sub-task #{task_index + 1} of {self.name} failed to execute ({type(e).__name__}): {str(e)}"
            results_list[task_index] = error_string_for_result
            
            log_error_message = f"Error in {self.name} during parallel sub-task #{task_index + 1} (desc snippet: '{error_desc_snippet}...'): {type(e).__name__} - {str(e)}"
            logger = getattr(self, 'logger', None)
            if logger:
                logger.error(log_error_message, exc_info=True)
            else:
                print(f"ERROR in {self.name} (task #{task_index+1}): {log_error_message}")

    def execute(self, **kwargs: Any) -> str:
        tasks = self._extract_task_list(**kwargs)
        
        if not tasks:
            return json.dumps([], ensure_ascii=False)

        threads = []
        results_list = [None] * len(tasks)

        for i, task_item in enumerate(tasks):
            thread = threading.Thread(
                target=self._execute_single_task_in_thread,
                args=(task_item, i, results_list),
                name=f"SubAgent-{self.name}-{i+1}"
            )
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()
            
        final_results_for_json = []
        for i, original_task_config in enumerate(tasks):
            original_td = "Original task description unknown"
            if isinstance(original_task_config, dict):
                 extracted_details = self._get_sub_agent_task_details(**original_task_config)
                 original_td = extracted_details.get("task_description", "Failed to extract original task description")

            task_result_or_error = results_list[i]

            task_entry = {
                "task_description": original_td
            }

            if task_result_or_error is None:
                task_entry["error_details"] = "Failed to get task result (thread may not have returned a value correctly)"
            elif isinstance(task_result_or_error, str) and task_result_or_error.startswith("Error:"):
                task_entry["error_message"] = task_result_or_error
            else:
                task_entry["result"] = task_result_or_error
            
            final_results_for_json.append(task_entry)
        
        return json.dumps(final_results_for_json, ensure_ascii=False, indent=2)
