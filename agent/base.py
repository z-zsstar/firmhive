import os
import re
import json
import uuid
import time
import queue
import inspect
import asyncio
import functools
import threading
import concurrent.futures
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Callable, Optional, Type, Union

from agent.llmclient import LLMClient
from agent.common import Message
from agent.historystrategy import HistoryStrategy
from agent.tools.basetool import ExecutableTool, FlexibleContext

class BaseLLM(ABC):
    def __init__(
        self,
        llm_client: LLMClient,
        system_prompt: str = "You are a helpful AI assistant.",
    ):
        self.llm_client = llm_client or LLMClient()
        self.system_prompt = system_prompt
        self.messages: List[Message] = []
        
        if not hasattr(self, 'messages_filters'):
            self.messages_filters = []
            
    def _build_system_message(self) -> str:
        format_section = self._get_response_format_prompt()
        return f"{self.system_prompt}\n\n--- Response Format Requirements ---\n{format_section}"
    
    @abstractmethod
    def _get_response_format_prompt(self) -> str:
        raise NotImplementedError
    
    @abstractmethod
    def _parse_llm_response(self, response_text: str) -> Dict[str, Any]:
        raise NotImplementedError
    
    def add_message(self, role: str, content: str, type: Optional[str] = None, tool_call_id: Optional[str] = None, name: Optional[str] = None):
        try:
            filtered_content = content
            for rule in getattr(self, 'messages_filters', []):
                try:
                    from_str = str(rule.get('from', ''))
                    to_str = str(rule.get('to', ''))
                    filtered_content = filtered_content.replace(from_str, to_str)
                except Exception:
                    continue
            msg = Message(role=role, content=filtered_content, type=type, tool_call_id=tool_call_id, name=name)
            self.messages.append(msg)
            
            if hasattr(self, 'messages_log_path') and self.messages_log_path:
                try:
                    with open(self.messages_log_path, 'a', encoding='utf-8') as f:
                        f.write(json.dumps(msg, ensure_ascii=False) + '\n')
                except Exception as e:
                    print(f"Warning: Failed to write message to log file {self.messages_log_path}. Error: {e}")

        except TypeError as e:
            print(f"Error: Failed to add message, content conversion failed - {e}")
        except Exception as e:
            print(f"Error: An unexpected error occurred while adding a message - {e}")
    
    def get_messages(self) -> List[Message]:
        return self.messages.copy()
    
    def clear_messages(self, keep_system_message: bool = False):
        if keep_system_message:
            self.messages = [self.messages[0]]
        else:
            self.messages = []
    
    def get_llm_response(self, messages: Optional[List[Message]] = None, **kwargs) -> Dict[str, Any]:
        msg_list = messages if messages is not None else self.messages
        return self.llm_client.invoke(msg_list, **kwargs)

    async def get_llm_response_async(self, messages: Optional[List[Message]] = None, **kwargs) -> Dict[str, Any]:
        msg_list = messages if messages is not None else self.messages
        return await self.llm_client.ainvoke(msg_list, **kwargs)


class JSONOutputLLM(BaseLLM):
    def __init__(
        self, 
        llm_client: Callable[[List[Message]], str],
        system_prompt: str = "You are a helpful AI assistant.",
        output_schema: Optional[Dict[str, Any]] = None
    ):
        self.output_schema = output_schema or {
            "type": "object",
            "properties": {
                "thought": {
                    "type": "string",
                    "description": "Thought process"
                },
                "response": {
                    "type": "string",
                    "description": "The final response to the user"
                }
            },
            "required": ["thought", "response"]
        }
        super().__init__(llm_client, system_prompt)
    
    def _get_response_format_prompt(self) -> str:
        output_schema_str = json.dumps(self.output_schema, ensure_ascii=False, indent=2)
        
        return f"""
你必须以严格的 JSON 格式响应。不要在 JSON 对象之外添加任何其他文本。
不要使用 markdown 格式（如 ```json）。直接输出单个 JSON 对象。

响应必须是符合以下模式的有效 JSON 对象：

{output_schema_str}

"""
    
    def _parse_llm_response(self, response_text: str) -> Dict[str, Any]:
        try:
            match = re.search(r"```json\s*(\{.*?\})\s*```", response_text, re.DOTALL)
            if match:
                json_str = match.group(1).strip()
            else:
                match = re.search(r"\{.*\}", response_text, re.DOTALL)
                if match:
                    json_str = match.group(0).strip()
                    if json_str.startswith("```") and json_str.endswith("```"):
                        json_str = json_str[3:-3].strip()
                else:
                    start_index = response_text.find('{')
                    end_index = response_text.rfind('}')

                    if start_index != -1 and end_index != -1 and end_index > start_index:
                        json_str = response_text[start_index:end_index + 1].strip()
                        if json_str.startswith("```") and json_str.endswith("```"):
                             json_str = json_str[3:-3].strip()
                    else:
                        raise json.JSONDecodeError("No valid JSON object found", response_text, 0)

            parsed = json.loads(json_str)
            
            if not isinstance(parsed, dict):
                raise ValueError("Parsed result is not a JSON object")
                
            required_fields = self.output_schema.get("required", [])
            missing_fields = [field for field in required_fields if field not in parsed]
            if missing_fields:
                raise ValueError(f"Response is missing required fields: {', '.join(missing_fields)}")
            
            return parsed
            
        except json.JSONDecodeError as e:
            print(f"JSON 解析错误：{e}。响应文本（前 200 字符）：'{response_text[:200]}'")
            raise
        except ValueError as e:
            print(f"JSON 内容验证错误：{e}。响应文本（前 200 字符）：'{response_text[:200]}'")
            raise
        except Exception as e:
            print(f"响应解析期间发生未知错误：{e}。响应文本（前 200 字符）：'{response_text[:200]}'")
            raise

    def run(self, user_input: str = None) -> Any:
        if user_input:
            self.add_message("user", user_input)
        messages = self.get_messages()
        llm_response = self.get_llm_response(messages, stream=False)
        return self._parse_llm_response(llm_response.get("content"))

    async def arun(self, user_input: str = None) -> Any:
        if user_input:
            self.add_message("user", user_input)
        messages = self.get_messages()
        llm_response = await self.get_llm_response_async(messages, stream=False)
        return self._parse_llm_response(llm_response.get("content"))


class BaseAgent(JSONOutputLLM):
    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        tools: Optional[List[Union[Type[ExecutableTool], ExecutableTool]]] = None,
        system_prompt: str = "You are a helpful AI assistant.",
        output_schema: Optional[Dict[str, Any]] = None,
        max_iterations: int = 25,
        history_strategy: Optional[HistoryStrategy] = None,
        messages_filters: Optional[List[Dict[str, str]]] = None,
        context: Optional[FlexibleContext] = None,
        agent_instance_name: Optional[str] = None
    ):
        self.context = context if context is not None else FlexibleContext()
        self.llm_client = llm_client or LLMClient()
        self.tool_configs = tools if tools is not None else []
        self.system_prompt = system_prompt
        self.max_iterations = max_iterations
        self.history_strategy = history_strategy
        if messages_filters is not None:
            self.messages_filters = messages_filters
        self.background_tasks: Dict[str, asyncio.Task] = {} 
        self.background_jobs: Dict[str, Dict] = {}

        self._setup_output_paths(agent_instance_name)
        self.name = agent_instance_name or self.__class__.__name__

        if self.tool_configs:
            initialized_tools_list = self._initialize_tools_from_list(self.tool_configs, self.context)
            self.tools = {tool.name: tool for tool in initialized_tools_list}
        else:
            self.tools = {}

        default_output_schema = {
            "type": "object",
            "properties": {
                "thought": {
                    "type": "string",
                    "description": "在这里逐步思考。分析当前情况、目标、可用工具和对话历史。决定是调用工具还是使用 'finish' 动作提供最终答案。"
                },
                "action": {
                    "type": "string",
                    "description": "选择下一个动作。必须是可用工具名称之一、'wait' 或 'finish'。"
                },
                "action_input": {
                    "oneOf": [
                        {"type": "object"},
                        {"type": "string"} 
                    ],
                    "description": "工具调用的参数或最终响应。如果 action 是工具名称，提供该工具所需的参数（通常是对象）；如果是 'finish'，使用 'final_response' 作为 action_input 的键提供最终响应（通常是包含字符串的对象）。"
                },
                "status": {
                    "type": "string",
                    "enum": ["continue", "complete"],
                    "description": "必须是 'continue'（如果选择了工具）或 'complete'（如果选择了 'finish'）。"
                }
            },
            "required": ["thought", "action", "action_input", "status"]
        }
        self.output_schema = output_schema or default_output_schema
        self.final_output_schema = None
        
        super().__init__(self.llm_client, self.system_prompt, output_schema=self.output_schema)
        
        self.add_message('system', self._build_initial_system_message_content())

    def _setup_output_paths(self, agent_instance_name: Optional[str]):
        log_identifier = agent_instance_name or self.__class__.__name__

        sanitized_agent_id = re.sub(r'[<>:"/\\|?*\s.]', '_', log_identifier)
        if not sanitized_agent_id:
            sanitized_agent_id = "agent"

        parent_log_dir = self.context.get("agent_log_dir")

        current_agent_log_dir: str
        if parent_log_dir and isinstance(parent_log_dir, str):
            subagents_dir = os.path.join(parent_log_dir, "subagents")
            current_agent_log_dir = os.path.join(subagents_dir, f"{sanitized_agent_id}_logs")
        else:
            output_base_dir = self.context.get("output", ".")
            if not isinstance(output_base_dir, str) or not output_base_dir.strip():
                output_base_dir = "."
            current_agent_log_dir = os.path.join(output_base_dir, f"{sanitized_agent_id}_logs")

        self.context.set("agent_log_dir", current_agent_log_dir)

        try:
            os.makedirs(current_agent_log_dir, exist_ok=True)
            self.messages_log_path = os.path.join(current_agent_log_dir, 'message.jsonl')
            print(f"BaseAgent '{log_identifier}' initialized. Messages will be saved to: {self.messages_log_path}")
        except OSError as e:
            print(f"[BaseAgent Setup] Warning: Could not create/access agent log directory '{current_agent_log_dir}'. Error: {e}. Message logging will be disabled.")
            self.messages_log_path = None

    def _initialize_tools_from_list(self, tool_inputs: List[Union[Type[ExecutableTool], ExecutableTool]], context: Optional[FlexibleContext]) -> List[ExecutableTool]:
        final_tools_list: List[ExecutableTool] = []
        processed_names = set()

        if not tool_inputs:
            return []

        for tool_input in tool_inputs:
            tool_instance: Optional[ExecutableTool] = None
            tool_name = "Unknown"

            try:
                if inspect.isclass(tool_input) and issubclass(tool_input, ExecutableTool):
                    tool_class = tool_input
                    tool_name = getattr(tool_class, 'name', tool_class.__name__)
                    if tool_name in processed_names:
                        continue
                    if context is None:
                         print(f"Warning: Cannot instantiate tool class {tool_name} without context. Skipping.")
                         continue
                    tool_instance = tool_class(context=context)
                    processed_names.add(tool_name)

                elif isinstance(tool_input, ExecutableTool):
                    tool_instance = tool_input
                    tool_name = getattr(tool_instance, 'name', tool_instance.__class__.__name__)
                    if tool_name in processed_names:
                        continue

                    if hasattr(tool_instance, 'context') and context is not None:
                        if tool_instance.context is None or id(tool_instance.context) != id(context):
                            tool_instance.context = context
                        else:
                            pass
                    processed_names.add(tool_name)

                else:
                    print(f"Warning: Skipping invalid item in tools list: {tool_input} (Type: {type(tool_input)})")
                    continue

                if tool_instance:
                    required_attrs = ['name', 'description', 'execute', 'parameters']
                    if not all(hasattr(tool_instance, attr) for attr in required_attrs):
                         print(f"Warning: Tool instance {tool_name} is missing required attributes ({required_attrs}) for Tool registration. Skipping.")
                         continue
                    
                    execute_method = getattr(tool_instance, 'execute', None)
                    if not callable(execute_method):
                        print(f"Warning: Tool instance {tool_name} has a non-callable 'execute' attribute. Skipping.")
                        continue

                    final_tools_list.append(tool_instance)

            except Exception as e:
                print(f"Error: Processing tool '{tool_name}' failed: {e}")

        print(f"{self.__class__.__name__} tools: {[t.name for t in final_tools_list]}")
        return final_tools_list

    def _get_response_format_prompt(self) -> str:
        base_prompt = super()._get_response_format_prompt()
        
        if self.final_output_schema:
            final_schema_str = json.dumps(self.final_output_schema, ensure_ascii=False, indent=2)
            final_prompt_part = f"""

--- 最终输出模式 ---
当你使用 'finish' 动作时，'action_input' 中 'final_response' 键的值必须是符合以下模式的 JSON 对象：

{final_schema_str}
"""
            return base_prompt + final_prompt_part
            
        return base_prompt

    def _build_initial_system_message_content(self) -> str:
        tool_section = self._format_tools_for_prompt()
        format_section = self._get_response_format_prompt()
        
        full_content = f"{self.system_prompt}\n\n"
        if self.tools:
            full_content += f"当前可用工具：\n{tool_section}\n\n"

            background_capable_tools = []
            for tool_name, tool in self.tools.items():
                if hasattr(tool, 'parameters') and isinstance(tool.parameters, dict):
                    properties = tool.parameters.get('properties', {})
                    if 'run_in_background' in properties:
                        background_capable_tools.append(tool_name)
            
            if background_capable_tools:
                full_content += "**后台执行和任务调度**：\n"
                full_content += "- 在 action_input 中设置 `run_in_background: true` 可异步运行任务。\n"
                full_content += "- 后台任务完成时，结果会自动注入。\n"
                full_content += "- 当需要后台结果才能继续时，使用 'wait' 动作。\n\n"
                full_content += "调度策略（避免遗漏和重复，最大化效率）：\n"
                full_content += "1. 识别独立任务，如果不立即需要结果，在后台启动它们。\n"
                full_content += "2. 在后台任务并行运行时继续其他工作。\n"
                full_content += "3. 当依赖任务需要后台结果时使用 'wait'。\n"
                full_content += "4. 在脑海中跟踪所有启动的后台任务以避免重复。\n"
                full_content += "5. 在 'finish' 之前，确保所有后台任务都已完成并整合结果。\n\n"
        else:
            full_content += "当前没有可用工具。\n\n"
        
        full_content += f"响应格式要求：\n{format_section}"
        return full_content

    def _format_tools_for_prompt(self) -> str:
        if not self.tools:
            return "当前没有可用工具。"
        
        tool_descriptions = "\n\n".join(
            [tool.format_for_prompt() for tool in self.tools.values()]
        )
        return tool_descriptions

    def _prepare_llm_request_messages(self) -> List[Message]:
        if not self.messages or self.messages[0].role != 'system':
            print("错误：消息历史为空或第一条消息不是系统消息！")
            return self.messages[:]

        system_message = self.messages[0]
        history_to_manage = self.messages[1:]  
        
        if self.history_strategy is not None:
            try:
                managed_history = self.history_strategy.apply(history_to_manage)
            except Exception as e:
                print(f"错误：应用历史策略 ({type(self.history_strategy).__name__}) 失败：{e}。回退到保留所有消息。")
                managed_history = history_to_manage[:]  
        else:
            managed_history = history_to_manage[:]  

        messages_to_send = [system_message] + managed_history
        return messages_to_send

    def _execute_tool(self, tool_name: str, tool_input: Dict[str, Any]) -> str:
        if tool_name not in self.tools:
            error_msg = f"错误：工具 '{tool_name}' 不存在。可用工具：{list(self.tools.keys())}"
            print(error_msg)
            return error_msg

        tool = self.tools[tool_name]
        print(f"执行工具：{tool_name}，输入参数：{json.dumps(tool_input, ensure_ascii=False, default=str)}")
        result_queue = queue.Queue()

        def execute_in_thread():
            try:
                safe_input_for_exec = {str(k): v for k, v in tool_input.items()}
                result = tool.execute(**safe_input_for_exec)
                result_queue.put(("success", result))
            except Exception as e:
                print(f"Exception in tool '{tool_name}' execution thread: {e}")
                result_queue.put(("error", e))

        thread = threading.Thread(target=execute_in_thread, daemon=True, name=f"ToolThread-{tool_name}")
        thread.start()
        
        default_timeout = 300
        timeout_seconds = tool.timeout if hasattr(tool, 'timeout') and tool.timeout is not None else default_timeout

        try:
            status, result = result_queue.get(timeout=timeout_seconds)
            
            tool_input_str_for_log = json.dumps(tool_input, ensure_ascii=False, default=str)
            
            if status == "success":
                try:
                    if result is None:
                        raw_output = f"工具：{tool_name}\n参数：{tool_input_str_for_log}\n结果：\n <无返回值>"
                        return raw_output
                    
                    result_str = str(result)
                    
                    if not result_str.strip() and result_str != "":
                         raw_output = f"工具：{tool_name}\n参数：{tool_input_str_for_log}\n结果：\n <空字符串>"
                         return raw_output
                    
                    formatted_result = f"工具：{tool_name}\n参数：{tool_input_str_for_log}\n结果：\n {result_str}"
                    return formatted_result
                except Exception as e:
                     print(f"警告：工具 '{tool_name}' 的结果无法安全转换为字符串或格式化：{e}")
                     raw_output = f"工具：{tool_name}\n参数：{tool_input_str_for_log}\n结果：\n <无法显示的复杂对象，转换/格式化错误：{str(e)}>"
                     return raw_output
            else:
                error_obj = result 
                print(f"工具 '{tool_name}' 执行失败。输入：{tool_input_str_for_log}。错误：{type(error_obj).__name__}: {str(error_obj)}")
                error_raw_output = f"工具：{tool_name}\n参数：{tool_input_str_for_log}\n结果：\n <执行失败，错误：{type(error_obj).__name__}: {str(error_obj)}>"
                return error_raw_output
        except queue.Empty:
            print(f"工具 '{tool_name}' 执行超时（超过 {timeout_seconds} 秒）。输入：{json.dumps(tool_input, ensure_ascii=False, default=str)}")
            timeout_raw_output = f"工具：{tool_name}\n参数：{json.dumps(tool_input, ensure_ascii=False, default=str)}\n结果：\n <执行超时，超过 {timeout_seconds} 秒>"
            return timeout_raw_output
        except Exception as e:
             print(f"工具 '{tool_name}' 执行期间发生意外的队列或处理错误：{e}。输入：{json.dumps(tool_input, ensure_ascii=False, default=str)}")
             error_queue_raw_output = f"工具：{tool_name}\n参数：{json.dumps(tool_input, ensure_ascii=False, default=str)}\n结果：\n <执行期间发生意外错误：{str(e)}>"
             return error_queue_raw_output

    async def _execute_tool_async(self, tool_name: str, tool_input: dict) -> str:
        """
        在单独的线程中异步执行工具以避免阻塞事件循环。
        """
        if tool_name not in self.tools:
            error_msg = f"错误：工具 '{tool_name}' 不存在。可用工具：{list(self.tools.keys())}"
            print(error_msg)
            return error_msg

        tool = self.tools[tool_name]
        loop = asyncio.get_running_loop()
        
        default_timeout = 600
        timeout_seconds = tool.timeout if hasattr(tool, 'timeout') and tool.timeout is not None else default_timeout

        try:
            safe_input_for_exec = {str(k): v for k, v in tool_input.items()}
            
            if hasattr(tool, 'aexecute') and callable(getattr(tool, 'aexecute')):
                result = await asyncio.wait_for(
                    tool.aexecute(**safe_input_for_exec), 
                    timeout=timeout_seconds
                )
            else:
                future = loop.run_in_executor(
                    None,
                    functools.partial(tool.execute, **safe_input_for_exec)
                )
                result = await asyncio.wait_for(future, timeout=timeout_seconds)

            tool_input_str_for_log = json.dumps(tool_input, ensure_ascii=False, default=str)
            
            if result is None:
                return f"工具：{tool_name}\n参数：{tool_input_str_for_log}\n结果：\n <无返回值>"
            
            result_str = str(result)
            
            if not result_str.strip() and result_str != "":
                return f"工具：{tool_name}\n参数：{tool_input_str_for_log}\n结果：\n <空字符串>"
            
            return f"工具：{tool_name}\n参数：{tool_input_str_for_log}\n结果：\n {result_str}"

        except asyncio.TimeoutError:
            error_msg = f"工具：{tool_name}\n参数：{json.dumps(tool_input, ensure_ascii=False, default=str)}\n结果：\n <执行失败，错误：TimeoutError：工具执行超过 {timeout_seconds} 秒。>"
            print(f"工具 '{tool_name}' 执行超时。")
            return error_msg
        except Exception as e:
            error_msg = f"工具：{tool_name}\n参数：{json.dumps(tool_input, ensure_ascii=False, default=str)}\n结果：\n <执行失败，错误：{type(e).__name__}: {str(e)}>"
            print(f"异步工具 '{tool_name}' 执行中发生异常：{e}")
            return error_msg

    def _auto_execute_tools(self, tool_calls: List[Dict[str, Any]]):
        """使用线程并发执行工具列表的辅助方法。"""
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_to_tool_call = {}
            for tool_call in tool_calls:
                tool_name = tool_call.get("name") or tool_call.get("tool_name")
                tool_input = tool_call.get("input") or tool_call.get("tool_input", {})
                if not tool_name:
                    print("警告：tool_call 中未提供 tool_name，跳过。")
                    continue
                
                future = executor.submit(self._execute_tool, tool_name, tool_input)
                future_to_tool_call[future] = tool_call

            for future in concurrent.futures.as_completed(future_to_tool_call):
                tool_call = future_to_tool_call[future]
                tool_name = tool_call.get("name") or tool_call.get("tool_name")
                try:
                    tool_result = future.result()
                    print(f"工具 '{tool_name}' 执行结果：\n{tool_result}")
                    self.add_message('user', tool_result, type='tool_result')
                except Exception as exc:
                    print(f"工具 '{tool_name}' 产生异常：{exc}")
                    error_message = f"工具 '{tool_name}' 执行失败，错误：{exc}"
                    self.add_message('user', error_message, type='tool_result_error')

    async def _aauto_execute_tools(self, tool_calls: List[Dict[str, Any]]):
        """并发执行工具列表的辅助方法。"""
        tasks = []
        for tool_call in tool_calls:
            tool_name = tool_call.get("name") or tool_call.get("tool_name")
            tool_input = tool_call.get("input") or tool_call.get("tool_input", {})
            if not tool_name:
                print("警告：tool_call 中未提供 tool_name，跳过。")
                continue
            tasks.append(self._execute_tool_async(tool_name, tool_input))
        
        if not tasks:
            return

        tool_results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in tool_results:
            if isinstance(result, Exception):
                print(f"并发工具执行期间发生异常：{result}")
                self.add_message('user', f"工具执行失败，错误：{result}", type='tool_result_error')
            else:
                print(f"工具执行结果：\n{result}")
                self.add_message('user', result, type='tool_result')

    def run(self, user_input: str = None, auto_tools: Optional[List[Dict[str, Any]]] = None) -> Any:
        if user_input:
            self.add_message('user', user_input)
            print(f"用户输入：\n {user_input}")
            print(f"当前上下文：\n {self.context}")
        
        if auto_tools:
            self._auto_execute_tools(auto_tools)

        final_answer = None
        is_waiting_for_jobs = False
        iteration_count = 0
        while iteration_count < self.max_iterations:
            if not is_waiting_for_jobs:
                iteration_count += 1
            
            print(f"\n----- [Iteration {iteration_count}/{self.max_iterations}] -----")

            injected_a_result = self._check_and_inject_background_jobs()

            if is_waiting_for_jobs and injected_a_result:
                print("后台任务已完成。继续...")
                is_waiting_for_jobs = False
            
            if is_waiting_for_jobs:
                if self.background_jobs:
                    print(f"等待 {len(self.background_jobs)} 个后台任务完成...")
                    time.sleep(1)
                    continue
                else:
                    print("所有后台任务已完成。继续 LLM 交互以生成最终摘要。")
                    is_waiting_for_jobs = False

            prompt_messages = self._prepare_llm_request_messages()

            max_parse_retries = 3
            parsed_response = None
            raw_response = ""
            
            for retry_count in range(max_parse_retries):
                try:
                    output_dir = self.context.get("output")
                    response_obj = self.get_llm_response(prompt_messages, output_dir=output_dir)
                    raw_response = response_obj['content']
                    print(f"LLM 原始响应（迭代 {iteration_count}，尝试 {retry_count+1}）：\n{raw_response}")
                    
                    if retry_count == 0:  
                        self.add_message('assistant', raw_response)    
                    parsed_response = self._parse_llm_response(raw_response)
                    print(f"解析后的 LLM 响应：{json.dumps(parsed_response, indent=2, ensure_ascii=False, default=str)}")
                    
                    if "error" in parsed_response:
                        raise ValueError(f"解析错误：{parsed_response['error']}: {parsed_response.get('message', '未知错误')}")
                    
                    break
                    
                except Exception as e:
                    print(f"响应解析失败（尝试 {retry_count+1}/{max_parse_retries}）：{e}")
                    if retry_count < max_parse_retries - 1:  
                        format_reminder_prompt = self._get_response_format_prompt()
                        error_feedback_to_llm = f"""
你之前的响应由于以下原因无法正确解析或验证：{str(e)}
原始响应开始于：{raw_response[:200]}...

请严格遵循所需的 JSON 模式和格式化指令。
确保所有必需字段都存在且 JSON 格式正确。

所需模式：
{format_reminder_prompt}

请重试生成响应。
"""
                        self.add_message('user', error_feedback_to_llm, type='parse_error')
                        prompt_messages = self._prepare_llm_request_messages()  
                    else:
                        print(f"已达到最大重试次数，无法解析 LLM 响应")
                        parsed_response = {
                            "error": "parse_error_max_retries",
                            "thought": f"经过 {max_parse_retries} 次尝试后，仍然无法生成有效格式的响应",
                            "action": "finish",
                            "action_input": {"final_response": f"抱歉，我遇到了技术问题，无法正确处理你的请求。"},
                            "status": "complete"
                        }
            
            if parsed_response is None or "error" in parsed_response:
                print("无法解析 LLM 响应，使用默认错误响应")
                parsed_response = {
                    "thought": "无法解析响应",
                    "action": "finish",
                    "action_input": {"final_response": "抱歉，我遇到了技术问题，无法正确处理你的请求。"},
                    "status": "complete"
                }

            action = parsed_response.get("action")
            action_input = parsed_response.get("action_input")
            status = parsed_response.get("status")  

            if action == "wait":
                if self.background_jobs:
                    print("动作是 'wait'，且后台任务正在运行。进入等待模式。")
                    is_waiting_for_jobs = True
                    continue
                else:
                    print("警告：Agent 选择了 'wait' 动作，但没有后台任务正在运行。")
                    self.add_message('user', "警告：你使用了 'wait' 动作，但没有后台任务正在运行。请选择其他动作或使用 'finish' 完成任务。", type='system_warning')
                    continue

            if status == "complete" or (action == "finish" and status != "continue"):
                if self.background_jobs:
                    print("Agent 想要完成，但后台任务正在运行。进入等待模式。")
                    is_waiting_for_jobs = True
                    self.add_message('user', "系统提示：已确认你的完成请求，但后台任务仍在运行。系统将等待它们完成后再生成最终摘要。下次如需明确等待而不完成，请使用 'wait' 动作。", type='system_note')
                    continue

                if isinstance(action_input, dict) and "final_response" in action_input:
                    final_answer = action_input["final_response"]
                else:
                    final_answer = parsed_response
                break 

            elif action and action != "finish" and status == "continue": 
                if not isinstance(action_input, dict):
                     tool_result = f"错误：工具 '{action}' 的 'action_input' 无效或缺失（需要字典），收到 {type(action_input)}。"
                     print(tool_result)
                     self.add_message('user', tool_result, type='tool_result_error')
                else:
                    tool_to_run = self.tools.get(action)
                    if tool_to_run and getattr(tool_to_run, 'is_background_task', False):
                        task_id = f"{action}_{uuid.uuid4().hex[:6]}"
                        print(f"检测到后台任务工具：'{action}'。正在启动，任务ID：{task_id}...")
                        
                        result_queue = queue.Queue()
                        
                        def execute_in_thread_bg():
                            try:
                                safe_input_for_exec = {str(k): v for k, v in action_input.items()}
                                result = tool_to_run.execute(**safe_input_for_exec)
                                result_queue.put(("success", result))
                            except Exception as e:
                                print(f"Exception in background tool '{action}' thread: {e}")
                                result_queue.put(("error", e))
                        
                        thread = threading.Thread(target=execute_in_thread_bg, daemon=True, name=f"BGToolThread-{task_id}")
                        thread.start()
                        
                        self.background_jobs[task_id] = {
                            "thread": thread,
                            "queue": result_queue,
                            "tool_name": action,
                            "tool_input": action_input
                        }
                        
                        tool_started_message = f"后台任务已启动。任务名称：'{action}'，任务ID：'{task_id}'。你可以继续进行其他操作；稍后会自动提供结果。"
                        print(tool_started_message)
                        self.add_message('user', tool_started_message, type='tool_result')
                        continue

                    else:
                        tool_result = self._execute_tool(action, action_input)
                        print(f"工具执行结果：\n{tool_result}")
                        self.add_message('user', tool_result, type='tool_result')

            else: 
                 print("警告：LLM 响应格式不一致或状态与动作不匹配")
                 status_mismatch = f"错误：你的响应不一致。如果动作是 '{action}'，状态应该是 {'complete' if action == 'finish' else 'continue'}，但收到了 '{status}'。"
                 self.add_message('user', status_mismatch, type='error')
                 continue 

        else: 
            print(f"已达到最大迭代次数（{self.max_iterations}）")
            final_answer = "已达到最大迭代次数但未找到答案。"
            if self.messages and self.messages[-1].role == 'assistant':
                final_answer = self.messages[-1].content

        print(f"{self.__class__.__name__} 已完成")
        return final_answer if final_answer is not None else "抱歉，我无法完成请求。"

    async def arun(self, user_input: str = None, auto_tools: Optional[List[Dict[str, Any]]] = None) -> Any:
        if user_input:
            self.add_message('user', user_input)
            print(f"用户输入：\n {user_input}")
            print(f"当前上下文：\n {self.context}")

        if auto_tools:
            await self._aauto_execute_tools(auto_tools)

        final_answer = None
        is_waiting_for_tasks = False
        
        iteration_count = 0
        while iteration_count < self.max_iterations:
            if not is_waiting_for_tasks:
                iteration_count += 1
            
            print(f"\n----- [Async Iteration {iteration_count}/{self.max_iterations}] -----")

            injected_a_result = await self._check_and_inject_background_tasks()

            if is_waiting_for_tasks and injected_a_result:
                print("后台任务已完成。继续 LLM 交互。")
                is_waiting_for_tasks = False

            if is_waiting_for_tasks:
                if self.background_tasks:
                    print(f"等待 {len(self.background_tasks)} 个后台任务完成...")
                    await asyncio.sleep(0.5)
                    continue
                else:
                    print("所有后台任务已完成。继续 LLM 交互以生成最终摘要。")
                    is_waiting_for_tasks = False
            
            prompt_messages = self._prepare_llm_request_messages()

            max_parse_retries = 3
            parsed_response = None
            raw_response = ""
            
            for retry_count in range(max_parse_retries):
                try:
                    output_dir = self.context.get("output")
                    response_obj = await self.get_llm_response_async(prompt_messages, output_dir=output_dir)
                    raw_response = response_obj['content']
                    print(f"LLM 原始响应（异步迭代 {iteration_count+1}，尝试 {retry_count+1}）：\n{raw_response}")
                    
                    if retry_count == 0:  
                        self.add_message('assistant', raw_response)    
                    parsed_response = self._parse_llm_response(raw_response)
                    print(f"解析后的 LLM 响应：{json.dumps(parsed_response, indent=2, ensure_ascii=False, default=str)}")
                    
                    if "error" in parsed_response:
                        raise ValueError(f"解析错误：{parsed_response['error']}: {parsed_response.get('message', '未知错误')}")
                    
                    break
                    
                except Exception as e:
                    print(f"响应解析失败（异步尝试 {retry_count+1}/{max_parse_retries}）：{e}")
                    if retry_count < max_parse_retries - 1:  
                        format_reminder_prompt = self._get_response_format_prompt()
                        error_feedback_to_llm = f"""
你之前的响应由于以下原因无法正确解析或验证：{str(e)}
原始响应开始于：{raw_response[:200]}...

请严格遵循所需的 JSON 模式和格式化指令。
确保所有必需字段都存在且 JSON 格式正确。

所需模式：
{format_reminder_prompt}

请重试生成响应。
"""
                        self.add_message('user', error_feedback_to_llm, type='parse_error')
                        prompt_messages = self._prepare_llm_request_messages()  
                    else:
                        print(f"已达到最大重试次数，无法解析 LLM 响应")
                        parsed_response = {
                            "error": "parse_error_max_retries",
                            "thought": f"经过 {max_parse_retries} 次尝试后，仍然无法生成有效格式的响应",
                            "action": "finish",
                            "action_input": {"final_response": f"抱歉，我遇到了技术问题，无法正确处理你的请求。"},
                            "status": "complete"
                        }
            
            if parsed_response is None or "error" in parsed_response:
                print("无法解析 LLM 响应，使用默认错误响应")
                parsed_response = {
                    "thought": "无法解析响应",
                    "action": "finish",
                    "action_input": {"final_response": "抱歉，我遇到了技术问题，无法正确处理你的请求。"},
                    "status": "complete"
                }

            action = parsed_response.get("action")
            action_input = parsed_response.get("action_input")
            status = parsed_response.get("status")  

            if action == "wait":
                if self.background_tasks:
                    print("动作是 'wait'，且后台任务正在运行。进入等待模式。")
                    is_waiting_for_tasks = True
                    continue
                else:
                    print("警告：Agent 选择了 'wait' 动作，但没有后台任务正在运行。")
                    self.add_message('user', "警告：你使用了 'wait' 动作，但没有后台任务正在运行。请选择其他动作或使用 'finish' 完成任务。", type='system_warning')
                    continue

            if status == "complete" or (action == "finish" and status != "continue"):
                if self.background_tasks:
                    print("Agent 想要完成，但后台任务正在运行。进入等待模式。")
                    is_waiting_for_tasks = True
                    self.add_message('user', "系统提示：已确认你的完成请求。系统现在将等待所有后台任务完成后再生成最终摘要。下次如需明确等待而不完成，请使用 'wait' 动作。", type='system_note')
                    continue
                
                if isinstance(action_input, dict) and "final_response" in action_input:
                    final_answer = action_input["final_response"]
                else:
                    final_answer = parsed_response
                break 

            elif action and action != "finish" and status == "continue": 
                if not isinstance(action_input, dict):
                     tool_result = f"错误：工具 '{action}' 的 'action_input' 无效或缺失（需要字典），收到 {type(action_input)}。"
                     print(tool_result)
                     self.add_message('user', tool_result, type='tool_result_error')
                else:
                    tool_to_run = self.tools.get(action)
                    if tool_to_run and getattr(tool_to_run, 'is_background_task', False):
                        task_id = f"{action}_{uuid.uuid4().hex[:6]}"
                        print(f"检测到后台任务工具: '{action}'。正在启动，任务ID: {task_id}...")
                        
                        new_task = asyncio.create_task(self._execute_tool_async(action, action_input))
                        self.background_tasks[task_id] = new_task
                        
                        tool_started_message = f"后台任务已启动。任务名称: '{action}', 任务ID: '{task_id}'. 你可以继续执行其他操作，稍后会自动收到结果。"
                        print(tool_started_message)
                        self.add_message('user', tool_started_message, type='tool_result')
                        continue

                    else:
                        tool_result = await self._execute_tool_async(action, action_input)
                        print(f"工具执行结果：\n{tool_result}")
                        self.add_message('user', tool_result, type='tool_result')

            else: 
                 print("警告：LLM 响应格式不一致或状态与动作不匹配")
                 status_mismatch = f"错误：你的响应不一致。如果动作是 '{action}'，状态应该是 {'complete' if action == 'finish' else 'continue'}，但收到了 '{status}'。"
                 self.add_message('user', status_mismatch, type='error')
                 continue 

        else:
            print(f"已达到最大迭代次数（{self.max_iterations}）")
            final_answer = "已达到最大迭代次数但未找到答案。"
            if self.messages and self.messages[-1].role == 'assistant':
                final_answer = self.messages[-1].content
        
        print(f"{self.__class__.__name__} 已完成")
        return final_answer if final_answer is not None else "抱歉，我无法完成请求。"

    def _check_and_inject_background_jobs(self) -> bool:
        """
        Checks the status of background jobs, injects results of completed jobs into the message history.
        Returns: True if at least one job result was injected, otherwise False.
        """
        completed_jobs = {}
        injected_a_result = False
        for task_id, job_info in self.background_jobs.items():
            if not job_info['thread'].is_alive():
                try:
                    status, result = job_info['queue'].get_nowait()
                    tool_name = job_info['tool_name']
                    tool_input = job_info['tool_input']
                    tool_input_str = json.dumps(tool_input, ensure_ascii=False, default=str)
                    
                    if status == "success":
                        result_str = str(result)
                        job_result_message = f"Background job '{task_id}' ({tool_name}) has completed.\nParameters: {tool_input_str}\nResult:\n{result_str}"
                    else:
                        error_obj = result
                        job_result_message = f"Background job '{task_id}' ({tool_name}) failed.\nParameters: {tool_input_str}\nError: {type(error_obj).__name__}: {str(error_obj)}"

                    print(f"--- Injected Background Job Result ---\n{job_result_message}\n---------------------------------------")
                    self.add_message('user', job_result_message, type='background_tool_result')

                except queue.Empty:
                    error_message = f"Background job '{task_id}' finished but no result was found in its queue."
                    print(f"--- Injected Background Job Error ---\n{error_message}\n--------------------------------------")
                    self.add_message('user', error_message, type='background_tool_error')
                except Exception as e:
                    error_message = f"An unexpected error occurred while processing result for background job '{task_id}': {e}"
                    print(f"--- Injected Background Job Error ---\n{error_message}\n--------------------------------------")
                    self.add_message('user', error_message, type='background_tool_error')
                
                completed_jobs[task_id] = job_info
                injected_a_result = True

        for task_id in completed_jobs:
            del self.background_jobs[task_id]
        
        return injected_a_result

    async def _check_and_inject_background_tasks(self) -> bool:
        """
        检查后台任务的状态，将任何已完成的任务结果注入到消息历史中。
        返回: True 如果有至少一个任务结果被注入，否则 False。
        """
        completed_tasks = {}
        injected_a_result = False
        for task_id, task in self.background_tasks.items():
            if task.done():
                try:
                    result = await task
                    tool_result_message = f"后台任务 '{task_id}' 已完成。\n结果:\n{result}"
                    print(f"--- Injected Background Task Result ---\n{tool_result_message}\n---------------------------------------")
                    self.add_message('user', tool_result_message, type='background_tool_result')
                except Exception as e:
                    error_message = f"后台任务 '{task_id}' 执行失败。\n错误: {type(e).__name__}: {e}"
                    print(f"--- Injected Background Task Error ---\n{error_message}\n--------------------------------------")
                    self.add_message('user', error_message, type='background_tool_error')
                
                completed_tasks[task_id] = task
                injected_a_result = True

        for task_id in completed_tasks:
            del self.background_tasks[task_id]
        
        return injected_a_result

    def stream(self, user_input: str = None) -> List[Dict[str, Any]]:
        print(f"系统提示：\n {self.messages[0].content}")
        conversation: List[Dict[str, Any]] = []
        
        if self.messages and self.messages[0].role == "system":
            conversation.append({
                "role": "system",
                "content": self.messages[0].content
            })

        if user_input:
            self.add_message('user', user_input)
            print(f"流式输入：\n {user_input}")
            conversation.append({
                "role": "user",
                "content": user_input
            })
        
        for i in range(self.max_iterations):
            print(f"\n----- [Iteration {i + 1}/{self.max_iterations}] (Stream Mode) -----")
            
            prompt_messages = self._prepare_llm_request_messages()
            
            max_parse_retries = 3
            parsed_response = None
            raw_response = ""

            for retry_count in range(max_parse_retries):
                print(f"----- Calling LLM (Stream Mode, Attempt {retry_count+1}/{max_parse_retries}) -----")
                try:
                    output_dir = self.context.get("output")
                    response_obj = self.get_llm_response(prompt_messages, output_dir=output_dir)
                    raw_response = response_obj['content']
                    print(f"----- LLM Raw Response (first 500) -----\n{raw_response[:500]}{'...' if len(raw_response)>500 else ''}\n" + "-"*20)
                    
                    if retry_count == 0:
                        self.add_message('assistant', raw_response)
                        conversation.append({
                            "role": "assistant",
                            "content": raw_response
                        })
                    
                    print(f"----- Parsing LLM Response (Stream Mode, Attempt {retry_count+1}/{max_parse_retries}) -----")
                    parsed_response = self._parse_llm_response(raw_response)
                    print(f"----- Parsed Result -----\n{json.dumps(parsed_response, indent=2, ensure_ascii=False)}\n" + "-"*20)
                    
                    if "error" in parsed_response:
                        raise ValueError(f"解析错误：{parsed_response['error']}: {parsed_response.get('message', '未知错误')}")
                    
                    break
                    
                except Exception as e:
                    print(f"Response parsing failed (Stream Mode, Attempt {retry_count+1}/{max_parse_retries}): {e}")
                    if retry_count < max_parse_retries - 1:  
                        format_reminder = self._get_response_format_prompt()
                        error_message_to_llm = f"""
Your previous response could not be parsed or validated: {str(e)}.
Raw response started with: {raw_response[:200]}...
Please strictly follow the required JSON schema:
{format_reminder}
Retry generating the response.
"""
                        self.add_message('user', error_message_to_llm, type='parse_error')
                        conversation.append({
                            "role": "system_feedback_to_llm",
                            "content": error_message_to_llm
                        })
                        prompt_messages = self._prepare_llm_request_messages()  
                    else:
                        print(f"Maximum retry attempts reached, failed to parse LLM response (Stream Mode)")
                        parsed_response = {
                            "error": "parse_error_max_retries",
                            "thought": f"经过 {max_parse_retries} 次尝试后，仍然无法生成有效格式的响应",
                            "action": "finish",
                            "action_input": {"final_response": "抱歉，我遇到了响应格式化的技术问题。"},
                            "status": "complete"
                        }
                        conversation.append({
                            "role": "error",
                            "content": f"After {max_parse_retries} attempts, still unable to parse LLM response"
                        })
            
            if parsed_response is None or "error" in parsed_response:
                print("Failed to parse LLM response, using default error response (Stream Mode)")
                parsed_response = {
                    "thought": "无法解析响应",
                    "action": "finish",
                    "action_input": {"final_response": "抱歉，我遇到了技术问题，无法正确处理你的请求。"},
                    "status": "complete"
                }
                if "error" not in conversation[-1]["role"]:  
                    conversation.append({
                        "role": "error",
                        "content": "Failed to parse response, cannot continue processing"
                    })
            
            action = parsed_response.get("action")
            action_input = parsed_response.get("action_input")
            status = parsed_response.get("status")
            
            if status == "complete" or (action == "finish" and status != "continue"):
                print("----- Completion status detected (Stream Mode) -----")
                final_response_content = "Task completed."
                if isinstance(action_input, dict) and "final_response" in action_input:
                    final_response_content = action_input["final_response"]
                elif isinstance(action_input, str):
                    final_response_content = action_input
                elif parsed_response.get("thought"):
                    final_response_content = f"Completed. Last thought: {parsed_response.get('thought')}"
                
                if conversation and conversation[-1].get("role") == "assistant_thought_process":
                    conversation[-1] = {"role": "assistant", "content": final_response_content}
                else:
                    conversation.append({"role": "assistant", "content": final_response_content})
                print(f"----- Final Response: {str(final_response_content)[:200]}...")
                break  
            
            elif action and action != "finish" and status == "continue":  
                print(f"----- Requesting tool execution: {action} (Stream Mode) -----")
                
                if not isinstance(action_input, dict):
                    tool_error_msg = f"Error: Tool '{action}' expects 'action_input' to be a dictionary, received {type(action_input)}: {str(action_input)[:100]}..."
                    print(f"----- {tool_error_msg}")
                    self.add_message('user', tool_error_msg, type='tool_result_error')
                    
                    conversation.append({
                        "role": "tool_error",
                        "tool_name": action,
                        "content": tool_error_msg
                    })
                else:
                    conversation.append({
                        "role": "tool_call",
                        "tool_name": action,
                        "tool_input": action_input
                    })
                    print(f"----- Executing tool '{action}' with input: {json.dumps(action_input, ensure_ascii=False, default=str)}")
                    tool_result_str = self._execute_tool(action, action_input)
                    print(f"----- Tool '{action}' result (first 500 chars): {tool_result_str[:500]}{'...' if len(tool_result_str)>500 else ''}")
                    self.add_message('user', tool_result_str, type='tool_result')
                    
                    conversation.append({
                        "role": "tool_result",
                        "tool_name": action,
                        "content": tool_result_str
                    })
            
            else:  
                print("----- Warning: LLM response format inconsistency or status mismatch with action (Stream Mode) -----")
                status_mismatch = f"Error: Response is inconsistent. If action is '{action}', status should be {'complete' if action == 'finish' else 'continue'}, but received '{status}'."
                self.add_message('user', status_mismatch, type='error')
                
                conversation.append({
                    "role": "error",
                    "content": status_mismatch
                })
                continue
        
        else:  
            print(f"----- Max iterations reached ({self.max_iterations}) (Stream Mode) -----")
            last_message_content = "Max iterations reached."
            if self.messages and self.messages[-1].role == 'assistant':
                last_assistant_response = self.messages[-1].content
                try:
                    parsed_last = self._parse_llm_response(last_assistant_response)
                    if isinstance(parsed_last.get("action_input"), dict) and "final_response" in parsed_last["action_input"]:
                        last_message_content = parsed_last["action_input"]["final_response"]
                    elif parsed_last.get("thought"):
                         last_message_content = f"Max iterations. Last thought: {parsed_last.get('thought')}"
                except Exception:
                    last_message_content = f"Max iterations. Last raw response: {last_assistant_response[:200]}..."
            
            conversation.append({
                "role": "assistant",
                "content": last_message_content
            })

        print(f"===== Agent run finished (Stream Mode) =====")
        return conversation

    async def astream(self, user_input: str = None) -> List[Dict[str, Any]]:
        print(f"系统提示：\n {self.messages[0].content}")
        conversation: List[Dict[str, Any]] = []
        
        if self.messages and self.messages[0].role == "system":
            conversation.append({
                "role": "system",
                "content": self.messages[0].content
            })

        if user_input:
            self.add_message('user', user_input)
            print(f"流式输入：\n {user_input}")
            conversation.append({
                "role": "user",
                "content": user_input
            })
        
        for i in range(self.max_iterations):
            print(f"\n----- [Iteration {i + 1}/{self.max_iterations}] (Async Stream Mode) -----")
            
            prompt_messages = self._prepare_llm_request_messages()
            
            max_parse_retries = 3
            parsed_response = None
            raw_response = ""

            for retry_count in range(max_parse_retries):
                print(f"----- Calling LLM (Async Stream Mode, Attempt {retry_count+1}/{max_parse_retries}) -----")
                try:
                    output_dir = self.context.get("output")
                    response_obj = await self.get_llm_response_async(prompt_messages, output_dir=output_dir)
                    raw_response = response_obj['content']
                    print(f"----- LLM Raw Response (first 500) -----\n{raw_response[:500]}{'...' if len(raw_response)>500 else ''}\n" + "-"*20)
                    
                    if retry_count == 0:
                        self.add_message('assistant', raw_response)
                        conversation.append({
                            "role": "assistant",
                            "content": raw_response
                        })
                    
                    print(f"----- Parsing LLM Response (Async Stream Mode, Attempt {retry_count+1}/{max_parse_retries}) -----")
                    parsed_response = self._parse_llm_response(raw_response)
                    print(f"----- Parsed Result -----\n{json.dumps(parsed_response, indent=2, ensure_ascii=False)}\n" + "-"*20)
                    
                    if "error" in parsed_response:
                        raise ValueError(f"解析错误：{parsed_response['error']}: {parsed_response.get('message', '未知错误')}")
                    
                    break
                    
                except Exception as e:
                    print(f"Response parsing failed (Async Stream Mode, Attempt {retry_count+1}/{max_parse_retries}): {e}")
                    if retry_count < max_parse_retries - 1:  
                        format_reminder = self._get_response_format_prompt()
                        error_message_to_llm = f"""
Your previous response could not be parsed or validated: {str(e)}.
Raw response started with: {raw_response[:200]}...
Please strictly follow the required JSON schema:
{format_reminder}
Retry generating the response.
"""
                        self.add_message('user', error_message_to_llm, type='parse_error')
                        conversation.append({
                            "role": "system_feedback_to_llm",
                            "content": error_message_to_llm
                        })
                        prompt_messages = self._prepare_llm_request_messages()  
                    else:
                        print(f"Maximum retry attempts reached, failed to parse LLM response (Async Stream Mode)")
                        parsed_response = {
                            "error": "parse_error_max_retries",
                            "thought": f"经过 {max_parse_retries} 次尝试后，仍然无法生成有效格式的响应",
                            "action": "finish",
                            "action_input": {"final_response": "抱歉，我遇到了响应格式化的技术问题。"},
                            "status": "complete"
                        }
                        conversation.append({
                            "role": "error",
                            "content": f"After {max_parse_retries} attempts, still unable to parse LLM response"
                        })
            
            if parsed_response is None or "error" in parsed_response:
                print("Failed to parse LLM response, using default error response (Async Stream Mode)")
                parsed_response = {
                    "thought": "无法解析响应",
                    "action": "finish",
                    "action_input": {"final_response": "抱歉，我遇到了技术问题，无法正确处理你的请求。"},
                    "status": "complete"
                }
                if "error" not in conversation[-1]["role"]:  
                    conversation.append({
                        "role": "error",
                        "content": "Failed to parse response, cannot continue processing"
                    })
            
            action = parsed_response.get("action")
            action_input = parsed_response.get("action_input")
            status = parsed_response.get("status")
            
            if status == "complete" or (action == "finish" and status != "continue"):
                print("----- Completion status detected (Async Stream Mode) -----")
                final_response_content = "Task completed."
                if isinstance(action_input, dict) and "final_response" in action_input:
                    final_response_content = action_input["final_response"]
                elif isinstance(action_input, str):
                    final_response_content = action_input
                elif parsed_response.get("thought"):
                    final_response_content = f"Completed. Last thought: {parsed_response.get('thought')}"
                
                if conversation and conversation[-1].get("role") == "assistant_thought_process":
                    conversation[-1] = {"role": "assistant", "content": final_response_content}
                else:
                    conversation.append({"role": "assistant", "content": final_response_content})
                print(f"----- Final Response: {str(final_response_content)[:200]}...")
                break  
            
            elif action and action != "finish" and status == "continue":  
                print(f"----- Requesting tool execution: {action} (Async Stream Mode) -----")
                
                if not isinstance(action_input, dict):
                    tool_error_msg = f"Error: Tool '{action}' expects 'action_input' to be a dictionary, received {type(action_input)}: {str(action_input)[:100]}..."
                    print(f"----- {tool_error_msg}")
                    self.add_message('user', tool_error_msg, type='tool_result_error')
                    
                    conversation.append({
                        "role": "tool_error",
                        "tool_name": action,
                        "content": tool_error_msg
                    })
                else:
                    conversation.append({
                        "role": "tool_call",
                        "tool_name": action,
                        "tool_input": action_input
                    })
                    print(f"----- Executing tool '{action}' with input: {json.dumps(action_input, ensure_ascii=False, default=str)}")
                    tool_result_str = await self._execute_tool_async(action, action_input)
                    print(f"----- Tool '{action}' result (first 500 chars): {tool_result_str[:500]}{'...' if len(tool_result_str)>500 else ''}")
                    self.add_message('user', tool_result_str, type='tool_result')
                    
                    conversation.append({
                        "role": "tool_result",
                        "tool_name": action,
                        "content": tool_result_str
                    })
            
            else:  
                print("----- Warning: LLM response format inconsistency or status mismatch with action (Async Stream Mode) -----")
                status_mismatch = f"Error: Response is inconsistent. If action is '{action}', status should be {'complete' if action == 'finish' else 'continue'}, but received '{status}'."
                self.add_message('user', status_mismatch, type='error')
                
                conversation.append({
                    "role": "error",
                    "content": status_mismatch
                })
                continue
        
        else:  
            print(f"----- Max iterations reached ({self.max_iterations}) (Async Stream Mode) -----")
            last_message_content = "Max iterations reached."
            if self.messages and self.messages[-1].role == 'assistant':
                last_assistant_response = self.messages[-1].content
                try:
                    parsed_last = self._parse_llm_response(last_assistant_response)
                    if isinstance(parsed_last.get("action_input"), dict) and "final_response" in parsed_last["action_input"]:
                        last_message_content = parsed_last["action_input"]["final_response"]
                    elif parsed_last.get("thought"):
                         last_message_content = f"Max iterations. Last thought: {parsed_last.get('thought')}"
                except Exception:
                    last_message_content = f"Max iterations. Last raw response: {last_assistant_response[:200]}..."
            
            conversation.append({
                "role": "assistant",
                "content": last_message_content
            })

        print(f"===== Agent run finished (Async Stream Mode) =====")
        return conversation
