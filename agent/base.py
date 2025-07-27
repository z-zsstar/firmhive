import os
import re
import json
import queue
import inspect
import threading
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Callable, Optional, Type, Union

from agent.llmclient import LLMClient
from agent.common import Message, Tool
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
        return self.llm_client(msg_list, **kwargs)


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
You must respond in strict JSON format. Do not add any other text outside the JSON object.
Do not use markdown format (like ```json). Output a single JSON object directly.

The response must be a valid JSON object that conforms to the following schema:

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
            print(f"JSON parsing error: {e}. Response text (first 200 chars): '{response_text[:200]}'")
            raise
        except ValueError as e:
            print(f"JSON content validation error: {e}. Response text (first 200 chars): '{response_text[:200]}'")
            raise
        except Exception as e:
            print(f"Unknown error during response parsing: {e}. Response text (first 200 chars): '{response_text[:200]}'")
            raise
    
class BaseAgent(JSONOutputLLM):
    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        tools: Optional[List[Union[Type[ExecutableTool], ExecutableTool]]] = None,
        system_prompt: str = "You are a helpful AI assistant.",
        output_schema: Optional[Dict[str, Any]] = None,
        final_output_schema: Optional[Dict[str, Any]] = None,
        max_iterations: int = 15,
        history_strategy: Optional[HistoryStrategy] = None,
        messages_filters: Optional[List[Dict[str, str]]] = None,
        context: Optional[FlexibleContext] = None,
        agent_instance_name: Optional[str] = None
    ):
        self.llm_client = llm_client or LLMClient()
        self.tool_configs = tools if tools is not None else []
        self.system_prompt = system_prompt
        self.final_output_schema = final_output_schema
        self.max_iterations = max_iterations
        self.history_strategy = history_strategy
        self.context = context if context is not None else FlexibleContext()
        if messages_filters is not None:
            self.messages_filters = messages_filters

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
                    "description": "Think step-by-step here. Analyze the current situation, goals, available tools, and conversation history. Decide whether to call a tool or use the 'finish' action to provide the final answer."
                },
                "action": {
                    "type": "string",
                    "description": "Select the next action. Must be one of the available tool names or 'finish'."
                },
                "action_input": {
                    "oneOf": [
                        {"type": "object"},
                        {"type": "string"} 
                    ],
                    "description": "Parameters for the tool call or the final response. If action is a tool name, provide the required parameters for that tool (usually an object); if it's 'finish', provide the final response using 'final_response' as the key for action_input (usually an object containing a string)."
                },
                "status": {
                    "type": "string",
                    "enum": ["continue", "complete"],
                    "description": "Must be 'continue' (if a tool is selected) or 'complete' (if 'finish' is selected)."
                }
            },
            "required": ["thought", "action", "action_input", "status"]
        }
        if self.final_output_schema:
            default_output_schema['properties']['action_input']['description'] = (
                "Parameters for the tool call or the final response. If action is a tool name, provide the required parameters for that tool (usually an object); "
                "if it's 'finish', 'action_input' must be an object containing a 'final_response' key, "
                "the value of which must follow the format defined in the 'Final Output Schema' section."
            )
        self.output_schema = output_schema or default_output_schema
        
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
            current_agent_log_dir = os.path.join(parent_log_dir, f"{sanitized_agent_id}_logs")
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

    def _initialize_tools_from_list(self, tool_inputs: List[Union[Type[ExecutableTool], ExecutableTool]], context: Optional[FlexibleContext]) -> List[Tool]:
        final_tools_list: List[Tool] = []
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

                    tool_obj = Tool(
                        name=getattr(tool_instance, 'name'),
                        description=getattr(tool_instance, 'description'),
                        function=execute_method,
                        parameters=getattr(tool_instance, 'parameters'),
                        timeout=getattr(tool_instance, 'timeout', 30)
                    )
                    final_tools_list.append(tool_obj)

            except Exception as e:
                print(f"Error: Processing tool '{tool_name}' failed: {e}")

        print(f"{self.__class__.__name__} tools: {[t.name for t in final_tools_list]}")
        return final_tools_list

    def _get_response_format_prompt(self) -> str:
        base_prompt = super()._get_response_format_prompt()
        
        if self.final_output_schema:
            final_schema_str = json.dumps(self.final_output_schema, ensure_ascii=False, indent=2)
            final_prompt_part = f"""

--- Final Output Schema ---
When you use the 'finish' action, the value of the 'final_response' key in 'action_input' must be a JSON object that conforms to the following schema:

{final_schema_str}
"""
            return base_prompt + final_prompt_part
            
        return base_prompt

    def _build_initial_system_message_content(self) -> str:
        tool_section = self._format_tools_for_prompt()
        format_section = self._get_response_format_prompt()
        
        full_content = f"{self.system_prompt}\n\n"
        if self.tools:
            full_content += f"Current available tools:\n{tool_section}\n\n"
        else:
            full_content += "Current no available tools.\n\n"
        
        full_content += f"Response format requirements:\n{format_section}"
        return full_content

    def _format_tools_for_prompt(self) -> str:
        if not self.tools:
            return "Current no available tools."
        
        tool_descriptions = "\n\n".join(
            [tool.format_for_prompt() for tool in self.tools.values()]
        )
        return tool_descriptions

    def _prepare_llm_request_messages(self) -> List[Message]:
        if not self.messages or self.messages[0].role != 'system':
            print("Error: Message history is empty or the first message is not a system message!")
            return self.messages[:]

        system_message = self.messages[0]
        history_to_manage = self.messages[1:]  
        
        if self.history_strategy is not None:
            try:
                managed_history = self.history_strategy.apply(history_to_manage)
            except Exception as e:
                print(f"Error: Applying history strategy ({type(self.history_strategy).__name__}) failed: {e}. Falling back to keeping all.")
                managed_history = history_to_manage[:]  
        else:
            managed_history = history_to_manage[:]  

        messages_to_send = [system_message] + managed_history
        return messages_to_send

    def _execute_tool(self, tool_name: str, tool_input: Dict[str, Any]) -> str:
        if tool_name not in self.tools:
            error_msg = f"Error: Tool '{tool_name}' does not exist. Available tools: {list(self.tools.keys())}"
            print(error_msg)
            return error_msg

        tool = self.tools[tool_name]
        print(f"Executing tool: {tool_name} with input: {json.dumps(tool_input, ensure_ascii=False, default=str)}")
        result_queue = queue.Queue()

        def execute_in_thread():
            try:
                safe_input_for_exec = {str(k): v for k, v in tool_input.items()}
                result = tool.function(**safe_input_for_exec)
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
                        raw_output = f"Tool: {tool_name}\nParameters: {tool_input_str_for_log}\nResult:\n <No return value>"
                        return raw_output
                    
                    result_str = str(result)
                    
                    if not result_str.strip() and result_str != "":
                         raw_output = f"Tool: {tool_name}\nParameters: {tool_input_str_for_log}\nResult:\n <Empty string>"
                         return raw_output
                    
                    formatted_result = f"Tool: {tool_name}\nParameters: {tool_input_str_for_log}\nResult:\n {result_str}"
                    return formatted_result
                except Exception as e:
                     print(f"Warning: Tool '{tool_name}' result cannot be safely converted to string or formatted: {e}")
                     raw_output = f"Tool: {tool_name}\nParameters: {tool_input_str_for_log}\nResult:\n <Undisplayable complex object, conversion/formatting error: {str(e)}>"
                     return raw_output
            else:
                error_obj = result 
                print(f"Tool '{tool_name}' execution failed. Input: {tool_input_str_for_log}. Error: {type(error_obj).__name__}: {str(error_obj)}")
                error_raw_output = f"Tool: {tool_name}\nParameters: {tool_input_str_for_log}\nResult:\n <Execution failed, error: {type(error_obj).__name__}: {str(error_obj)}>"
                return error_raw_output
        except queue.Empty:
            print(f"Tool '{tool_name}' execution timed out (exceeded {timeout_seconds} seconds). Input: {json.dumps(tool_input, ensure_ascii=False, default=str)}")
            timeout_raw_output = f"Tool: {tool_name}\nParameters: {json.dumps(tool_input, ensure_ascii=False, default=str)}\nResult:\n <Execution timed out, exceeded {timeout_seconds} seconds>"
            return timeout_raw_output
        except Exception as e:
             print(f"Unexpected queue or processing error during tool '{tool_name}' execution: {e}. Input: {json.dumps(tool_input, ensure_ascii=False, default=str)}")
             error_queue_raw_output = f"Tool: {tool_name}\nParameters: {json.dumps(tool_input, ensure_ascii=False, default=str)}\nResult:\n <Unexpected error during execution: {str(e)}>"
             return error_queue_raw_output

    def auto_execute_tools(self, auto_tools: Optional[List[Dict[str, Any]]] = None) -> None:
        if auto_tools is None:
            return
        for tool in auto_tools:
            name = tool.get("name")
            params = tool.get("params", {})
            if name in self.tools:
                print(f"Auto-executing tool: {name} with params: {params}")
                try:
                    output = self._execute_tool(name, params)
                    self.add_message('user', f"[Tool:{name}\nParameters:{json.dumps(params, ensure_ascii=False, default=str)}\nResult]:\n{output}", type='tool_result')
                except Exception as e:
                    error = f"Error executing tool {name}: {e}"
                    print(f"Error auto-executing tool {name}: {e}")
                    self.add_message('user', f"[Tool:{name}\nParameters:{json.dumps(params, ensure_ascii=False, default=str)}\nError]:\n{error}", type='tool_result')

    def run(self, user_input: str = None, auto_tools: Optional[List[Dict[str, Any]]] = None) -> Any: 
        if user_input:
            self.add_message('user', user_input) 
            print(f"User input:\n {user_input}")

        print(f"Current context:\n {self.context}")

        if auto_tools:
            self.auto_execute_tools(auto_tools)

        final_answer = None
        for i in range(self.max_iterations):
            print(f"\n----- [Iteration {i + 1}/{self.max_iterations}] -----")

            prompt_messages = self._prepare_llm_request_messages()

            max_parse_retries = 3
            parsed_response = None
            raw_response = ""
            
            for retry_count in range(max_parse_retries):
                try:
                    output_dir = self.context.get("output")
                    response_obj = self.get_llm_response(prompt_messages, output_dir=output_dir)
                    raw_response = response_obj['content']
                    print(f"LLM Raw Response (Iteration {i+1}, Attempt {retry_count+1}):\n{raw_response}")
                    
                    if retry_count == 0:  
                        self.add_message('assistant', raw_response)    
                    parsed_response = self._parse_llm_response(raw_response)
                    print(f"Parsed LLM Response: {json.dumps(parsed_response, indent=2, ensure_ascii=False, default=str)}")
                    
                    if "error" in parsed_response:
                        raise ValueError(f"Parsing error: {parsed_response['error']}: {parsed_response.get('message', 'Unknown error')}")
                    
                    break
                    
                except Exception as e:
                    print(f"Response parsing failed (Attempt {retry_count+1}/{max_parse_retries}): {e}")
                    if retry_count < max_parse_retries - 1:  
                        format_reminder_prompt = self._get_response_format_prompt()
                        error_feedback_to_llm = f"""
Your previous response could not be parsed or validated correctly due to: {str(e)}
The raw response started with: {raw_response[:200]}...

Please strictly follow the required JSON schema and formatting instructions.
Ensure all required fields are present and the JSON is well-formed.

Required schema:
{format_reminder_prompt}

Retry generating the response.
"""
                        self.add_message('user', error_feedback_to_llm, type='parse_error')
                        prompt_messages = self._prepare_llm_request_messages()  
                    else:
                        print(f"Maximum retry attempts reached, failed to parse LLM response")
                        parsed_response = {
                            "error": "parse_error_max_retries",
                            "thought": f"After {max_parse_retries} attempts, still unable to generate a valid formatted response",
                            "action": "finish",
                            "action_input": {"final_response": f"Sorry, I encountered a technical issue and couldn't process your request correctly."},
                            "status": "complete"
                        }
            
            if parsed_response is None or "error" in parsed_response:
                print("Failed to parse LLM response, using default error response")
                parsed_response = {
                    "thought": "Failed to parse response",
                    "action": "finish",
                    "action_input": {"final_response": "Sorry, I encountered a technical issue and couldn't process your request correctly."},
                    "status": "complete"
                }

            action = parsed_response.get("action")
            action_input = parsed_response.get("action_input")
            status = parsed_response.get("status")  

            if status == "complete" or (action == "finish" and status != "continue"):
                if isinstance(action_input, dict) and "final_response" in action_input:
                    final_answer = action_input["final_response"]
                else:
                    final_answer = action_input
                break

            elif action and action != "finish" and status == "continue": 
                if not isinstance(action_input, dict):
                     tool_result = f"Error: 'action_input' for tool '{action}' is invalid or missing (requires a dictionary), received {type(action_input)}."
                     print(tool_result)
                     self.add_message('user', tool_result, type='tool_result_error')
                else:
                    tool_result = self._execute_tool(action, action_input)
                    print(f"Tool execution result:\n{tool_result}")
                    self.add_message('user', tool_result, type='tool_result')

            else: 
                 print("Warning: LLM response format inconsistency or status mismatch with action")
                 status_mismatch = f"Error: Your response is inconsistent. If action is '{action}', status should be 'complete' if action is 'finish' else 'continue', but received '{status}'."
                 self.add_message('user', status_mismatch, type='error')
                 continue 

        else: 
            print(f"Max iterations reached ({self.max_iterations})")
            final_answer = "Max iterations reached but no answer found."
            if self.messages and self.messages[-1].role == 'assistant':
                final_answer = self.messages[-1].content

        print(f"{self.__class__.__name__} finished")
        return final_answer if final_answer is not None else "Sorry, I was unable to complete the request."
    

    def stream(self, user_input: str = None) -> List[Dict[str, Any]]:
        print(f"System prompt:\n {self.messages[0].content}")
        conversation: List[Dict[str, Any]] = []
        
        if self.messages and self.messages[0].role == "system":
            conversation.append({
                "role": "system",
                "content": self.messages[0].content
            })

        if user_input:
            self.add_message('user', user_input)
            print(f"Stream input:\n {user_input}")
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
                        raise ValueError(f"Parsing error: {parsed_response['error']}: {parsed_response.get('message', 'Unknown error')}")
                    
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
                            "thought": f"After {max_parse_retries} attempts, still unable to generate a valid formatted response",
                            "action": "finish",
                            "action_input": {"final_response": "Sorry, I encountered a technical issue with response formatting."},
                            "status": "complete"
                        }
                        conversation.append({
                            "role": "error",
                            "content": f"After {max_parse_retries} attempts, still unable to parse LLM response"
                        })
            
            if parsed_response is None or "error" in parsed_response:
                print("Failed to parse LLM response, using default error response (Stream Mode)")
                parsed_response = {
                    "thought": "Failed to parse response",
                    "action": "finish",
                    "action_input": {"final_response": "Sorry, I encountered a technical issue and couldn't process your request correctly."},
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
