import json
import os
import fcntl
from typing import Dict, List, Any, Optional, Type, Union

from agent.base import BaseAgent
from agent.historystrategy import HistoryStrategy
from agent.tools.basetool import ExecutableTool, FlexibleContext

DEFAULT_KB_FILE = "knowledge_base.jsonl"

FINDING_SCHEMA: Dict[str, Dict[str, Any]] = {
    "name": {
        "type": "string", 
        "description": "为项目定义唯一标识符。建议格式：'<类型>-<函数/模块>'。"
    },
    "location": {
        "type": "string",
        "description": "精确位置（文件:行号 函数名 地址）\n"
    },
    "description": {
        "type": "string",
        "description": "详细描述发现或观察结果。\n"
    },
    "link_identifiers": {
        "type": "array",
        "items": {"type": "string"},
        "description": "将此发现与其他发现连接的特定标识符列表（NVRAM 变量、函数名、文件路径）。避免使用通用术语，确保精准追踪跨文件、跨进程的数据流与交互。\n"
    },
    "code_snippet": {
        "type": "string",
        "description": "与发现直接相关的代码片段。应包含足够的上下文以理解问题，通常为3-10行。"
    },
    "risk_score": {
        "type": "number",
        "description": "风险评分（0.0-10.0）"
    },
    "confidence": {
        "type": "number",
        "description": "对发现准确性和可利用性的置信度（0.0-10.0）"
    },
    "notes": {
        "type": "string",
        "description": "其他需要记录的备注信息，供人工分析师参考。包括做出的假设、需要进一步验证的文件或者变量来源、剩余问题或下一步分析的建议\n"
    }
}

FINDING_SCHEMA_REQUIRED_FIELDS: List[str] = ["location", "description"]

class KnowledgeBaseMixin:
    def _initialize_kb(self, context: FlexibleContext):
        output_from_context = context.get("output")

        if output_from_context and isinstance(output_from_context, str):
            self.output = output_from_context
        else:
            raise ValueError("'output' not found in context or invalid.")

        if not os.path.exists(self.output):
            try:
                os.makedirs(self.output, exist_ok=True)
                print(f"Created output directory: {os.path.abspath(self.output)}")
            except OSError as e:
                print(f"Warning: Could not create output directory '{self.output}': {e}. Attempting to create the knowledge base file in the current directory.")
                self.output = "."

        self.kb_file_path = os.path.join(self.output, DEFAULT_KB_FILE)

        kb_specific_dir = os.path.dirname(self.kb_file_path)
        if kb_specific_dir and not os.path.exists(kb_specific_dir):
            try:
                os.makedirs(kb_specific_dir, exist_ok=True)
            except OSError as e:
                 print(f"Warning: Could not create specific directory for KB file '{kb_specific_dir}': {e}")

        print(f"Knowledge base file path set to: {os.path.abspath(self.kb_file_path)}")

    def _load_kb_data(self, lock_file) -> List[Dict[str, Any]]:
        findings = []
        try:
            fcntl.flock(lock_file, fcntl.LOCK_SH)
            lock_file.seek(0)
            for line_bytes in lock_file:
                if not line_bytes.strip():
                    continue
                try:
                    findings.append(json.loads(line_bytes.decode('utf-8-sig')))
                except json.JSONDecodeError as e:
                    print(f"Warning: Error parsing a line in the knowledge base, skipped. Error: {e}. Line: {line_bytes[:100]}...")
            return findings
        except Exception as e:
            print(f"Error loading KB '{self.kb_file_path}': {e}. Returning an empty list.")
            return []
        finally:
            try:
                fcntl.flock(lock_file, fcntl.LOCK_UN)
            except (ValueError, OSError):
                pass

class StoreFindingsTool(ExecutableTool, KnowledgeBaseMixin):
    name: str = "StoreStructuredFindings"
    description: str = "以追加模式将结构化的固件分析发现存储到知识库中。每个发现都必须包含详细的路径和条件约束，以确保可追溯性和可验证性。"
    parameters: Dict = {
        "type": "object",
        "properties": {
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": FINDING_SCHEMA,
                    "required": FINDING_SCHEMA_REQUIRED_FIELDS
                },
                "description": "要存储的发现列表。列表中的每个对象都应遵循定义的模式。工具将自动添加上下文信息（如 'file_path'）。"
            }
        },
        "required": ["findings"]
    }

    def __init__(self, context: FlexibleContext):
        ExecutableTool.__init__(self, context)
        KnowledgeBaseMixin._initialize_kb(self, context)

    def execute(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        context_file_path = self.context.get("file_path")
        context_dir = self.context.get("current_dir")
        context_base_path = self.context.get("base_path")
        context_stage = self.context.get("stage")

        context_dir_path = None
        if context_dir and context_base_path:
            try:
                context_dir_path = os.path.relpath(context_dir, context_base_path)
            except ValueError:
                context_dir_path = context_dir

        if not findings:
            return {"status": "info", "message": "Info: No findings provided for storage."}

        enriched_findings = []
        for finding_dict in findings:
            if isinstance(finding_dict, dict):
                finding_copy = finding_dict.copy()

                if context_file_path:
                    finding_copy['file_path'] = os.path.relpath(context_file_path, context_base_path)
                elif context_dir_path:
                    finding_copy['dir_path'] = os.path.relpath(context_dir, context_base_path)
                if context_stage:
                    finding_copy['stage'] = context_stage

                enriched_findings.append(finding_copy)
            else:
                print(f"Warning: Non-dictionary item found in findings list and was ignored: {finding_dict}")

        if not enriched_findings:
            return {"status": "info", "message": "Info: No valid findings were processed for storage."}

        try:
            with open(self.kb_file_path, 'ab') as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                try:
                    for finding in enriched_findings:
                        try:
                            json_string = json.dumps(finding, ensure_ascii=False)
                            f.write(json_string.encode('utf-8'))
                            f.write(b'\n')
                        except TypeError as te:
                            print(f"CRITICAL: Could not serialize finding, skipped. Error: {te}. Content: {str(finding)[:200]}...")
                            continue
                finally:
                    fcntl.flock(f, fcntl.LOCK_UN)

            num_stored = len(enriched_findings)
            message = f"Successfully appended {num_stored} findings to the knowledge base."
            print(f"{message}")
            return {"status": "success", "message": message, "stored_count": num_stored}

        except Exception as e:
            error_message = f"Error storing findings: {str(e)}"
            print(f"{error_message} (Details: {e})")
            return {"status": "error", "message": error_message}


class QueryFindingsTool(ExecutableTool, KnowledgeBaseMixin):
    name: str = "QueryFindings"
    description: str = "根据指定的字段名（query_key）和期望值（query_value）从知识库中检索匹配的发现。它会遍历知识库中的每条发现记录以查找匹配。"

    parameters: Dict = {
        "type": "object",
        "properties": {
            "query_key": {
                "type": "string",
                "description": "要查询的发现记录中的字段名称。",
                "enum": ["file_path", "link_identifiers", "notes"]
            },
            "query_value": {
                "description": "要匹配的值。对于 'link_identifiers' 列表，这应该是单个关键字字符串；对于其他字段，将执行直接相等比较。"
            }
        },
        "required": ["query_key", "query_value"]
    }

    def __init__(self, context: FlexibleContext):
        ExecutableTool.__init__(self, context)
        KnowledgeBaseMixin._initialize_kb(self, context)

    def _check_match(self, finding_item: Dict[str, Any], query_key: str, query_value: Any) -> bool:
        if not isinstance(finding_item, dict) or query_key not in finding_item:
            return False

        actual_value = finding_item[query_key]

        if query_key == "link_identifiers":
            if isinstance(actual_value, list) and isinstance(query_value, str):
                return query_value in [str(item) for item in actual_value if isinstance(item, (str, int, float, bool))]
            return False

        return actual_value == query_value

    def execute(self, query_key: str, query_value: Any) -> List[Dict[str, Any]]:
        if not isinstance(query_key, str) or not query_key:
            return [{"error": "Query key 'query_key' must be a non-empty string."}]

        results = []
        try:
            if not os.path.exists(self.kb_file_path):
                 return [{"message": f"Knowledge base file '{self.kb_file_path}' does not exist, there may be no findings yet.", "query_key": query_key, "query_value": query_value}]

            with open(self.kb_file_path, 'rb') as f:
                all_findings = self._load_kb_data(f)

            if not all_findings:
                return [{"message": "Knowledge base is empty or malformed.", "query_key": query_key, "query_value": query_value}]

            for finding_item in all_findings:
                if self._check_match(finding_item, query_key, query_value):
                    results.append(finding_item.copy())

            query_value_str = str(query_value)
            if len(query_value_str) > 100: query_value_str = query_value_str[:100] + "..."

            print(f"[Tool - Query] Found {len(results)} matching findings for key '{query_key}' and value '{query_value_str}'.")
            if not results:
                return [{"message": f"No findings matched the query key '{query_key}' and value '{query_value_str}'."}]
            return results
        except FileNotFoundError:
             return [{"message": "Knowledge base file not found, there may be no findings yet.", "query_key": query_key, "query_value": query_value}]
        except Exception as e:
            print(f"[Tool - Query] Error querying findings: {e}")
            return [{"error": f"Error querying findings: {str(e)}", "query_key": query_key, "query_value": query_value}]


class ListUniqueValuesTool(ExecutableTool, KnowledgeBaseMixin):
    name: str = "ListUniqueValues"
    description: str = """
    列出知识库中指定字段的所有唯一值，对探索性分析和构建更精确的查询很有用。

    典型用例：
    - 列出 'link_identifiers' 以发现代码中的关键标识符和关联点。
    - 查询 'notes' 字段以获取更多上下文和相关信息。
    - 查看 'file_path' 以了解已分析文件的范围。
    - 获取特定目录中所有文件的列表。
    - 查看所有已知的漏洞类型和风险评估分布。
    """
    parameters: Dict = {
        "type": "object",
        "properties": {
            "target_key": {
                "type": "string",
                "description": "要查询唯一值的发现记录中的字段名称（例如，'file_path'、'link_identifiers'、'notes'）。"
            }
        },
        "required": ["target_key"]
    }

    def __init__(self, context: FlexibleContext):
        ExecutableTool.__init__(self, context)
        KnowledgeBaseMixin._initialize_kb(self, context)

    def execute(self, target_key: str) -> Dict[str, Any]:
        if not target_key or not isinstance(target_key, str):
            return {"status": "error", "message": "Error: 'target_key' must be a valid string."}

        unique_values = set()
        try:
            if not os.path.exists(self.kb_file_path):
                return {"status": "info", "message": "Knowledge base file not found, it might not have been initialized.", "unique_values": []}

            with open(self.kb_file_path, 'rb') as f:
                all_findings = self._load_kb_data(f)

            if not all_findings:
                return {"status": "info", "message": f"Knowledge base '{self.kb_file_path}' is empty or malformed.", "target_key": target_key, "unique_values": []}

            for finding_item in all_findings:
                if not isinstance(finding_item, dict):
                    continue

                if target_key in finding_item:
                    value_to_add = finding_item[target_key]
                    if isinstance(value_to_add, list):
                        for item in value_to_add:
                            if isinstance(item, (str, int, float, bool)):
                                unique_values.add(item)
                    elif isinstance(value_to_add, (str, int, float, bool)):
                        unique_values.add(value_to_add)

            try:
                sorted_unique_values = sorted(list(unique_values), key=lambda x: str(x))
            except TypeError:
                 sorted_unique_values = list(unique_values)

            return {
                "status": "success",
                "message": f"Successfully retrieved all unique values for the field '{target_key}'.",
                "target_key": target_key,
                "unique_values": sorted_unique_values
            }

        except FileNotFoundError:
            return {"status": "info", "message": "Knowledge base not found.", "target_key": target_key, "unique_values": []}
        except Exception as e:
            error_message = f"Error getting unique values for key '{target_key}': {str(e)}"
            print(f"[Tool - ListUnique] {error_message}")
            return {"status": "error", "message": error_message, "target_key": target_key, "unique_values": []}


DEFAULT_KB_SYSTEM_PROMPT = f"""
你是一个固件分析知识库代理，负责高效准确地处理固件分析发现的存储、查询和关联分析。当没有有效的风险信息或与用户请求无关时，不要执行任何存储或查询操作。

## **存储前的准备工作**
**在每次存储操作之前，强烈建议首先使用 `ListUniqueValues` 工具了解知识库的整体状态：**
- 使用 `ListUniqueValues` 查询 'link_identifiers' 字段，检查是否存在潜在相关的发现。如果有，主动分析它们。
- 使用 `ListUniqueValues` 查询 'notes' 字段以获取备注，查看它们是否被其他发现引用。

## **查询前的准备工作**
- 使用 `ListUniqueValues` 查询 'file_path' 字段以了解已分析文件的范围。
- 使用 `ListUniqueValues` 查询 'link_identifiers' 字段，检查是否存在潜在相关的发现。如果有，主动分析它们。

这种探索性分析有助于：
- 精确构建后续查询条件。
- 发现潜在的关联线索。
- 避免遗漏重要信息。
- 提高查询效率和准确性。

## 工具使用指南

### 1. 存储发现 (StoreStructuredFindings)
- **目的**：将结构化的分析发现存储到知识库中。**严格筛选实际可利用且具有完整、可验证攻击链的发现。**
- **关键要求**：
  - 通过存储具有相同含义的关键字列表来建立关联。
  - 在 `description` 中详细说明**完整且可验证的攻击链**、触发条件和可利用性分析。
  - 使用 `link_identifiers` 和 `notes` 建立跨文件关联。
  - 如果通过关联发现更可信、更深层的发现，你必须主动存储它们，特别是追踪组件之间的污点流以确定完整的漏洞链，前提是你确信它们确实相关。

### 2. 查询发现 (QueryFindings)
- **目的**：根据特定条件在知识库中查询发现。
- **最佳实践**：
  - **查询前探索**：首先使用 `ListUniqueValues` 了解可查询值的范围，例如 `link_identifiers`。
  - 通过 `link_identifiers` 和 `notes` 字段建立关联。
  - 值匹配仅支持精确匹配，不支持模糊匹配。
  - **当查询为空时**：明确说明，"知识库中没有相关发现，可能需要进一步分析。"

### 3. 列出唯一值 (ListUniqueValues)
- **目的**：探索知识库中特定字段的唯一值。
- **核心重要性**：这是精确查询的必要前提；没有它，精确查询是不可能的。
- **使用场景**：
  - **查询前准备**：了解知识库的内容分布和可用查询条件。
  - 通过列出 `link_identifiers` 字段发现相关关键字列表并检查关联。
  - 通过列出 `notes` 字段查找相关发现和重要上下文。
  - 识别重复或相似的发现。

## **绝对禁止事项**
1. **不得捏造信息**：所有发现都必须基于实际的代码分析结果。不要添加实际分析中未发现的任何内容。
2. **不得猜测或推测**：只记录由**完整且可验证的证据链**支持的发现。避免使用"可能"、"似乎"或"推测"等不确定的术语。
3. **不得记录理论发现**：不要存储关于不良实践（例如使用 `strcpy`）的发现，除非你能**证明它们会导致可利用的漏洞**。部分或不完整的路径是不可接受的。
4. **准确区分分析状态**：**"没有发现"**与**"没有问题"**不同。空的知识库表明分析尚未完成或处于初步阶段。

记住：你的工作直接影响固件安全分析的质量和效率。保持专业、准确和系统的方法。永远不要捏造或猜测任何信息。当信息不足以证明可利用性时，诚实地报告分析状态及其局限性。
"""

DEFAULT_KB_TOOLS = [StoreFindingsTool, QueryFindingsTool, ListUniqueValuesTool]

class KnowledgeBaseAgent(BaseAgent):
    def __init__(
        self,
        context: FlexibleContext,
        max_iterations: int = 25,
        history_strategy: Optional[HistoryStrategy] = None,
        tools: Optional[List[Union[Type[ExecutableTool], ExecutableTool]]] = DEFAULT_KB_TOOLS,
        system_prompt: Optional[str] = DEFAULT_KB_SYSTEM_PROMPT,
        output_schema: Optional[Dict[str, Any]] = None,
        **extra_params: Any
    ):
        tools_to_pass = tools

        final_system_prompt = system_prompt

        self.messages_filters = [{'from': context.get('base_path'), 'to': ''}, {'from': 'user_name', 'to': 'user'}]

        super().__init__(
            tools=tools_to_pass,
            context=context,
            system_prompt=final_system_prompt,
            output_schema=output_schema,
            max_iterations=max_iterations,
            history_strategy=history_strategy,
            **extra_params
        )
