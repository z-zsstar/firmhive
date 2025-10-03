import os
import json
import shlex
import r2pipe
import requests
import traceback
import subprocess
from typing import Dict, Any, Optional, List
from agent.tools.basetool import ExecutableTool, FlexibleContext


class GetContextInfoTool(ExecutableTool):
    name = "get_context_info"
    description = "获取当前分析任务的上下文信息，例如正在分析的文件或目录。"
    parameters: Dict[str, Any] = {
        "type": "object",
        "properties": {},
        "required": []
    }

    def execute(self) -> str:
        file_path = self.context.get("file_path")
        current_dir = self.context.get("current_dir")
        base_path = self.context.get("base_path")
        file_name_str = os.path.basename(file_path) if file_path else "未指定"
        dir_name_str = os.path.basename(current_dir) if current_dir else "未指定"
        rel_dir_path = os.path.relpath(current_dir, base_path) if current_dir and base_path else "未指定"
        
        return (
            f"当前分析焦点：\n"
            f"- 文件：{file_name_str}\n"
            f"- 目录：{dir_name_str}\n"
            f"- 相对于固件根目录的目录路径：{rel_dir_path}"
        )  

class ShellExecutorTool(ExecutableTool):
    name = "execute_shell"
    ALLOWED_COMMANDS = ['file', 'find', 'strings', 'grep', 'head', 'tail', 'readelf', 'cat', 'sort', 'ls']
    DANGEROUS_PATTERNS = ['>', '>>', 'cd', 'pushd', 'popd', ';', '&&', '||', '`', '$(']
    timeout = 180

    def __init__(self, context: Optional[FlexibleContext] = None):
        super().__init__(context)
        file_path = self.context.get("file_path", "Not specified")
        file_name = os.path.basename(file_path) if file_path else "Not specified"
        current_dir = self.context.get("current_dir", "Not specified")

        self.description = f"""在当前目录（{os.path.basename(current_dir)}）中执行只读 shell 命令。
    **警告：** 此工具严格限制在当前工作目录内。所有文件操作不得引用父目录或任何其他目录。建议使用 `file` 工具在当前目录内进行探索和识别。
    **注意：** 所有命令都在当前目录中执行。所有路径参数应相对于当前目录。禁止包含 '/' 或 '..' 的路径。
    支持的命令：{', '.join(self.ALLOWED_COMMANDS)}。
    禁止输出重定向（'>'、'>>'）、命令链接和目录更改。"""

        self.parameters = {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": f"要执行的 shell 命令。命令将在 '{os.path.basename(current_dir)}' 目录中执行。命令中的所有路径应相对于此目录。"
                }
            },
            "required": ["command"]
        }


    def execute(self, command: str) -> str:
        return self.execute_shell(command=command)
    
    def _resolve_path(self, path: str, working_dir: str) -> Optional[str]:
        if os.path.isabs(path):
            return None

        real_working_dir = os.path.realpath(working_dir)
        
        prospective_path = os.path.join(real_working_dir, path)
        real_prospective_path = os.path.realpath(prospective_path)

        if real_prospective_path.startswith(real_working_dir + os.sep) or real_prospective_path == real_working_dir:
            return real_prospective_path
        
        return None


    def _is_safe_command(self, command: str) -> tuple[bool, str]:
        if not command or not command.strip():
            return False, "命令不能为空。"
        
        base_path = self.context.get("base_path")
        current_dir = self.context.get("current_dir")

        if not base_path or not os.path.isdir(os.path.normpath(base_path)):
            return False, "[安全错误] 上下文中未提供有效的固件根目录（base_path）。"
        if not current_dir or not os.path.isdir(os.path.normpath(current_dir)):
            return False, "[安全错误] 上下文中未提供有效的工作目录（current_dir）。"
        
        norm_current_dir = os.path.normpath(current_dir)
        norm_base_path = os.path.normpath(base_path)
        if not norm_current_dir.startswith(norm_base_path):
            return False, f"[安全错误] 当前工作目录 '{current_dir}' 不在固件根目录 '{base_path}' 内。"

        for pattern in self.DANGEROUS_PATTERNS:
            if pattern in command:
                return False, f"[安全错误] 命令包含禁止的模式：'{pattern}'"

        try:
            tokens = shlex.split(command)
        except ValueError as e:
            return False, f"解析命令失败：{e}。"
        
        if not tokens:
            return False, "无效的命令。"
        
        base_cmd = tokens[0]
        
        if base_cmd not in self.ALLOWED_COMMANDS:
            return False, f"[安全错误] 命令 '{base_cmd}' 不在允许的命令列表中（{', '.join(sorted(self.ALLOWED_COMMANDS))}）。"
        
        path_like_cmds = {'file', 'cat', 'head', 'tail', 'readelf', 'strings', 'ls'}

        if base_cmd in path_like_cmds:
            for token in tokens[1:]:
                if not token.startswith('-'):
                    if self._resolve_path(token, current_dir) is None:
                        return False, f"[安全错误] 参数 '{token}' 解析到当前工作目录之外的路径或包含非法字符。"
        elif base_cmd == 'find':
            path_arg_found = False
            for token in tokens[1:]:
                if not token.startswith('-'):
                    if not path_arg_found:
                        if self._resolve_path(token, current_dir) is None:
                            return False, f"[安全错误] find 命令的搜索路径 '{token}' 解析到当前工作目录之外的路径。"
                        path_arg_found = True
        elif base_cmd == 'grep':
            if len(tokens) > 2 and not tokens[-1].startswith('-'):
                path_token = tokens[-1]
                if self._resolve_path(path_token, current_dir) is None:
                    return False, f"[安全错误] grep 命令的文件路径 '{path_token}' 解析到当前工作目录之外的路径。"
        
        return True, ""

    def execute_shell(self, command: str) -> str:
        try:
            is_safe, error_msg = self._is_safe_command(command)
            if not is_safe:
                return f"[Security Error] {error_msg}"
            
            working_dir = os.path.normpath(str(self.context.get("current_dir"))) 
            
            cmd_args = shlex.split(command)

            result = subprocess.run(
                cmd_args,
                shell=False,
                cwd=working_dir, 
                capture_output=True, 
                text=True, 
                timeout=self.timeout,
                check=False, 
                encoding='utf-8', 
                errors='ignore'
            )
            
            output = f"退出代码：{result.returncode}\n"
            if result.stdout:
                output += f"标准输出：\n{result.stdout}\n"
            if result.stderr:
                output += f"标准错误：\n{result.stderr}\n"
            
            return output
            
        except subprocess.TimeoutExpired: 
            return f"[错误] 命令 '{command[:100]}...' 在 {self.timeout}秒 后超时。"
        except Exception as e: 
            return f"[错误] 命令 '{command[:100]}...' 执行失败：{e}"


class Radare2Tool(ExecutableTool):
    name: str = "r2"
    description: str = """
    与 Radare2 交互式会话交互以分析当前二进制文件。注意，此工具会自动为当前分析焦点文件建立并维护 r2 会话。

    主要功能：
    - 发送 Radare2 命令并获取输出
    - 会话状态在调用之间保持（对于同一文件）
    - 支持使用 r2ghidra 插件进行反编译：
    * 使用 `pdg` 命令反编译函数
    * 提供类似 C 的伪代码输出
    
    """
    parameters: Dict[str, Any] = {
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": "Command to interact directly with Radare2"
            }
        },
        "required": ["command"]
    }
    timeout = 600

    def __init__(self, context: FlexibleContext):
        super().__init__(context)
        self.r2: Optional[r2pipe.Pipe] = None
        self._initialize_r2()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def _initialize_r2(self):
        if self.r2:
            return True

        file_path = self.context.get("file_path")
        if not file_path:
            print("错误：无法在没有 file_path 的情况下初始化 Radare2。")
            return False

        print(f"正在为 {file_path} 初始化 Radare2 会话...")
        try:
            self.r2 = r2pipe.open(file_path, flags=['-e', 'scr.interactive=false'])
            print("正在为 r2 主工具会话运行初始分析（aaa）...")
            self.r2.cmd('aaa')
            print("Radare2 会话已初始化。")
            return True
        except Exception as e:
            print(f"初始化 Radare2 会话时出错：{e}")
            self.r2 = None
            return False

    def execute(self, command: str) -> str:
        if not self.r2:
            print("Radare2 会话未就绪，正在尝试初始化...")
            if not self._initialize_r2():
                return "[错误] Radare2 会话初始化失败。请检查文件路径和 r2 安装。"

        if not command:
            return "[错误] 未向 Radare2 提供命令。"

        print(f"执行 r2 命令：{command}")
        try:
            result = self.r2.cmd(command)
            return result.strip() if result else f"[{command} 命令无输出]"
        except Exception as e:
            print(f"执行 Radare2 命令 '{command}' 时出错：{e}。正在重置管道。")
            return f"[错误] 执行命令 '{command}' 失败：{e}。Radare2 管道可能不稳定。"

    def close(self):
        if self.r2:
            print(f"正在关闭 {self.context.get('file_path', '未知文件')} 的 Radare2 管道...")
            try:
                self.r2.quit()
            except Exception as e:
                print(f"为 {self.context.get('file_path', '未知文件')} 执行 r2.quit() 时出错：{e}")
            finally:
                self.r2 = None
                print("Radare2 管道已关闭，r2 实例已重置。")
        else:
            pass


class Radare2FileTargetTool(ExecutableTool):
    name: str = "r2_file_target"
    description: str = """
    与 Radare2 交互式会话交互以分析指定的二进制文件。注意，此工具会自动为目标分析对象建立并维护 r2 会话。

    主要功能：
    - 发送 Radare2 命令并获取输出
    - 会话状态在调用之间保持（对于同一文件）
    - 支持使用 r2ghidra 插件进行反编译：
    * 使用 `pdg` 命令反编译函数
    * 提供类似 C 的伪代码输出

    """
    parameters: Dict[str, Any] = {
        "type": "object",
        "properties": {
            "file_name": {
                "type": "string",
                "description": "要分析的文件名称。提供相对于固件根目录的路径，不要以 ./ 开头。"
            },
            "command": {
                "type": "string",
                "description": "直接与 Radare2 交互的命令"
            }
        },
        "required": ["file_name", "command"]
    }
    timeout = 600

    def __init__(self, context: FlexibleContext):
        super().__init__(context)
        self.r2: Optional[r2pipe.Pipe] = None
        self.current_analyzed_file: Optional[str] = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def _initialize_r2_for_file(self, file_path: str) -> bool:
        if self.r2 and self.current_analyzed_file == file_path:
            return True

        if self.r2:
            print(f"正在关闭先前文件的 Radare2 会话：{self.current_analyzed_file}")
            self.close()

        if not file_path:
            print("错误：无法在没有有效 file_path 的情况下初始化 Radare2。")
            return False
        
        if not os.path.exists(file_path):
            print(f"错误：在 {file_path} 找不到文件。无法初始化 Radare2。")
            return False


        print(f"正在为 {file_path} 初始化 Radare2 会话...")
        try:
            self.r2 = r2pipe.open(file_path, flags=['-e', 'scr.interactive=false'])
            if not self.r2:
                print(f"错误：为 {file_path} 执行 r2pipe.open 失败。文件可能不存在或 r2 未正确安装。")
                self.current_analyzed_file = None
                return False
            print("正在为 r2 文件目标工具运行初始分析（aaa）...")
            self.r2.cmd('aaa')
            self.current_analyzed_file = file_path
            print(f"Radare2 会话已成功初始化：{file_path}")
            return True
        except Exception as e:
            print(f"为 {file_path} 初始化 Radare2 会话时出错：{e}")
            self.r2 = None
            self.current_analyzed_file = None
            return False

    def execute(self, file_name: str, command: str) -> str:
        current_dir = self.context.get("current_dir")
        if not current_dir:
            return "[错误] 上下文中未找到 current_dir。无法确定文件路径。"

        if not file_name:
            return "[错误] 未提供 file_name。"
        
        target_file_path = os.path.join(current_dir, file_name)

        if not self._initialize_r2_for_file(target_file_path):
            return f"[错误] 为 {target_file_path} 初始化 Radare2 会话失败。请确保文件存在且 Radare2 配置正确。"

        if not self.r2:
            return f"[错误] 即使在尝试初始化后，Radare2 会话对 {target_file_path} 仍不可用。"

        if not command:
            return "[错误] 未向 Radare2 提供命令。"

        print(f"在文件 '{target_file_path}' 上执行 r2 命令：'{command}'")
        try:
            result = self.r2.cmd(command)
            return result.strip() if result is not None else f"['{command}' 命令无输出]"
        except Exception as e:
            print(f"在 '{target_file_path}' 上执行 Radare2 命令 '{command}' 时出错：{e}。正在重置此文件的管道。")
            self.close()
            return f"[错误] 在 '{target_file_path}' 上执行命令 '{command}' 失败：{e}。管道已重置。"

    def close(self):
        if self.r2:
            print(f"正在关闭 {self.current_analyzed_file} 的 Radare2 管道...")
            try:
                self.r2.quit()
            except Exception as e:
                print(f"为 {self.current_analyzed_file} 执行 r2.quit() 时出错：{e}")
            finally:
                self.r2 = None
                self.current_analyzed_file = None
                print("Radare2 管道已关闭，状态已清除。")
        else:
            pass


class VulnerabilitySearchTool(ExecutableTool):
    name: str = "cve_search_nvd"
    description: str = "使用 NVD API 2.0 搜索与软件关键词相关的 CVE 漏洞信息。结果包括 CVE ID、描述和 CVSSv3 分数，按分数降序排列。"
    parameters: Dict[str, Any] = {
        "type": "object",
        "properties": {
            "keyword_search": {
                "type": "string",
                "description": "要在 NVD 中搜索的软件名称或关键词（例如，'BusyBox 1.33.1'、'OpenSSL'、'Linux Kernel'）。如果需要通过 NVD 的关键词搜索匹配特定版本，请在关键词中包含版本号。"
            },
             "max_results": {
                  "type": "integer",
                  "description": "限制返回的匹配 CVE 数量（将显示得分最高的）。",
                  "default": 10,
                  "minimum": 1,
                  "maximum": 50
             }
        },
        "required": ["keyword_search"]
    }
    timeout = 30

    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    REQUEST_TIMEOUT = 30
    DEFAULT_USER_AGENT = "AgentNvdSearchTool/1.2"

    def execute(self, keyword_search: str, max_results: int = 10, **kwargs) -> str:
        max_results = min(max_results, self.parameters["properties"]["max_results"]["maximum"])
        results_to_fetch = max(max_results * 2, 50)

        params = {
            "keywordSearch": keyword_search,
            "resultsPerPage": results_to_fetch,
            "startIndex": 0,
            "keywordExactMatch": None
        }

        print(f"Querying NVD API: keyword='{keyword_search}', fetching up to {results_to_fetch} potential results.")
        
        headers = {'User-Agent': self.DEFAULT_USER_AGENT}
        api_key = os.getenv("NVD_API_KEY")
        if api_key:
            headers['apiKey'] = api_key
            print("  (Found and using NVD_API_KEY)")

        try:
            response = requests.get(self.NVD_API_URL, params=params, timeout=self.REQUEST_TIMEOUT, headers=headers)
            response.raise_for_status()
            data = response.json()

            total_results = data.get("totalResults", 0)
            if total_results == 0:
                return f"NVD API found no CVEs related to the keyword '{keyword_search}'."

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                 return f"NVD API reported {total_results} results for '{keyword_search}', but failed to retrieve vulnerability list details."

            print(f"NVD API returned {len(vulnerabilities)} raw results (total available: {total_results}). Processing and sorting...")

            filtered_cves = []
            for item in vulnerabilities:
                cve_item = item.get("cve", {})
                cve_id = cve_item.get("id")
                if not cve_id: continue

                cvss_v3_score = self._get_cvss_v3_score(cve_item.get("metrics", {}))

                description = self._get_english_description(cve_item.get("descriptions", []))

                filtered_cves.append({
                    "id": cve_id,
                    "score_v3": cvss_v3_score,
                    "description": description.strip()
                })

            if not filtered_cves:
                 return f"Found {total_results} potential CVEs related to '{keyword_search}', but could not extract valid CVE information after processing."

            filtered_cves.sort(key=lambda x: (x['score_v3'] is not None, x['score_v3'] if x['score_v3'] is not None else -1.0), reverse=True)

            if len(filtered_cves) > max_results:
                print(f"Displaying top {max_results} of {len(filtered_cves)} processed CVEs, sorted by score.")
                filtered_cves = filtered_cves[:max_results]
            
            output_text = (f"Top {len(filtered_cves)} CVE results for '{keyword_search}' (sorted by CVSSv3 score):\n\n")

            for idx, cve in enumerate(filtered_cves, 1):
                 output_text += f"{idx}. [{cve['id']}] (CVSSv3 Score: {cve['score_v3'] or 'N/A'})\n   {cve['description']}\n\n"

            return self._limit_output(output_text.strip())

        except requests.exceptions.Timeout:
            return f"[Error] NVD API request timed out ({self.REQUEST_TIMEOUT} seconds)."
        except requests.exceptions.HTTPError as e:
             return f"[Error] NVD API request failed: {e.response.status_code} {e.response.reason}. Please check API status or your query."
        except requests.exceptions.RequestException as e:
            return f"[Error] NVD API network request failed: {e}"
        except json.JSONDecodeError:
             return "[Error] NVD API returned invalid JSON data. The API might be temporarily unavailable or its format may have changed."
        except Exception as e:
            traceback.print_exc()
            return f"[Error] An internal error occurred while processing NVD API results: {e}"

    def _get_english_description(self, descriptions: List[Dict[str, str]]) -> str:
        for desc_item in descriptions:
            if desc_item.get("lang") == "en":
                return desc_item.get("value", "No English description available.")
        return "No description found."

    def _get_cvss_v3_score(self, metrics: Dict[str, Any]) -> Optional[float]:
        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            try: return metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            except (KeyError, IndexError, TypeError): pass
        if "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            try: return metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
            except (KeyError, IndexError, TypeError): pass
        return None

    def _limit_output(self, text: str, max_len: int = 10000) -> str:
        if len(text) > max_len:
             last_newline = text.rfind('\n', 0, max_len)
             if last_newline != -1:
                  return text[:last_newline] + "\n...[Output truncated]"
             else:
                  return text[:max_len] + "...[Output truncated]"
        return text





