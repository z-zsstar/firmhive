import json
import os
import argparse

def load_knowledge_base(file_path):
    alerts = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    try:
                        alerts.append(json.loads(line))
                    except json.JSONDecodeError:
                        print(f"警告：无法解码该行，已跳过：{line.strip()}")
        return alerts
    except FileNotFoundError:
        print(f"错误：文件未找到 {file_path}")
        return None

def filter_and_sort_alerts(alerts_list):
    if not alerts_list:
        return [], 0

    def sort_key(finding):
        try:
            risk = float(finding.get('risk_score', 0) or 0)
            confidence = float(finding.get('confidence', 0) or 0)
            return (-risk, -confidence)
        except (ValueError, TypeError):
            placeholder_id = f"{finding.get('file_path', 'N/A')} at {finding.get('location', 'N/A')}"
            print(f"警告：发现中的一个或多个数值无效，以最低优先级排序：{placeholder_id}")
            return (0, 0)

    sorted_alerts = sorted(alerts_list, key=sort_key)
    return sorted_alerts, len(sorted_alerts)

def _format_verification_record_md(record: dict, header_level: int = 3) -> str:
    task = record.get('verification_task', {})
    result_raw = record.get('verification_result', {})
    duration = record.get('verification_duration_seconds', 'N/A')
    tokens = record.get('verification_token_usage', 'N/A')
    
    result_dict = None
    if isinstance(result_raw, str):
        try:
            parsed_result = json.loads(result_raw)
            if isinstance(parsed_result, dict):
                result_dict = parsed_result
        except json.JSONDecodeError: pass
    elif isinstance(result_raw, dict):
        result_dict = result_raw

    header_prefix = '#' * header_level
    name = task.get('name', '无标题的待验证发现')
    markdown_output = f"{header_prefix} {name}\n\n"
    markdown_output += f"{header_prefix}# 原始信息\n"
    path_to_display = task.get('file_path') or task.get('dir_path') or task.get('relative_path') or task.get('file_name', 'N/A')
    if path_to_display and path_to_display != 'N/A':
        markdown_output += f"- **文件/目录路径：** `{path_to_display}`\n"
    markdown_output += f"- **位置：** `{task.get('location', 'N/A')}`\n"
    if task.get('description'):
        markdown_output += f"- **描述：** {task.get('description', 'N/A')}\n"
    code_snippet_value = task.get('code_snippet')
    if code_snippet_value:
        processed_snippet_str = "\n".join(str(item) for item in code_snippet_value) if isinstance(code_snippet_value, list) else str(code_snippet_value)
        escaped_snippet = processed_snippet_str.replace('`', '\\`')
        lines = escaped_snippet.splitlines()
        indented_code_block_content = "\n".join([f"  {line}" for line in lines])
        markdown_output += f"- **代码片段：**\n  ```\n{indented_code_block_content}\n  ```\n"
    notes = task.get('notes')
    if notes:
        markdown_output += f"- **备注：** {notes}\n"
    markdown_output += f"\n{header_prefix}# 验证结论\n"
    if result_dict and 'accuracy' in result_dict and 'vulnerability' in result_dict:
        markdown_output += f"- **描述准确性：** `{result_dict.get('accuracy', 'N/A')}`\n"
        markdown_output += f"- **是否为真实漏洞：** `{result_dict.get('vulnerability', 'N/A')}`\n"
        markdown_output += f"- **风险级别：** `{result_dict.get('risk_level', 'N/A')}`\n"
        markdown_output += f"- **详细原因：** {result_dict.get('reason', 'N/A')}\n"
    else:
        output_str = json.dumps(result_dict, indent=2, ensure_ascii=False) if result_dict else str(result_raw)
        markdown_output += f"**原始验证结果：**\n```json\n{output_str}\n```\n"
    markdown_output += f"\n{header_prefix}# 验证指标\n"
    markdown_output += f"- **验证时长：** {float(duration):.2f} 秒\n" if isinstance(duration, float) else f"- **验证时长：** {duration}\n"
    markdown_output += f"- **Token 使用量：** {tokens}\n"
    markdown_output += "\n---\n\n"
    return markdown_output

def generate_verification_report_md(output_dir, output_filename="verification_report.md"):
    report_title = f"{os.path.basename(os.path.abspath(output_dir))} - 验证报告"
    results_file = os.path.join(output_dir, "verification_results.jsonl")
    
    if not os.path.exists(results_file):
        print(f"警告：在 '{output_dir}' 中未找到 'verification_results.jsonl'。")
        return False, "未找到验证结果文件"

    all_results = load_knowledge_base(results_file)
    if not all_results:
        markdown_output = f"# {report_title}\n\n验证结果文件为空。"
    else:
        filtered_results = []
        for r in all_results:
            try:
                task = r.get('verification_task', {})
                if float(task.get('risk_score', 0) or 0) > 0.5:
                    filtered_results.append(r)
            except (ValueError, TypeError):
                pass
        
        markdown_output = f"# {report_title} ({len(filtered_results)} 个发现)\n\n"
        markdown_output += "---\n\n"

        if not filtered_results:
             markdown_output += "未发现风险评分 > 0.5 的已验证发现。\n"
        else:
            sorted_results, _ = filter_and_sort_alerts(filtered_results)
            for record in sorted_results:
                markdown_output += _format_verification_record_md(record, header_level=2)
            
    output_markdown_file = os.path.join(output_dir, output_filename)
    try:
        with open(output_markdown_file, 'w', encoding='utf-8') as f:
            f.write(markdown_output)
        return True, output_markdown_file
    except IOError as e:
        return False, f"无法写入文件 {output_markdown_file}：{str(e)}"

def convert_to_markdown(alerts, kb_title, total_alerts_count):
    markdown_output = f"# {kb_title} ({total_alerts_count} 个发现)\n\n"
    markdown_output += "---\n\n"

    if not alerts:
        markdown_output += "未发现风险评分 > 0.5 的符合条件的发现。\n"
        return markdown_output

    for finding in alerts:
        name = finding.get('name', '无标题的发现')
        markdown_output += f"### {name}\n\n"
        
        path_to_display = finding.get('file_path') or finding.get('dir_path') or finding.get('relative_path') or finding.get('file_name', 'N/A')
        if path_to_display:
            markdown_output += f"- **文件/目录路径：** `{path_to_display}`\n"
        
        markdown_output += f"- **位置：** `{finding.get('location', 'N/A')}`\n"

        markdown_output += f"- **风险评分：** {finding.get('risk_score', 'N/A')}\n"
        
        markdown_output += f"- **置信度：** {finding.get('confidence', 'N/A')}\n"
        
        markdown_output += f"- **描述：** {finding.get('description', 'N/A')}\n"
        
        code_snippet_value = finding.get('code_snippet')
        if code_snippet_value:
            processed_snippet_str = "\n".join(str(item) for item in code_snippet_value) if isinstance(code_snippet_value, list) else str(code_snippet_value)
            escaped_snippet = processed_snippet_str.replace('`', '\\`')
            lines = escaped_snippet.splitlines()
            indented_code_block_content = "\n".join([f"  {line}" for line in lines])
            markdown_output += f"- **代码片段：**\n  ```\n{indented_code_block_content}\n  ```\n"
            
        link_identifiers = finding.get('link_identifiers') or finding.get('keywords')
        if link_identifiers and isinstance(link_identifiers, list):
            markdown_output += f"- **关键词：** {', '.join(str(k) for k in link_identifiers)}\n"
            
        notes = finding.get('notes')
        if notes:
            markdown_output += f"- **备注：** {notes}\n"
            
        markdown_output += "\n---\n"
        
    return markdown_output

def convert_kb_to_markdown(knowledge_base_file_path, output_filename="knowledge_base.md"):
    kb_dir_path = os.path.dirname(knowledge_base_file_path)
    kb_title = os.path.basename(kb_dir_path) if kb_dir_path else "知识库"
    
    all_alerts = load_knowledge_base(knowledge_base_file_path)
    
    if all_alerts is None:
        return False, f"无法加载或找到知识库文件：{knowledge_base_file_path}"
    if not all_alerts:
        print(f"警告：知识库 '{knowledge_base_file_path}' 为空。将生成空报告。")
    
    filtered_alerts = []
    for f in all_alerts:
        try:
            if float(f.get('risk_score', 0) or 0) > 0.5:
                filtered_alerts.append(f)
        except (ValueError, TypeError):
            pass

    sorted_alerts, _ = filter_and_sort_alerts(filtered_alerts)
    
    markdown_content = convert_to_markdown(
        sorted_alerts,
        kb_title, 
        len(sorted_alerts)
    )
    
    output_markdown_file = os.path.join(kb_dir_path, output_filename)
    
    try:
        with open(output_markdown_file, 'w', encoding='utf-8') as f:
            f.write(markdown_content)
        return True, output_markdown_file
    except IOError as e:
        return False, f"无法写入文件 {output_markdown_file}：{str(e)}"

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="将知识库从 JSONL 格式转换为 Markdown 格式。")
    subparsers = parser.add_subparsers(dest='command', required=True)
    parser_kb = subparsers.add_parser('kb', help='将知识库文件转换为 Markdown。')
    parser_kb.add_argument("knowledge_base_file", help="知识库 JSONL 文件的路径。")
    parser_kb.add_argument("-o", "--output", default="knowledge_base.md", help="输出 Markdown 文件名。")
    parser_vr = subparsers.add_parser('vr', help='从目录生成验证报告。')
    parser_vr.add_argument("output_dir", help="包含 verification_results.jsonl 的目录路径。")
    parser_vr.add_argument("-o", "--output", default="verification_report.md", help="验证报告的输出 Markdown 文件名。")
    args = parser.parse_args()

    if args.command == 'kb':
        success, message = convert_kb_to_markdown(args.knowledge_base_file, args.output)
        if success:
            print(f"成功将知识库转换为 {message}")
        else:
            print(f"错误：{message}")

    elif args.command == 'vr':
        success, message = generate_verification_report_md(args.output_dir, args.output)
        if success:
            print(f"成功生成验证报告：{message}")
        else:
            print(f"错误：{message}")