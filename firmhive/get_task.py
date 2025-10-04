import sys
import argparse

T1_HARDCODED_CREDENTIALS = (
    "对固件文件系统进行全面扫描，以定位并报告所有硬编码的凭据和敏感信息。"
)

T2_COMPONENT_CVE = (
    "分析固件以生成第三方组件的软件物料清单（SBOM），并识别相关的高风险漏洞（CVE）。"
)

T3_NVRAM_INTERACTION = (
    "分析固件中对 NVRAM 和类似环境变量配置系统（例如 `getenv`）的访问。"
    "核心任务是识别并报告从这些变量到危险函数调用的完整、未清理的数据流路径。"
)

T4_WEB_ATTACK_CHAIN = (
    "分析固件的 Web 服务，以定位外部 HTTP 输入传递到危险函数（例如 `system`、`strcpy`）的漏洞。"
    "核心任务是识别并报告从 HTTP 参数到危险函数调用的完整、未清理的数据流路径。"
)

T5_COMPREHENSIVE_ANALYSIS = (
    "对固件文件系统进行全面的分析。核心目标是识别并报告从不可信输入点到危险操作的完整、可行且**实际可利用**的攻击链。"
    "分析必须关注具有明确可利用性证据的漏洞，而不是理论缺陷。自主明确地定义和陈述其所评估的攻击者模型。\n"
    "1. **输入点识别**：识别所有相关文件（二进制、配置文件、脚本等）的不可信输入源，包括但不限于网络接口（HTTP、API、套接字）、IPC、NVRAM/环境变量等。\n"
    "2. **数据流追踪**：追踪不可信数据在系统内的传播路径，并分析是否存在缺少适当验证、过滤或边界检查的过程。\n"
    "3. **组件交互分析**：关注组件之间的交互（例如 `nvram` get/set、IPC 通信、前后台交互），观察外部可控数据如何在系统内流动并影响其他组件。\n"
    "4. **利用链评估**：对于发现的每个潜在攻击链，评估其触发条件、重现步骤以及成功利用的概率，并明确该链所对应的攻击者模型与必要前提（认证级别、所需权限、网络可达性等）。\n"
    "5. **最终输出**：报告应清楚地描述攻击者最有可能成功利用的攻击路径和安全漏洞，并在每个发现中标注所采用的攻击者模型与前提条件（含认证级别、所需权限、暴露面/可达性等），并给出理由。"
)

def get_task_prompt(task_name: str) -> str:
    """
    Get the task instruction string by its variable name from the current module.
    """
    task_inputs = sys.modules[__name__]
    if not hasattr(task_inputs, task_name):
        print(f"Error: Task '{task_name}' not found.", file=sys.stderr)
        sys.exit(1)
    return getattr(task_inputs, task_name)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Get a specific task prompt by its variable name.")
    parser.add_argument("task_name", type=str, help="The variable name of the task (e.g., T1_HARDCODED_CREDENTIALS).")
    args = parser.parse_args()
    
    prompt = get_task_prompt(args.task_name)
    print(prompt) 