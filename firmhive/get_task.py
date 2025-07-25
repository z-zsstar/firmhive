import sys
import argparse

T1_HARDCODED_CREDENTIALS = (
    "Perform a comprehensive scan of the firmware filesystem to locate and report all hard-coded credentials and sensitive information. "
)

T2_COMPONENT_CVE = (
    "Analyze the firmware to generate a Software Bill of Materials (SBOM) for third-party components and identify associated high-risk vulnerabilities (CVEs). "
)

T3_NVRAM_INTERACTION = (
    "Analyze access to NVRAM and similar environment variable configuration systems (e.g., `getenv`) in the firmware. "
    "The core task is to identify and report the complete, unsanitized data flow path from these variables to dangerous function calls."
)

T4_WEB_ATTACK_CHAIN = (
    "Analyze the firmware's web services to locate vulnerabilities where external HTTP input is passed to dangerous "
    "functions (e.g., `system`, `strcpy`). The core task is to identify and report the complete, unsanitized data flow path from HTTP parameters to dangerous function calls. "
)

T5_COMPREHENSIVE_ANALYSIS = (
    "Perform a comprehensive security analysis of the firmware. The core objective is to identify and report "
    "complete, viable attack chains from untrusted input points to dangerous operations. The analysis should focus on "
    "practically exploitable vulnerabilities, not theoretical flaws. The report must cover the following aspects:\n"
    "1. **Input Point Identification**: Identify all potential sources of untrusted input, including but not limited "
    "to network interfaces (HTTP, API, sockets), IPC, NVRAM/environment variables, etc.\n"
    "2. **Data Flow Tracking**: Trace the propagation paths of untrusted data within the system and analyze whether "
    "there are any processes without proper validation, filtering, or boundary checks.\n"
    "3. **Component Interaction Analysis**: Focus on interactions between components (e.g., `nvram` get/set, IPC "
    "communication) to observe how externally controllable data flows within the system and affects other components.\n"
    "4. **Exploit Chain Evaluation**: For each potential attack chain discovered, evaluate its trigger conditions, "
    "reproduction steps, and the probability of successful exploitation.\n"
    "5. **Final Output**: The report should clearly describe the attack paths and security vulnerabilities most likely "
    "to be successfully exploited by an attacker."
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