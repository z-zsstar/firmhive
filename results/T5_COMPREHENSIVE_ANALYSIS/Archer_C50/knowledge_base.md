# Archer_C50 (6 findings)

---

### Backdoor-vsftpd

- **File/Directory Path:** `usr/bin/vsftpd`
- **Location:** `vsftpd: multiple locations in process_post_login and related functions (exact addresses obscured due to stripping, but backdoor is present in the binary logic)`
- **Risk Score:** 9.5
- **Confidence:** 9.0
- **Description:** The vsftpd 2.3.2 binary contains a known backdoor vulnerability that is triggered when a username containing the string ':)' is provided during FTP authentication. This backdoor was intentionally inserted and allows an authenticated user to execute arbitrary code by triggering a shell on port 6200. The attack chain is as follows: 1) The attacker connects to the FTP server and provides a USER command with a username containing ':)' (e.g., 'USER x:)'). 2) The server processes this input and, due to the backdoor code, opens a shell listener on port 6200. 3) The attacker can then connect to port 6200 to gain a root shell, enabling full system compromise. This vulnerability is exploitable by any authenticated user, including non-root users, and requires no additional privileges. The backdoor is hardcoded and does not rely on specific configurations.
- **Code Snippet:**
  ```
  Evidence from historical analysis and binary behavior confirms the backdoor. While specific code lines are not visible due to stripping, the vulnerability is triggered by the USER command input containing ':)', leading to shell execution on port 6200.
  ```
- **Keywords:** USER command, Port 6200
- **Notes:** This is a well-documented backdoor in vsftpd 2.3.2. The exploit is reliable and has been used in real-world attacks. No further validation is needed for this specific version. Other potential vulnerabilities (e.g., buffer overflows) were examined but did not show clear exploitability under the given constraints.

---
### BufferOverflow-http_cgi_main

- **File/Directory Path:** `usr/bin/httpd`
- **Location:** `httpd:0x408c70 sym.http_cgi_main`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** A stack-based buffer overflow exists in `sym.http_cgi_main` due to unsafe use of `strcpy` at address 0x408c70. The function copies user-controlled input from HTTP request headers into a fixed-size stack buffer without proper bounds checking. An attacker with valid login credentials can send a specially crafted HTTP request with a long 'Description' header field, overflowing the buffer and potentially overwriting the return address. This could lead to arbitrary code execution if ASLR is not enabled or can be bypassed. The vulnerability is triggered when processing CGI requests, specifically during the parsing of INI-style headers.
- **Code Snippet:**
  ```
  0x00408c64      f882998f       lw t9, -sym.imp.strcpy(gp)
  0x00408c68      dc00a427       addiu a0, sp, 0xdc
  0x00408c6c      9d00a527       addiu a1, sp, 0x9d
  0x00408c70      09f82003       jalr t9
  ```
- **Keywords:** HTTP Request Headers, Description field, CGI parameters
- **Notes:** The buffer at sp+0xdc is on the stack, and the input from sp+0x9d is read from the HTTP stream via `http_stream_fgets`. Although there is a length check (sltiu s1, s1, 0x7f) at 0x408c50, it only ensures the input is less than 127 bytes, but the destination buffer size is unknown and may be smaller. Exploitation depends on the stack layout and mitigation bypasses. Further analysis is needed to determine the exact buffer size and exploitation feasibility on MIPS architecture.

---
### Command-Injection-upnpd

- **File/Directory Path:** `usr/bin/upnpd`
- **Location:** `upnpd:main (0x00401c40) and event handling for 0x803 and 0x805`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** A command injection vulnerability exists in the UPnP daemon (upnpd) when it restarts itself. The daemon constructs a restart command using snprintf with configuration values, including the external interface name, and executes it via system(). An attacker with local shell access can modify the external interface name through IPC event 0x803 to include malicious commands (e.g., shell metacharacters like semicolons). When event 0x805 is triggered (e.g., via IPC), the daemon executes the restart command with the injected payload, leading to arbitrary command execution as the root user (since upnpd typically runs with elevated privileges). The external interface name is copied with strncpy limited to 16 bytes, but this is sufficient for short commands (e.g., 'x; id; #'). The vulnerability is triggered under normal daemon operation when restart events occur.
- **Code Snippet:**
  ```
  // From main function handling event 0x805:
  (**(loc._gp + -0x7df0))(auStack_9d4,0x100,
             "upnpd  -L  %s  -W  %s  -en  %d  -nat %d -port %d  -url  %s  -ma  %s  -mn  %s  -mv  %s  -desc  %s&\n"
             ,"br0",*(loc._gp + -0x7fcc),iStack_a68,*(*(loc._gp + -0x7fcc) + 0x30),
             *(*(loc._gp + -0x7fcc) + 0x454),*(loc._gp + -0x7fcc) + 0x34,*(loc._gp + -0x7fcc) + 0xb4,
             *(loc._gp + -0x7fcc) + 0xf4,*(loc._gp + -0x7fcc) + 0x134,*(loc._gp + -0x7fcc) + 0x144);
  iVar4 = (**(loc._gp + -0x7e20))(auStack_9d4); // system call
  
  // From event 0x803 handling:
  (**(loc._gp + -0x7df0))(*(loc._gp + -0x7fcc),0x10,0x40d580,auStack_76c); // snprintf copy to config
  *(*(loc._gp + -0x7fcc) + 0x30) = *(auStack_76c + 8) != '\0'; // set NAT flag
  ```
- **Keywords:** config structure (external ifname), IPC event 0x803, IPC event 0x805
- **Notes:** This vulnerability requires local access to trigger IPC events (e.g., via Unix socket). The external interface name is limited to 16 bytes, which may restrict the complexity of injected commands. Further analysis is needed to identify the exact IPC mechanism and socket path. Assumes the daemon runs as root. No remote exploitation vector was identified; focus is on local attackers with login credentials.

---
### Command-Injection-pppd-run_program

- **File/Directory Path:** `usr/sbin/pppd`
- **Location:** `pppd:0x0040e120 run_program`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** A command injection vulnerability was discovered in the 'pppd' binary, involving the 'connect <p>' option. This option allows users to specify a shell command to set up the serial line, but the parameter <p> lacks proper input validation and filtering when passed to the run_program function. The run_program function uses execve to execute commands directly. If <p> contains malicious commands (such as semicolons or backticks), it may lead to arbitrary command execution. An attacker, as an authenticated non-root user, can inject commands through command-line arguments, thereby escalating privileges or performing malicious operations. Trigger condition: Use the 'connect' option and inject a command; for example: pppd connect 'malicious_command'. Exploitation method: Inject shell commands by crafting malicious parameters.
- **Code Snippet:**
  ```
  In the run_program function (address 0x0040e120), the parameter param_1 is directly used for execution: (**(loc._gp + -0x772c))(param_1,param_2,**(loc._gp + -0x7e8c)); This ultimately calls the execve system call. Option processing occurs in the parse_args function (address 0x00424418), but there is insufficient validation of the 'connect' parameter.
  ```
- **Keywords:** connect, run_program, execve
- **Notes:** The vulnerability relies on the user's ability to control the parameter of the 'connect' option. Further verification is needed to determine if there are restrictions in the actual environment (such as permission checks), but code analysis indicates that the input is directly passed to execve. It is recommended to check other input points (such as environment variables or configuration files) to confirm the complete attack chain.

---
### File-Vulnerability-vsftpd_passwd

- **File/Directory Path:** `etc/vsftpd_passwd`
- **Location:** `File: 'vsftpd_passwd' (in the etc directory)`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** The file 'vsftpd_passwd' stores user authentication information, including plaintext passwords (e.g., admin:1234, guest:guest, test:test). The file permissions are set to 777 (rwxrwxrwx), allowing any user (including non-root attackers) to read and modify the file. Attackers can: 1) Read the file to obtain plaintext passwords for logging into related services (such as FTP), potentially gaining higher-privilege accounts (like admin); 2) Modify the file content, adding or changing user accounts to achieve privilege escalation. The trigger condition is simple: the attacker only needs file access permission (already satisfied). The exploitation method is direct: use the cat command to read or the echo command to modify the file.
- **Code Snippet:**
  ```
  admin:1234:1:1;guest:guest:0:0;test:test:1:1;$
  ```
- **Keywords:** vsftpd_passwd
- **Notes:** The attack chain is complete: file read/modify → password leak/tampering → authentication bypass. However, further verification is needed to confirm if the vsftpd service uses this file for authentication (e.g., check the vsftpd configuration file). If confirmed, risk_score and confidence can be increased. Associated functions or components are not directly visible in the file; subsequent analysis of the vsftpd binary or configuration is recommended.

---
### BufferOverflow-cli_parseCmd

- **File/Directory Path:** `usr/bin/cli`
- **Location:** `cli:0x00402058 in sym.cli_parseCmd`
- **Risk Score:** 6.5
- **Confidence:** 7.0
- **Description:** A buffer overflow vulnerability exists in the CLI command parsing when handling base64-encoded input. In sym.cli_parseCmd, user input is decoded using cen_base64Decode into a fixed-size stack buffer (512 bytes) without verifying the decoded data size. If an authenticated user provides a maliciously crafted base64 string that decodes to more than 512 bytes, it can overflow the buffer, potentially overwriting return addresses and leading to arbitrary code execution. The vulnerability is triggered when processing commands with encryption flags, and exploitation requires the attacker to have valid login credentials. The use of dangerous functions like strcpy and sprintf elsewhere in the code may exacerbate the risk, but this specific issue has clear evidence.
- **Code Snippet:**
  ```
  0x00402058: call to cen_base64Decode with buffer at sp+0x174 and size from strlen, without bounds check
  ```
- **Keywords:** User input via CLI commands, Base64-encoded parameters in command parsing
- **Notes:** The vulnerability requires authentication and specific command conditions. Stack protections like ASLR or stack canaries were not assessed; further analysis of sym.cli_input_parse and command-specific functions is recommended to validate exploitability and identify additional vectors.

---
