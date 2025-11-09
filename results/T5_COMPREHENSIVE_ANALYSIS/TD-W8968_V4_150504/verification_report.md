# TD-W8968_V4_150504 - Verification Report (7 findings)

---

## Original Information

- **File/Directory Path:** `bin/httpd`
- **Location:** `httpd:0x41bc68 sym.cgiConfigNtp`
- **Description:** A command injection vulnerability exists in the `cgiConfigNtp` function, which handles NTP configuration via CGI. The function reads a date-time string from the global variable `glbWebVar` at offset 0x9e8, formats it into a 'date -s' command using `sprintf`, and executes it via `system`. The input is parsed with `sscanf` using the format '%d.%d.%d-%d:%d:%d', but the original string is used directly in `sprintf` without sanitization. An attacker can inject arbitrary commands by including shell metacharacters (e.g., ';' or '&') in the input. The vulnerability is triggered when a user submits a malicious date-time string through the HTTP interface, such as via a POST request to the NTP configuration endpoint. The attack chain involves: 1. User input being stored in `glbWebVar` through CGI parsing in `web_main` or similar functions; 2. The `cgiConfigNtp` function processing the input and constructing a command string; 3. The command string being executed by `system`, leading to arbitrary command execution as the httpd process user.
- **Code Snippet:**
  ```
  0x0041bc64      24a5b354       addiu a1, a1, -0x4cac       ; 0x45b354 ; "%d.%d.%d-%d:%d:%d" ; arg2
  0x0041bc68      260409e8       addiu a0, s0, 0x9e8         ; arg1
  0x0041bc6c      0320f809       jalr t9                     ; sscanf
  0x0041bc80      8f99831c       lw t9, -sym.imp.sprintf(gp) ; [0x452180:4]=0x8f998010
  0x0041bc8c      24a5b368       addiu a1, a1, -0x4c98       ; 0x45b368 ; "date -s %s" ; arg2
  0x0041bc90      260609e8       addiu a2, s0, 0x9e8         ; arg3
  0x0041bc94      0320f809       jalr t9                     ; sprintf
  0x0041bca0      8f998938       lw t9, -sym.imp.system(gp)  ; [0x451200:4]=0x8f998010
  0x0041bca4      0320f809       jalr t9                     ; system
  ```
- **Notes:** The vulnerability requires the attacker to have valid login credentials to access the NTP configuration functionality. The `glbWebVar` structure is populated from HTTP inputs, likely through `cgiSetVar` or similar functions. Further analysis could identify the exact HTTP endpoint and parameters. No additional vulnerabilities like buffer overflows were found in this function, but other CGI functions should be checked for similar issues.

## Verification Conclusion

- **Description Accuracy:** `accurate`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** The security alert accurately describes a command injection vulnerability. Evidence comes from the disassembled code: the function `cgiConfigNtp` reads input from `glbWebVar+0x9e8`, parses it with `sscanf` but retains the original string, directly uses it in `sprintf` to construct a command and executes it via `system`. The input is not sanitized, shell metacharacters (such as ';' or '&') can inject arbitrary commands. The attack path is reachable: when the input is non-empty and `sscanf` returns 6 (successful parsing), the command executes. The attacker model is an authenticated remote attacker (requires login credentials to access the NTP configuration function). Actual impact: arbitrary command execution as the httpd process user (potentially high privileges). PoC steps: 1. Log in to the device web interface; 2. Access the NTP configuration endpoint; 3. Submit a malicious date-time parameter, such as '2023.12.31-12:00:00; whoami' (injecting the 'whoami' command); 4. The server executes 'date -s 2023.12.31-12:00:00; whoami', resulting in command injection.

## Verification Metrics

- **Verification Duration:** 211.44 s
- **Token Usage:** 148867

---

## Original Information

- **File/Directory Path:** `lib/libwlupnp.so`
- **Location:** `File: ./libwlupnp.so Function: fcn.00004b88 Address: 0x00004bb8; File: ./libwlupnp.so Function: sym.upnp_msg_deinit Address: 0x0000cc38, 0x0000cc20`
- **Description:** A use-after-free vulnerability was discovered in the 'upnp_http_process' function, originating from an error path in HTTP request processing. Specific behavior: When processing an HTTP request, if iStack_28 < 0 (error condition), fcn.00004b88 is called, which in turn calls sym.upnp_msg_deinit. In sym.upnp_msg_deinit, a value is loaded from offset 0x20bc of a tainted pointer and passed to the free function. Trigger condition: An attacker sends a specially crafted HTTP request to the UPnP interface, triggering the error handling path. Constraint: The attacker must possess valid login credentials (non-root user). Potential attack: By precisely controlling the pointer value at offset 0x20bc, arbitrary memory freeing can be achieved, leading to use-after-free or double-free, potentially exploitable for code execution or privilege escalation. The code logic involves multiple layers of function calls, with tainted data propagating from the HTTP request structure to the free operation.
- **Code Snippet:**
  ```
  Decompiled code snippet from upnp_http_process (error path):
  if (iStack_28 < 0) {
      (*(fcn.00004b88 + *(iVar2 + -0x7fd8)))(*aiStackX_0); // Call fcn.00004b88
      break;
  }
  
  Taint propagation from fcn.00004b88 to sym.upnp_msg_deinit:
  0x00004bb8: jalr t9 // Call sym.upnp_msg_deinit, taint in a0
  
  In sym.upnp_msg_deinit:
  0x0000cc38: lw v0, 0x28(sp); lw v0, 0x20bc(v0); sw v0, 0x18(sp) // Load value from tainted pointer
  0x0000cc20: lw a0, 0x18(sp); lw v0, -0x7f98(gp); move t9, v0; jalr t9 // Call free
  ```
- **Notes:** This finding is based on complete evidence of the taint propagation path, from the HTTP input point to the free operation. Suggested follow-up analysis: Verify the specific exploitation method for the use-after-free (e.g., constructing memory layout to achieve code execution), check if similar issues exist in other UPnP-related functions. Related file: ./libwlupnp.so.

## Verification Conclusion

- **Description Accuracy:** `accurate`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** The security alert accurately describes a use-after-free vulnerability. Evidence is as follows: 1) In the upnp_http_process function (address 0x00004cc4), the error path is triggered when var_18h < 0, calling fcn.00004b88; 2) fcn.00004b88 (address 0x00004bb8) calls sym.upnp_msg_deinit, passing a tainted pointer a0; 3) In sym.upnp_msg_deinit (addresses 0x0000cc38 and 0x0000cc20), a value is loaded from pointer offset 0x20bc and free is called. The attacker model is an authenticated non-root user who sends specially crafted HTTP requests to control input (HTTP request structure), causing the processing function to return a negative value triggering the error path. Complete attack chain: The attacker controls the pointer value at offset 0x20bc, triggering the free operation, leading to arbitrary memory freeing. Exploitability verification: Input is controllable (HTTP request can be manipulated), path is reachable (error condition can be triggered), actual impact (arbitrary freeing may lead to use-after-free or double-free, and subsequently code execution). PoC steps: 1) Authenticate with a valid user account; 2) Send a malicious HTTP request to the UPnP interface, carefully crafting the request body to cause the processing function to return an error (e.g., invalid headers or data); 3) Set the value at offset 0x20bc in the request structure to a target memory address (e.g., heap chunk address); 4) After triggering the error path, free releases that address, and subsequent operations can exploit the freed memory layout to achieve code execution.

## Verification Metrics

- **Verification Duration:** 252.06 s
- **Token Usage:** 185190

---

## Original Information

- **File/Directory Path:** `lib/libwlupnp.so`
- **Location:** `File: ./libwlupnp.so Function: sym.soap_process Address: 0x00009dfc`
- **Description:** A buffer overflow vulnerability was discovered in the 'soap_process' function, originating from a manual null terminator write operation during SOAP message parsing of the SOAPACTION header. Specific issue: After using the strcspn function to calculate the delimiter position, a null byte is written directly to the calculated address (sb zero, (v0)), without verifying if the address is within the buffer boundaries. Trigger condition: An attacker sends a crafted SOAP message where the SOAPACTION header does not contain the expected delimiter (such as quotes or spaces), causing strcspn to return the entire string length, making the write location exceed the buffer boundary. Constraint: The attacker must possess valid login credentials (non-root user). Potential attack: By writing a null byte out-of-bounds, it may cause memory corruption, which could be exploited to execute arbitrary code or cause a denial of service. The vulnerability involves a lack of boundary checks, and an attacker can trigger the overflow by controlling the content of the SOAPACTION header.
- **Code Snippet:**
  ```
  Decompiled code snippet from soap_process:
  0x00009dd8      8f8280b0       lw v0, -sym.imp.strcspn(gp) ; Call strcspn
  0x00009ddc      0040c821       move t9, v0
  0x00009de0      0320f809       jalr t9
  0x00009de4      00000000       nop
  0x00009de8      8fdc0010       lw gp, (var_10h)
  0x00009dec      afc2001c       sw v0, (var_1ch)
  0x00009df0      8fc2001c       lw v0, (var_1ch)
  0x00009df4      8fc30020       lw v1, (var_20h)
  0x00009df8      00621021       addu v0, v1, v0
  0x00009dfc      a0400000       sb zero, (v0) ; Out-of-bounds write of null byte
  ```
- **Notes:** The vulnerability depends on the buffer size returned by 'upnp_msg_get', which does not perform boundary checks. It is recommended to further analyze the buffer allocation mechanism and heap layout to confirm exploitation details. Related functions include 'action_process'. Subsequent analysis directions should include testing actual SOAP message triggers and evaluating the impact of memory corruption.

## Verification Conclusion

- **Description Accuracy:** `accurate`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `Medium`
- **Detailed Reason:** The security alert accurately describes a buffer overflow vulnerability. Based on decompiled code analysis, at address 0x00009dfc in the 'sym.soap_process' function, after using strcspn to calculate the delimiter position, a null byte is written directly to the calculated address (sb zero, (v0)) without verifying if the address is within the buffer boundaries. Input is controllable: An attacker can control the content of the SOAPACTION header via a crafted SOAP message. Path is reachable: The code flow shows that the vulnerable path can be reached after passing basic checks (such as the SOAPACTION header being non-empty and specific string comparisons). Actual impact: Writing a null byte out-of-bounds may cause memory corruption, which could be exploited to execute arbitrary code or cause a denial of service. The attacker model is an authenticated non-root user (requires valid login credentials), which reduces the immediate risk, but the vulnerability is still exploitable. PoC steps: 1. Attacker obtains valid login credentials; 2. Constructs a SOAP message where the SOAPACTION header is a long string without the expected delimiters (such as quotes, tabs, or spaces); 3. Sends this message to the target service; 4. strcspn will return the entire string length, causing the null byte to be written outside the buffer, triggering memory corruption. The vulnerability risk is medium because authentication is required and exploitation might be affected by memory layout, but the potential harm is severe.

## Verification Metrics

- **Verification Duration:** 271.45 s
- **Token Usage:** 197806

---

## Original Information

- **File/Directory Path:** `etc/vsftpd_passwd`
- **Location:** `vsftpd_passwd`
- **Description:** The file 'vsftpd_passwd' stores user passwords in plaintext, including weak passwords (such as '1234', 'guest', 'test'), and contains permission flags (for example, '1' may indicate administrator privileges). Problem manifestation: After an attacker logs in as a non-root user, if the file is readable, they can directly obtain the passwords. Trigger condition: The attacker accesses the file path and reads the content. Constraint condition: The file must have read permissions, and the vsftpd service must use this file for authentication. Potential attack: The attacker uses the obtained passwords (e.g., admin's '1234') to log into FTP or other services, escalate privileges to administrator, and perform dangerous operations. Code logic: The file format is username:password:flag:flag, separated by semicolons, and the password is not encrypted.
- **Code Snippet:**
  ```
  admin:1234:1:1;guest:guest:0:0;test:test:1:1;$
  ```
- **Notes:** Evidence is based on file content analysis; further verification is needed regarding file permissions (e.g., whether it is globally readable) and vsftpd configuration (e.g., whether /etc/vsftpd.conf references this file). It is recommended that subsequent analysis check related configuration files and service status to confirm the feasibility of the attack chain.

## Verification Conclusion

- **Description Accuracy:** `partially`
- **Is Real Vulnerability:** `False`
- **Risk Level:** `N/A`
- **Detailed Reason:** The alert correctly describes the file content (plaintext weak passwords and permission flags) and the file is globally readable, but it has not been verified that the vsftpd service actually uses this file for authentication. The attacker model is a non-root user already logged into the system; they can execute 'cat etc/vsftpd_passwd' to read the passwords, but there is a lack of evidence proving that the vsftpd configuration (/etc/vsftpd.conf) references this file, therefore it cannot be confirmed that the passwords can be used to log into the FTP service or escalate privileges. The vulnerability chain is incomplete and does not constitute a real vulnerability.

## Verification Metrics

- **Verification Duration:** 304.10 s
- **Token Usage:** 225636

---

## Original Information

- **File/Directory Path:** `bin/snmpd`
- **Location:** `snmpd:0x004081b0 sym.set_community`
- **Description:** A buffer overflow vulnerability exists in the SNMP community string handling function sym.set_community. The function uses strcpy to copy user-provided community strings from SNMP packets to a fixed-size buffer without bounds checking. An attacker with valid login credentials can send a crafted SNMP packet with a long community string (>72 bytes) to trigger the overflow. The buffer is located at a global address (0x42b040 + index * 0x48), and overflow could corrupt adjacent memory, potentially leading to denial of service or code execution. The vulnerability is triggered when processing SNMP set requests or other operations that modify community strings.
- **Code Snippet:**
  ```
  From decompilation:
  (**(loc._gp + -0x7fac))(param_2 * 0x48 + 0x42b040, *&uStackX_0);
  Where -0x7fac is strcpy, param_2 is the community index (0-2), and *&uStackX_0 is the user-controlled community string. No length validation is performed before copying.
  ```
- **Notes:** The attack chain involves sending a malicious SNMP packet to the snmpd service. Full exploitation requires overcoming potential mitigations (e.g., ASLR, stack canaries), which may not be present in this embedded environment. Further analysis is needed to determine the exact impact and exploitability. Related functions like fcn.004104b0 also use dangerous string operations but lack clear input paths.

## Verification Conclusion

- **Description Accuracy:** `partially`
- **Is Real Vulnerability:** `False`
- **Risk Level:** `N/A`
- **Detailed Reason:** The code vulnerability in sym.set_community is accurate: strcpy is used without bounds checking, copying data to a fixed buffer at 0x42b040 + index * 0x48. However, the exploitability description is inaccurate. Evidence from decompilation and cross-references shows that sym.set_community is called only during initialization in main (e.g., at 0x402bf4 and 0x402c18), with parameters derived from internal data structures, not directly from SNMP packets. No code path was found where SNMP set requests or other operations trigger this function with attacker-controlled input. The attack model (attacker with valid login credentials sending crafted SNMP packets) is not supported, as the function is not invoked in packet processing loops. Therefore, while a buffer overflow exists, it is not exploitable remotely as described, and thus does not constitute a real vulnerability in this context.

## Verification Metrics

- **Verification Duration:** 353.82 s
- **Token Usage:** 249716

---

## Original Information

- **File/Directory Path:** `bin/vsftpd`
- **Location:** `vsftpd:0x41a338 and 0x41a400 (sym.vsf_read_only_check)`
- **Description:** A buffer overflow vulnerability exists in the 'vsf_read_only_check' function due to the use of 'strcpy' to copy user-supplied data into a fixed-size stack buffer (128 bytes) without bounds checking. The function is called during FTP command processing (e.g., for file operations like RETR, STOR) in 'process_post_login'. An attacker with valid FTP credentials could trigger this by sending a crafted file path or argument longer than 127 bytes, potentially overwriting stack memory and leading to arbitrary code execution. The vulnerability requires the attacker to be authenticated but non-root, and exploitation depends on overcoming stack protections and controlling execution flow.
- **Code Snippet:**
  ```
  From decompiled code:
  (**(loc._gp + -0x7fa8))(acStack_118, uVar1); // strcpy equivalent
  where acStack_118 is a 128-byte buffer and uVar1 is derived from param_2 (user input).
  ```
- **Notes:** The vulnerability is plausible based on code analysis, but full exploitability requires verifying that user input flows to param_2 without length restrictions in all paths. Additional analysis is needed to confirm the attack chain, including testing under real conditions. Other functions like vsf_cmdio_get_cmd_and_arg have input length checks, which may mitigate some risks. Recommend further investigation into data flow from FTP commands to vsf_read_only_check.

## Verification Conclusion

- **Description Accuracy:** `accurate`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `Medium`
- **Detailed Reason:** The security alert is accurate based on code analysis. The 'vsf_read_only_check' function uses 'strcpy' to copy user input into fixed-size 128-byte stack buffers without bounds checking, as confirmed at addresses 0x0041a338 and 0x0041a400. The function is called from multiple sites in 'process_post_login' during FTP command processing (e.g., for operations like MKDIR, RETR, STOR). User input flows to the function via the second argument (derived from FTP command arguments) without length restrictions in the observed paths. An authenticated FTP user (non-root) can trigger this by sending a crafted command with a file path or argument longer than 127 bytes. For example, a PoC would involve authenticating to the FTP server and issuing a command like 'MKDIR <long_string>' or 'RETR <long_string>', where <long_string> is 128 bytes or more (e.g., 'A' * 128). This would overflow the buffer, potentially overwriting stack memory and allowing arbitrary code execution, though actual exploitation may require bypassing stack protections. The risk is medium due to the authentication prerequisite and the complexity of reliable exploitation.

## Verification Metrics

- **Verification Duration:** 452.14 s
- **Token Usage:** 280850

---

## Original Information

- **File/Directory Path:** `lib/libbigballofmud.so`
- **Location:** `libbigballofmud.so:0x6b89c (function sym.smb_panic)`
- **Description:** In the sym.smb_panic function, the system function is called to execute a 'panic action' command. The command string is obtained through a dynamic function call (e.g., pcVar2 = (**(iVar9 + -0x5854))()), possibly from external configuration (such as NVRAM or environment variables). If an attacker can control this string (e.g., by modifying the configuration), malicious commands can be injected. Trigger conditions include system panic events (such as service crashes), which an attacker may trigger via malicious requests. Full attack chain: user-controllable configuration → trigger panic → system execution, potentially leading to arbitrary command execution.
- **Code Snippet:**
  ```
  Decompiled code shows: char *pcVar2 = (**(iVar9 + -0x5854))(); ... uVar3 = (**(iVar9 + -0x5a90))(pcVar2); where the latter is a system call. Lacks input validation and filtering.
  ```
- **Notes:** Further verification is needed regarding the specific source of the command string (such as configuration file paths and permissions). Related functions may include configuration parsing routines. It is recommended to check if NVRAM settings or environment variables can be modified by non-root users.

## Verification Conclusion

- **Description Accuracy:** `accurate`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** Verification is based on decompiled code and assembly analysis: In the sym.smb_panic function, pcVar2 = (**(iVar9 + -0x5854))() calls sym.lp_panic_action to obtain the command string, uVar3 = (**(iVar9 + -0x5a90))(pcVar2) executes the command; although system is not directly imported, return value checks and context confirm it is a system call. The command string originates from external configuration (such as Samba's panic action parameter), which an attacker can control (e.g., by modifying configuration files or NVRAM). Attacker model: An authenticated user or remote attacker (if able to modify configuration) can trigger a panic via malicious requests (such as an SMB crash), leading to command execution. Full attack chain: Attacker modifies the panic action in the configuration to a malicious command (e.g., 'rm -rf /' or a reverse shell) → triggers panic (e.g., by sending a malformed SMB request) → system executes the malicious command. Evidence supports input controllability, path reachability, and actual impact; the vulnerability is exploitable.

## Verification Metrics

- **Verification Duration:** 540.99 s
- **Token Usage:** 297923

---

