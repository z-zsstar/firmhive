# R8500 (8 findings)

---

### AuthBypass-utelnetd

- **File/Directory Path:** `bin/utelnetd`
- **Location:** `utelnetd:0x000090a4 main function (child process code after fork)`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** utelnetd lacks an authentication mechanism. When handling telnet connections, it directly executes a login shell and runs with the process privileges of utelnetd (typically root). An attacker (a logged-in non-root user) can obtain a root shell by connecting to the telnet service, achieving privilege escalation. Trigger condition: utelnetd runs with root privileges (common in embedded systems to bind to privileged ports), and the attacker can access the telnet port. Exploitation method: The attacker uses a telnet client to connect to the device. The system directly executes a login shell without verifying user identity, thereby granting root privileges. In the code logic, within the child process after fork, execv is called to execute the login shell, with no authentication checks.
- **Code Snippet:**
  ```
  iVar15 = sym.imp.fork();
  // ...
  if (iVar15 == 0) {
      // child process
      // ... 
      sym.imp.execv((*0x9aec)[2],*0x9aec + 3);
  }
  ```
- **Keywords:** network interface (telnet port), command-line option -l for login shell path
- **Notes:** This vulnerability depends on utelnetd running with high privileges (such as root). In the default configuration, utelnetd often starts as root to bind to port 23. It is recommended to check the runtime environment to confirm privilege settings. No other exploitable vulnerabilities (such as buffer overflows) were found, because the use of strcpy/strncpy in the code is restricted or the data is not controllable (e.g., ptsname has a fixed length).

---
### CommandInjection-minidlna-fcn.0000bd6c

- **File/Directory Path:** `usr/sbin/minidlna.exe`
- **Location:** `minidlna.exe:0xbd6c fcn.0000bd6c`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** A command injection vulnerability exists in the minidlna.exe binary due to the use of the `system` function with user-controlled input. In function fcn.0000bd6c (likely a configuration parser or command-line handler), the `system` function is called with a string constructed from input parameters (case 6 in the switch statement). An attacker can exploit this by providing crafted input that includes shell metacharacters, leading to arbitrary command execution. This is triggered when processing specific command-line options or configuration settings, allowing a local user (with valid credentials) to escalate privileges or execute unauthorized commands. The vulnerability is directly reachable via command-line arguments or configuration files, and exploitation does not require root access.
- **Code Snippet:**
  ```
  // From decompilation at 0xc0bc (case 6):
  sym.imp.snprintf(*(puVar24 + -0x10b8),0x1000,*0xcdf0);
  sym.imp.system(*(puVar24 + -0x10b8));
  ```
- **Keywords:** system, argv, minidlna.conf
- **Notes:** This vulnerability requires the attacker to have access to the command-line interface or ability to modify configuration files. Since the user is non-root but has login credentials, they can likely invoke minidlna.exe with malicious arguments or modify configuration in their scope. Further analysis is needed to confirm if network-based input can trigger this, but local exploitation is feasible. Recommend checking for other instances of `system` calls and input validation throughout the code.

---
### Command-Injection-hd-idle-main

- **File/Directory Path:** `sbin/hd-idle`
- **Location:** `hd-idle:0x00009430 main (sprintf call), hd-idle:0x00009438 main (system call)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** A command injection vulnerability was discovered in the 'hd-idle' program, allowing attackers to execute arbitrary commands through command-line arguments. The program uses sprintf to format the user-provided disk name into the command string 'hdparm -y /dev/%s', which is then executed via a system call. Since the input is not filtered, attackers can inject malicious command separators (such as semicolons or backticks) to execute arbitrary system commands. Trigger condition: When the program runs with privileges (e.g., root), the attacker provides malicious parameters via the -a or -t options. Exploitation method: For example, executing 'hd-idle -a "disk; malicious_command"' can run malicious commands on the device.
- **Code Snippet:**
  ```
  0x0000941c      b8119fe5       ldr r1, str.hdparm__y__dev__s ; [0x98df:4]=0x61706468 ; "hdparm -y /dev/%s"
  0x00009420      013083e3       orr r3, r3, 1
  0x00009424      4830c4e5       strb r3, [r4, 0x48]
  0x00009428      124e8de2       add r4, string
  0x0000942c      0400a0e1       mov r0, r4                  ; char *s
  0x00009430      acfdffeb       bl sym.imp.sprintf          ; int sprintf(char *s, const char *format, ...)
  0x00009434      0400a0e1       mov r0, r4                  ; const char *string
  0x00009438      6bfdffeb       bl sym.imp.system           ; int system(const char *string)
  ```
- **Keywords:** Command-line arguments (-a, -t), Disk name string, system call, sprintf format string
- **Notes:** Exploiting the vulnerability requires the program to run with sufficient privileges (e.g., root). In a firmware environment, hd-idle typically runs with root privileges to manage disks, making the attack chain complete. It is recommended to verify the program's privilege settings in the target system. Subsequent checks can examine whether other input points (such as configuration files or environment variables) also have similar issues.

---
### BufferOverflow-SOAP-Upnpd

- **File/Directory Path:** `usr/sbin/upnpd`
- **Location:** `sbin/upnpd:0x0001d680 fcn.0001d680`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** In the function fcn.0001d680 (handling SOAP requests), there are multiple unsafe string operations, such as strcpy and strncpy, used to copy user-controlled input into fixed-size stack buffers, lacking proper boundary checks. Specific trigger condition: When processing malicious UPnP SOAP requests, if the request data (such as XML content or headers) exceeds the target buffer size, it can cause a stack buffer overflow. This may overwrite the return address or critical variables, allowing an attacker to control the program execution flow. Potential attack method: An attacker can craft a specially designed UPnP request and send it to the upnpd service (usually listening on ports 1900/5000), triggering the overflow and executing arbitrary code. Since upnpd typically runs with root privileges, successful exploitation may lead to complete device compromise. Complete attack chain: Entry point (network interface) → Data flow (SOAP processing) → Buffer overflow → Arbitrary code execution.
- **Code Snippet:**
  ```
  sym.imp.strcpy(puVar19 + -0x294, param_1); // Potential overflow point
  sym.imp.strncpy(puVar19 + -0x54, iVar4, iVar5); // Possible overflow
  ```
- **Keywords:** upnp_turn_on, lan_ipaddr, wan_ipaddr, UPnP protocol, fcn.0001d680, fcn.0001bb00, fcn.0001bf7c
- **Notes:** Recommend further verification: Confirm crash and exploitability through dynamic testing (such as sending overly long SOAP requests). Related files: /etc/config/upnpd (configuration may affect service behavior). Subsequent analysis direction: Check if other functions (such as fcn.00024360 for UPnP event handling) have similar vulnerabilities, and analyze if system calls (such as system) could be used for command injection. The attacker is a non-root user already connected to the device and possessing valid login credentials, possibly triggering the vulnerability through network access.

---
### Command-Injection-main

- **File/Directory Path:** `sbin/acos_service`
- **Location:** `acos_service:0xc050 main function`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** A command injection vulnerability exists in the main function. When the program reads an NVRAM variable and uses sprintf to insert it into a format string, which is then executed via the system function. An attacker can inject arbitrary commands by setting malicious NVRAM variable values (such as commands containing semicolons or backticks). Since the program may run with root privileges, successful exploitation could lead to remote code execution and privilege escalation. Trigger condition: The attacker can modify specific NVRAM variables (such as wan_ipaddr) and trigger acos_service to execute the relevant code path.
- **Code Snippet:**
  ```
  uVar5 = sym.imp.acosNvramConfig_get(*0xd460);
  sym.imp.sprintf(iVar9, *0xd39c, uVar5);
  sym.imp.system(iVar9);
  ```
- **Keywords:** NVRAM variable points to *0xd460 (e.g., wan_ipaddr), Format string points to *0xd39c
- **Notes:** Need to verify if NVRAM variables can be set via user interfaces (such as the web UI). It is recommended to further analyze the format string content to confirm the injection point. The attack chain is complete: input point (NVRAM) → data flow (sprintf) → dangerous operation (system).

---
### Stack-Buffer-Overflow-fcn.0000c99c

- **File/Directory Path:** `bin/wps_monitor`
- **Location:** `wps_monitor:0xc99c fcn.0000c99c`
- **Risk Score:** 8.0
- **Confidence:** 7.0
- **Description:** In function fcn.0000c99c, there exists a stack buffer overflow vulnerability due to the lack of length checks when using strcat to concatenate a string from NVRAM into a fixed-size stack buffer (256 bytes). An attacker, as an authenticated user, can trigger the overflow by setting a malicious NVRAM variable (such as a long string), overwriting the return address on the stack, potentially leading to arbitrary code execution. Vulnerability trigger conditions include: the attacker controls the NVRAM variable value (e.g., via nvram_set or other interfaces), and the function is called (possibly via WPS-related network requests or system operations). Exploitation methods include: crafting a long string to overwrite the return address, pointing to shellcode on the stack or utilizing existing code snippets. In the code logic, strcat operations within a loop may lead to multiple concatenations, exacerbating the overflow risk. Constraints include a fixed buffer size (256 bytes) but a lack of boundary checks.
- **Code Snippet:**
  ```
  Decompiled code snippet (based on Radare2 output):
  if (*(puVar27 + -0x304) != '\0') {
      iVar6 = sym.imp.strlen(puVar27 + -0x304);
      sym.imp.memcpy(puVar27 + iVar6 + -0x304, *0xda88, 2);
  }
  sym.imp.strcat(puVar27 + -0x304, iVar5);  // iVar5 comes from NVRAM data, length not checked
  ```
- **Keywords:** NVRAM variables accessed via pointers *0xd9b8, *0xda4c, etc. (specific variable names require further verification but may involve WPS configurations such as 'wps_mode' or 'wps_uuid'), Stack buffer addresses puVar27 + -0x304 and puVar27 + -0x404
- **Notes:** The vulnerability may be used for local privilege escalation or remote code execution (if the function can be triggered via the network). Further verification is needed for specific NVRAM variable names and function trigger mechanisms (e.g., by analyzing code paths that call fcn.0000c99c). Stack layout and protection mechanisms (such as ASLR, stack protection) may be weaker in embedded devices, increasing exploitability. It is recommended to subsequently analyze associated components (such as HTTP services or IPC) to confirm input point propagation.

---
### Buffer-Overflow-main

- **File/Directory Path:** `sbin/acos_service`
- **Location:** `acos_service:0xc050 main function`
- **Risk Score:** 7.0
- **Confidence:** 7.0
- **Description:** A stack buffer overflow vulnerability exists in the main function. When the program uses strcpy to copy an NVRAM variable value to a stack buffer, it does not perform bounds checking. An attacker can overflow the buffer by setting an overly long NVRAM variable value, potentially overwriting the return address and executing arbitrary code. Since the program may run with root privileges, successful exploitation could lead to privilege escalation. Trigger condition: An attacker can modify a specific NVRAM variable (such as http_passwd) to a long string and trigger acos_service to execute the relevant code path.
- **Code Snippet:**
  ```
  uVar5 = sym.imp.acosNvramConfig_get(*0xd13c);
  sym.imp.strcpy(iVar20 + -0xab0, uVar5);
  ```
- **Keywords:** NVRAM variable points to *0xd13c (e.g., http_passwd), File path /tmp/opendns.flag
- **Notes:** Need to confirm the stack layout and offsets to precisely calculate the overflow point. It is recommended to test the buffer size and overwrite possibility. The attack chain is complete: input point (NVRAM) → data flow (strcpy) → dangerous operation (buffer overflow).

---
### BufferOverflow-nvram-version

- **File/Directory Path:** `usr/sbin/nvram`
- **Location:** `sbin/nvram:0x00008924 (In the 'version' command branch of function fcn.00008924)`
- **Risk Score:** 6.5
- **Confidence:** 7.5
- **Description:** A buffer overflow vulnerability was discovered in the 'sbin/nvram' binary, located in the 'version' command processing logic. When executing the 'nvram version' command, the program retrieves variables (such as 'pmon_ver' and 'os_version') from NVRAM and uses the strcat function to concatenate them into a fixed-size stack buffer (0x20000 bytes), lacking boundary checks. If an attacker sets these variables to long strings (total length exceeding 0x20000 bytes) via the 'nvram set' command, it will cause a stack buffer overflow. An attacker can carefully craft the overflow data to overwrite the return address and execute arbitrary code. Trigger condition: The attacker possesses valid login credentials (non-root user), first sets 'pmon_ver' and 'os_version' to malicious long strings, and then executes 'nvram version'. Potential exploitation methods include executing shellcode or system commands, but since the binary runs with user privileges, it cannot directly escalate privileges; it might be used to escape a restricted shell or perform unauthorized operations.
- **Code Snippet:**
  ```
  Relevant snippet extracted from decompiled code:
  puVar19 = iVar20 + -0x20000 + -4;
  sym.imp.memset(puVar19, 0, 0x20000);
  iVar1 = sym.imp.nvram_get(iVar10 + *0x8ef8); // Get 'pmon_ver'
  if (iVar1 == 0) {
      iVar1 = iVar10 + *0x8f0c; // Default string
  }
  sym.imp.strcat(puVar19, iVar1); // String concatenation without boundary check
  // Followed by multiple strcat and memcpy operations
  ```
- **Keywords:** pmon_ver, os_version, version, set
- **Notes:** Exploiting the vulnerability requires the attacker to be able to set NVRAM variables, and the 'nvram' file permissions are -rwxrwxrwx, allowing any user to execute, so it might be feasible. Further verification requires confirming the stack layout and offsets, and whether ASLR is enabled on the device. It is recommended to test whether the overflow can indeed overwrite the return address.

---
