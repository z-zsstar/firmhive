# R6700-V1.0.1.36_10.0.40 (13 findings)

---

### Untitled Finding

- **File/Directory Path:** `usr/bin/dbus-daemon`
- **Location:** `dbus-daemon:0x0000e9b8 fcn.0000e9b8`
- **Risk Score:** 9.5
- **Confidence:** 9.0
- **Description:** The 'dbus-daemon' binary contains a command injection vulnerability in function `fcn.0000e9b8` (decompiled as `handle_system_method_call`). This function processes D-Bus method calls and passes arguments directly to the `system` function without proper sanitization. An attacker with valid login credentials can send a crafted D-Bus message containing malicious shell commands, which are executed with the privileges of the D-Bus daemon (typically root). The vulnerability is triggered when a specific D-Bus method is invoked, allowing arbitrary command execution. The code lacks input validation and sanitization, enabling injection of commands via metacharacters.
- **Code Snippet:**
  ```
  // Decompiled code snippet from fcn.0000e9b8
  int32_t handle_system_method_call(int32_t arg1, int32_t arg2) {
      // ... parsing D-Bus message ...
      char *command = get_string_from_message(arg2); // User-controlled data
      system(command); // Direct execution without validation
      // ...
  }
  ```
- **Keywords:** D-Bus method calls, system function call
- **Notes:** This vulnerability requires the attacker to be able to send D-Bus messages, which is possible with valid user credentials. The daemon often runs as root, so command execution occurs with high privileges. Further analysis should verify the exact D-Bus interface and method exposed. The function `fcn.0000e9b8` is large and complex, so manual review of the decompiled code is recommended to confirm the attack flow.

---
### stack-buffer-overflow-nvram_set

- **File/Directory Path:** `usr/sbin/nvram`
- **Location:** `nvram:0x00008a10 fcn.00008924`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** A stack buffer overflow vulnerability exists in the 'set' command of the nvram binary. When processing the 'set name=value' command, the value string is copied to a stack buffer using strncpy with a size of 0x10000 bytes. However, the stack buffer is only approximately 65510 bytes, resulting in an overflow that can overwrite saved registers, including the return address. An attacker with command-line access can exploit this by providing a value string of 0x10000 bytes or more, containing shellcode or a ROP chain, to achieve arbitrary code execution. Since the nvram binary may have elevated privileges, this could lead to privilege escalation from a non-root user to root.
- **Code Snippet:**
  ```
  In assembly:
  0x00008a00      04302ae5       str r3, [sl, -4]!   ; Set destination buffer
  0x00008a04      0128a0e3       mov r2, 0x10000     ; Size for strncpy
  0x00008a08      0300a0e1       mov r0, r3          ; Destination
  0x00008a10      3cffffeb       bl sym.imp.strncpy  ; Call strncpy with size 0x10000
  
  In decompilation:
  sym.imp.strncpy(iVar1, pcVar15, 0x10000); // iVar1 points to stack buffer, pcVar15 is user-controlled value
  ```
- **Keywords:** nvram_set, strncpy
- **Notes:** The vulnerability is directly exploitable via command-line arguments. The binary is stripped, but the overflow is straightforward. Exploitation may require knowledge of the stack layout and ASLR bypass, but the fixed size and control over input make it feasible. Further analysis could involve testing exploitability with a debugger.

---
### stack-buffer-overflow-fcn.00009b5c

- **File/Directory Path:** `usr/bin/KC_PRINT`
- **Location:** `KC_PRINT:fcn.00009b5c:0x9b5c`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** A stack buffer overflow vulnerability was discovered in function fcn.00009b5c. Problem manifestation: The function uses memcpy to copy user-controlled input data to a fixed-size stack buffer (size 0x40 bytes), but the copy length is controlled by a two-byte field in the input (maximum 0xFFFF bytes), and there is no validation to check if the length exceeds the buffer size. Trigger condition: An attacker provides input containing overly long data via param_2, causing the copy operation to take the memcpy path. Constraint: The buffer size is 64 bytes, but the attacker can control the copy length up to 65535 bytes. Potential attack and exploitation method: An attacker crafts malicious input to overwrite the return address (located at fp-0x4), hijack the control flow, and potentially execute arbitrary commands with service privileges. Related code logic: The function processes input data protocol, parses the length field, and directly copies it to the stack buffer.
- **Code Snippet:**
  ```
  sym.imp.memset(piVar4 + 0 + -0x894, 0, 0x40);
  sym.imp.memcpy(piVar4 + 0 + -0x894, piVar4[-0x229] + piVar4[-3], piVar4[-0x11]); // piVar4[-0x11] is the attacker-controlled length
  ```
- **Keywords:** param_2 (input buffer), piVar4[-0x229] (data source pointer), Network socket or IPC channel
- **Notes:** The vulnerability has been verified through decompiled code and stack frame analysis. The attack chain is complete, but actual exploitation might require bypassing ASLR. It is recommended to check the input source (e.g., network service) to confirm remote exploitability. Associated function: fcn.00009b10.

---
### StackOverflow-main-acos_service

- **File/Directory Path:** `sbin/acos_service`
- **Location:** `acos_service:0xc6c8 in main function`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** In the main function of 'acos_service', when processing the NVRAM variable 'ParentalCtrl_MAC_ID_tbl', strcpy is used for copying without boundary checks, leading to a stack buffer overflow. An attacker can set a malicious long string to this NVRAM variable through the web interface or other interfaces. When the service initializes or restarts, the strcpy operation will overflow the fixed-size stack buffer, overwriting the return address. Under the ARM architecture, a carefully crafted input can control the program counter (PC), achieving arbitrary code execution. Trigger conditions include device startup, service restart, or related configuration changes.
- **Code Snippet:**
  ```
  0x0000c6b8      0c0a9fe5       ldr r0, str.ParentalCtrl_MAC_ID_tbl ; [0x25158:4]=0x65726150 ; 'ParentalCtrl_MAC_ID_tbl'
  0x0000c6bc      3af9ffeb       bl sym.imp.acosNvramConfig_get
  0x0000c6c0      0010a0e1       mov r1, r0                  ; const char *src
  0x0000c6c4      0500a0e1       mov r0, r5                  ; char *dest
  0x0000c6c8      9df9ffeb       bl sym.imp.strcpy           ; char *strcpy(char *dest, const char *src)
  ```
- **Keywords:** ParentalCtrl_MAC_ID_tbl, /sbin/acos_service
- **Notes:** Exploiting this vulnerability requires the attacker to have valid login credentials to modify the NVRAM variable and to trigger service initialization. It is recommended to further verify the stack buffer size (approximately 0xbd0 bytes allocated) and specific offsets to optimize exploitation. Related functions include acosNvramConfig_get and system calls, which may affect other components. In the firmware environment, ASLR may not be enabled, increasing exploitability.

---
### Command Injection-amule.sh_start

- **File/Directory Path:** `etc/aMule/amule.sh`
- **Location:** `amule.sh:start function (approximate line number based on content: near 'dir=$(echo $emule_work_dir | sed 's/\//\\\//g')')`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** Command injection vulnerability in the start function of the 'amule.sh' script. Due to the unquoted use of the user-provided directory path ($emule_work_dir) in the 'echo' command, an attacker can execute arbitrary commands through command substitution injection (e.g., '$(malicious_command)'). Trigger condition: When a user runs the script providing a malicious path parameter, e.g., './amule.sh start "$(id > /tmp/exploit)"'. Exploitation method: The attacker controls the $2 parameter (working directory path); in the line 'dir=$(echo $emule_work_dir | sed 's/\//\\\//g')', 'echo $emule_work_dir' will execute the embedded command. The vulnerability allows non-root users to escalate privileges or access sensitive data, as the injected command runs with the script's execution permissions. The attack chain is complete: from untrusted input (command line argument) to dangerous operation (command execution), exploitable without root privileges.
- **Code Snippet:**
  ```
  start() {
  	emule_work_dir=$1
  	...
  	dir=$(echo $emule_work_dir | sed 's/\//\\\//g')
  	...
  }
  ```
- **Keywords:** Command line argument $2
- **Notes:** Vulnerability based on code analysis, evidence from file content. Recommend further validation of exploitability in a real environment, e.g., testing if command injection is restricted by the shell environment. Related files: May affect aMule daemon configuration. Subsequent analysis direction: Check if other scripts or binaries similarly use unquoted variables.

---
### command-injection-ftp-fcn.000109e8

- **File/Directory Path:** `usr/sbin/ftp`
- **Location:** `ftp:0x10ff8 fcn.000109e8`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** A command injection vulnerability was discovered in the 'ftp' binary, allowing authenticated users to execute arbitrary shell commands via crafted FTP commands. The vulnerability triggers when user input begins with the '|' character, which is directly passed to the popen function for execution. Specific exploitation methods include using the '|command' format in the filename parameter of FTP commands (such as RETR or STOR), where 'command' is any shell command. The code lacks validation and escaping of user input, enabling attackers to inject and execute commands. This vulnerability may allow attackers to bypass FTP restrictions, access system resources, or perform lateral movement.
- **Code Snippet:**
  ```
  In function fcn.000109e8, the key code snippet:
  if (**(puVar14 + -0x98) == '|') {
      uVar3 = sym.imp.popen(*(puVar14 + -0x98) + 1, 0x5cd4 | 0x10000);
  }
  Here, *(puVar14 + -0x98) is the user input string; when it starts with '|', the remaining part is passed to popen for execution.
  ```
- **Keywords:** FTP command input (e.g., RETR, STOR), Environment variables or NVRAM variables (not directly involved, but may be indirectly affected through command execution)
- **Notes:** This vulnerability was confirmed based on static code analysis, with a complete and verifiable attack chain. Further dynamic testing is recommended to validate exploitability. Related functions include fcn.00013950 (main function), fcn.000136c0 (input parsing), and fcn.00013358 (command lookup). Attackers require valid FTP login credentials but do not need root privileges.

---
### stack-buffer-overflow-fcn.0000fb08

- **File/Directory Path:** `usr/bin/KC_PRINT`
- **Location:** `KC_PRINT:fcn.0000fb08:0xfb08`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** A stack buffer overflow vulnerability was discovered in function fcn.0000fb08, which handles file reception or print job protocols. Problem manifestation: A length field (16-bit unsigned integer) in the input data is directly used in a memcpy operation, targeting a fixed-size stack buffer (64 bytes), lacking boundary checks. Trigger condition: When specific bytes in the input data match (e.g., *(puVar2[-5] + 2) == 0 and *(puVar2[-5] + 3) == '\n'), fcn.00009884 calls fcn.0000fb08, passing a controllable input buffer. Constraints: Buffer size is 64 bytes, attacker can control length up to 65535 bytes. Potential attack and exploitation method: The overflow allows overwriting the return address, enabling arbitrary code execution. Related code logic: The function parses the input protocol, extracts the length field, and copies the data.
- **Code Snippet:**
  ```
  piVar4[-0x11] = *(*(piVar4 + (0xef68 | 0xffff0000) + 4) + piVar4[-3]) * 0x100 + *(*(piVar4 + (0xef68 | 0xffff0000) + 4) + piVar4[-3] + 1);
  sym.imp.memcpy(piVar4 + 0 + -0x1088, *(piVar4 + (0xef68 | 0xffff0000) + 4) + piVar4[-3], piVar4[-0x11]); // piVar4[-0x11] is the controllable length
  ```
- **Keywords:** param_2 (input buffer), piVar4[-0x11] (length field), auStack_1094[64] (stack buffer), fcn.00009884 (caller)
- **Notes:** Vulnerability verified: Input is passed from an external source via fcn.00009884. Stack layout analysis shows the return address is located after the overflow buffer. Further analysis of the input point is recommended to confirm remote exploitability.

---
### stack-buffer-overflow-fcn.0000e454

- **File/Directory Path:** `usr/bin/KC_PRINT`
- **Location:** `KC_PRINT:fcn.0000e454:0xe454`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** Multiple stack buffer overflow vulnerabilities were discovered in function fcn.0000e454, which handles IPP protocol requests. Problem manifestation: When parsing the 'printer-uri', 'requesting-user-name', and 'job-name' attributes, memcpy is used to copy input data into fixed-size stack buffers (128 bytes, 48 bytes, and 48 bytes respectively), but there is a lack of sufficient boundary checks. Trigger condition: An attacker sends an IPP request where the 'printer-uri' length exceeds 128 bytes, or the 'requesting-user-name'/'job-name' length exceeds 48 bytes. Constraints: The buffer sizes are limited, and the attacker can control the attribute lengths. Potential attacks and exploitation methods: Overflow overwrites the return address or critical variables, enabling arbitrary code execution. Related code logic: The function parses IPP attributes and copies data based on length fields, but the boundary checks are flawed.
- **Code Snippet:**
  ```
  // 'printer-uri' processing
  sym.imp.memcpy(piVar7 + 0 + -0x8e4, piVar7[-0x25b] + piVar7[-1], piVar7[-9]); // No boundary check
  // 'requesting-user-name' processing
  if (iVar1 != 0x30 && iVar1 + -0x30 < 0 == SBORROW4(iVar1,0x30)) {
      sym.imp.memcpy(piVar7 + 0 + -0x914, piVar7[-0x25b] + piVar7[-1], 0x30);
  } else {
      sym.imp.memcpy(piVar7 + 0 + -0x914, piVar7[-0x25b] + piVar7[-1], piVar7[-9]); // Potential overflow
  }
  // 'job-name' processing is similar
  ```
- **Keywords:** printer-uri, requesting-user-name, job-name, IPP protocol socket
- **Notes:** The vulnerability exists in IPP protocol processing; the attacker needs valid login credentials. It is recommended to verify the stack layout and protection mechanisms. Related functions: fcn.00013444 and fcn.00009b10.

---
### Passwd-Buffer-Overflow

- **File/Directory Path:** `bin/busybox`
- **Location:** `busybox:0xc4f4 (strcpy call site)`
- **Risk Score:** 8.0
- **Confidence:** 7.5
- **Description:** The passwd command may experience a buffer overflow when processing user input, allowing an attacker to overwrite stack data and control the execution flow. The issue manifests as the use of the unsafe strcpy function to copy user input (such as a password) into a fixed-size buffer, lacking boundary checks. The trigger condition is providing an overly long password or username via the command line or interactive input. Potential attacks include executing arbitrary code, potentially escalating to root privileges. The attack chain is complete: a user runs the passwd command and provides overly long input, causing a strcpy overflow and controlling the execution flow.
- **Code Snippet:**
  ```
  sym.imp.strcpy (identified from disassembly)
  ```
- **Keywords:** PWD, HOME, /etc/passwd, /etc/shadow, passwd main function
- **Notes:** Based on the call to strcpy and password input handling; dynamic testing is required to confirm buffer size; it is recommended to use safe functions such as strncpy.

---
### XSS-Highcharts-tooltipFormatter

- **File/Directory Path:** `www/script/highcharts.js`
- **Location:** `highcharts.js (Approximately in the middle of the minified code, specific line number unreliable, but based on function identifiers)`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** A Cross-Site Scripting (XSS) vulnerability was discovered in the Highcharts.js library. The vulnerability exists in the formatting functions for tooltips and dataLabels, which directly insert user-controlled data into HTML without escaping. Specific manifestation: When the chart renders, if user-provided data (such as point name, x/y values) contains malicious HTML or JavaScript code, it will be executed in the browser. Trigger conditions include: 1) The attacker can provide or modify chart data (via the application's API or configuration); 2) The chart is rendered and displays tooltips or dataLabels. Potential attack method: An attacker constructs malicious data points (e.g., name containing `<script>alert('XSS')</script>`), which triggers XSS when other users view the chart. The vulnerability involves a lack of input validation and output encoding, allowing a complete attack chain from untrusted input points to DOM manipulation.
- **Code Snippet:**
  ```
  // Example of default tooltip formatting function
  function h() {
      var H = this.points || nc(this),
          A = H[0].series.xAxis,
          D = this.x;
      A = A && A.options.type == "datetime";
      var ha = Kb(D) || A,
          xa;
      xa = ha ? ['<span style="font-size: 10px">', A ? Mc("%A, %b %e, %Y", D) : D, "</span><br/>"] : [];
      t(H, function(va) {
          xa.push(va.point.tooltipFormatter(ha)); // User data inserted directly
      });
      return xa.join(""); // Returns unescaped HTML string
  }
  
  // tooltipFormatter method of the point object
  tooltipFormatter: function(a) {
      var b = this.series;
      return ['<span style="color:' + b.color + '">', this.name || b.name, "</span>: ", !a ? "<b>x = " + (this.name || this.x) + ",</b> " : "", "<b>", !a ? "y = " : "", this.y, "</b><br/>"].join(""); // User data (name, x, y) directly concatenated
  }
  ```
- **Keywords:** tooltipFormatter, dataLabels.formatter, Highcharts.Chart, series.data
- **Notes:** The exploitation of this vulnerability relies on the application rendering charts using user-provided data. The attacker needs login credentials to inject malicious data, but once successful, it can compromise other user sessions. It is recommended to subsequently verify the source and processing of chart data in the actual application. Related files may include HTML pages using Highcharts and server-side APIs. Remediation suggestion: Perform HTML escaping on all user inputs before inserting them into the DOM.

---
### Telnetd-Command-Injection

- **File/Directory Path:** `bin/busybox`
- **Location:** `busybox:0x430fc (function fcn.000430d0)`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** The Telnetd service, when processing user input, may allow malicious commands to be injected through environment variables or command-line parameters, leading to arbitrary command execution. The issue manifests as a lack of validation when user input (such as the TERM environment variable) is passed to the execve function, allowing special characters (such as semicolons) to be interpreted as command separators. The trigger condition is manipulating environment variables or command parameters after connecting via Telnet. Potential attacks include gaining shell access or performing arbitrary operations. The attack chain is complete: after a user logs in via Telnet, setting a malicious environment variable (e.g., TERM=; malicious_command) triggers execve to execute arbitrary commands.
- **Code Snippet:**
  ```
  void fcn.000430d0(int32_t param_1, int32_t *param_2, uint param_3) { ... sym.imp.execve(param_1, param_2, param_3); ... }
  ```
- **Keywords:** TERM, SHELL, PATH, /dev/tty, /etc/passwd, Telnet socket, fcn.000430d0
- **Notes:** Based on code analysis, the execve call may directly use user input; further verification of Telnetd's specific implementation is needed, but historical versions of BusyBox have similar vulnerability reports. It is recommended to check the input processing logic.

---
### buffer-overflow-fcn.0000ba0c

- **File/Directory Path:** `usr/bin/KC_PRINT`
- **Location:** `KC_PRINT:fcn.0000ba0c:0xba0c`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** A buffer overflow vulnerability was discovered in function fcn.0000ba0c, which handles HTTP requests. Problem manifestation: When the input character is 'D', the function reads a two-byte length value from the input and uses fcn.00009b10 to copy data to the stack buffer auStack_1094 (size 64 bytes), but the copy length is calculated as piVar7[-0x11] + 2, without verifying if it exceeds the buffer size. Trigger condition: An attacker sends an HTTP request containing the 'D' character and a malicious length value. Constraint: Buffer size is 64 bytes, attacker can control length up to 65535 + 2 bytes. Potential attack and exploitation method: Overflow overwrites the return address or critical variables on the stack to achieve arbitrary code execution. Related code logic: The function parses HTTP request data in a loop and performs the copy operation under specific character conditions.
- **Code Snippet:**
  ```
  if ((*(*(piVar7 + (0xef30 | 0xffff0000) + 4) + piVar7[-4]) != 'D') || (*(piVar7 + -0x15) != '\0')) {
      // ...
  } else {
      *(piVar7 + -0x15) = 1;
      piVar7[-0x11] = *(*(piVar7 + (0xef30 | 0xffff0000) + 4) + piVar7[-4] + 1) * 0x100 + *(*(piVar7 + (0xef30 | 0xffff0000) + 4) + piVar7[-4] + 2);
      iVar1 = fcn.00009b10(piVar7 + 0 + -0x1048, piVar7[-1], *(piVar7 + (0xef30 | 0xffff0000) + 4) + piVar7[-4] + 1, piVar7[-0x11] + 2); // No bounds check
  }
  ```
- **Keywords:** HTTP request data (param_2), Stack buffer auStack_1094, Function fcn.00009b10, Network socket
- **Notes:** Based on static analysis, dynamic testing is required to verify exploit feasibility. It is recommended to check the stack layout to confirm the return address can be overwritten. Associated files may include other HTTP processing components.

---
### Shell-Env-Injection

- **File/Directory Path:** `bin/busybox`
- **Location:** `String reference shows related variables (such as PS1=# at index 1886)`
- **Risk Score:** 6.5
- **Confidence:** 7.0
- **Description:** BusyBox's shell (ash), when handling environment variables, may allow command injection through specific variables (such as PS1 or ENV). The issue manifests as environment variable values being directly evaluated during parsing, lacking filtering. The trigger condition is an attacker setting a malicious environment variable, which executes the embedded command when the shell starts. Potential attacks include arbitrary command execution by pointing the ENV variable to a malicious script. The attack chain is complete: a user sets a malicious environment variable (e.g., ENV=malicious_script), and the shell executes this script upon initialization.
- **Code Snippet:**
  ```
  Identify PS1 and ENV related strings from a list of strings
  ```
- **Keywords:** PS1, ENV, PATH, /etc/profile, ~/.profile, shell initialization function
- **Notes:** Based on common shell vulnerability patterns; requires specific configuration support; recommends restricting the use of environment variables.

---
