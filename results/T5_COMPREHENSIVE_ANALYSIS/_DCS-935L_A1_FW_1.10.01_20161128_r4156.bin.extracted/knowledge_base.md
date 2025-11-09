# _DCS-935L_A1_FW_1.10.01_20161128_r4156.bin.extracted (17 findings)

---

### Command-Injection-write_param_to_flash

- **File/Directory Path:** `bin/wscd`
- **Location:** `File: wscd, Function: write_param_to_flash, Address: 0x00419518`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** A command injection vulnerability exists in the 'wscd' binary via the '-w' command-line argument. The argument value is copied unsanitized into a buffer and used in a system call within the 'write_param_to_flash' function. An attacker with valid login credentials can exploit this by providing a malicious interface name containing shell metacharacters (e.g., semicolons) to execute arbitrary commands with root privileges. The vulnerability is triggered during the WPS configuration process when 'write_param_to_flash' is called, typically after initialization or during event processing.
- **Code Snippet:**
  ```
  Relevant code from write_param_to_flash:
  (**(loc._gp + -0x7eac))(auStack_a8,"%s -param_file %s %s","flash",param_1 + 0x188,"/tmp/flash_param");
  (**(loc._gp + -0x7bfc))(auStack_a8);
  Here, param_1 + 0x188 points to user-controlled data from the '-w' argument, and auStack_a8 is a stack buffer of 120 bytes. The system call executes the constructed string without validation.
  ```
- **Keywords:** Command-line argument: -w (wlan interface), NVRAM/ENV variables: None directly, but derived from command-line input, Function: write_param_to_flash, Dangerous operation: system call
- **Notes:** This vulnerability requires the attacker to have shell access and permissions to execute 'wscd'. The attack chain is straightforward and reliably exploitable. Additional analysis should check for similar issues in other command-line arguments (e.g., -br, -fi) and in network handling functions like ExecuteSoapAction. The buffer size (120 bytes) may limit the length of injected commands but is sufficient for most payloads.

---
### Command-Injection-PushDCHEventNotifyCheck

- **File/Directory Path:** `usr/sbin/hnap_push_service`
- **Location:** `hnap_push_service:0x00407210 PushDCHEventNotifyCheck`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** A command injection vulnerability exists in the PushDCHEventNotifyCheck function where unsanitized input from XML policy files is used in system commands. The function reads policy data from '/mnt/flash/config/hnap_policy.xml' and uses values like DeviceMacID, ModuleID, etc., in formatted strings passed to system(). For example, when handling event 422015 (ACTION_ID_SNAP_NOTIFY), the code executes: '/usr/sbin/msger eventd 0 eiotsnapshottrigger 1 "%d %s %d %d %s" 2>/dev/null 1>/dev/null' with data from XML. If an attacker can set malicious values in the policy (e.g., via HNAP requests), they can inject shell metacharacters to execute arbitrary commands. The service runs as root, so command execution occurs with root privileges. Triggering requires an event that matches the policy, but an attacker can set the policy to trigger on specific events.
- **Code Snippet:**
  ```
  // From decompilation at ~0x00408a00 in PushDCHEventNotifyCheck
  (**(iVar28 + -0x7f60)) (*(&stack0x0004df9c + iVar5), "/usr/sbin/msger eventd 0 eiotsnapshottrigger 1 \"%d %s %d %d %s\" 2>/dev/null 1>/dev/null", 0, *(&stack0x0004dfc0 + iVar5));
  (**(*(apcStack_7fc8 + iVar5) + -0x7e48)) (*(&stack0x0004df9c + iVar5)); // system call
  // *(&stack0x0004dfc0 + iVar5) contains data from XML tags like DeviceMacID
  ```
- **Keywords:** /mnt/flash/config/hnap_policy.xml, DeviceMacID, ModuleID, EventID, ActionID
- **Notes:** The vulnerability requires the attacker to set the policy via HNAP or other means, which may be feasible with login credentials. Other events (e.g., 422017, 422019) have similar code patterns. Further analysis should verify HNAP handlers in other binaries that write the policy file.

---
### CommandInjection-param.cgi-PanTilt

- **File/Directory Path:** `web/cgi-bin/cgi/param.cgi`
- **Location:** `param.cgi:0x0040365c (fcn.0040365c) - PanTilt parameter handling`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** A command injection vulnerability exists in the PanTilt configuration update functionality of param.cgi. When an authenticated admin user submits a request with action='update', group='PanTilt', and name='Position1' (or similar position names), the user-provided value is directly incorporated into a system command without proper sanitization. This allows an attacker to inject arbitrary commands by including shell metacharacters (e.g., semicolons or backticks) in the value parameter. The vulnerable code uses a sprintf-like function to format a command string and then executes it via system(), leading to remote command execution with the privileges of the CGI process.
- **Code Snippet:**
  ```
  // From fcn.0040365c decompilation
  iVar1 = (**(loc._gp + -0x7f68))(param_4, "Position1");
  if (iVar1 == 0) {
      (**(loc._gp + -0x7f78))(&uStack_21c, "/usr/sbin/ptctrl -setpreset0=%s 2>/dev/null 1>/dev/null", param_5);
      (**(loc._gp + -0x7ef4))(&uStack_21c);
  }
  ```
- **Keywords:** action, group, name, value
- **Notes:** This vulnerability requires admin-level authentication, as the code checks *0x431d60 == 1 before processing. The attack chain is complete from input (CGI parameters) to dangerous operation (system call). No evidence of input sanitization was found. Additional positions (Position2 to Position8) are similarly vulnerable. Exploitation could lead to full device compromise.

---
### Command-Injection-sym.usrAdd

- **File/Directory Path:** `usr/lib/libweb.so`
- **Location:** `libweb.so.0:0x75c0 sym.usrAdd`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** The function sym.usrAdd in libweb.so.0 constructs a shell command using system to execute /usr/sbin/set_passwd for adding users. The username parameter (param_2) is directly incorporated into the command string without any sanitization or escaping, while only the password parameter (param_3) is escaped for a limited set of characters (", `, \, $). This allows an attacker to inject arbitrary shell commands by including metacharacters (e.g., ;, |, &) in the username parameter. For example, a username like " ; echo injected ; " would break the command string and execute echo injected. The vulnerability is triggered when a user addition request is processed, typically via a web API. Attackers with valid non-root credentials can exploit this if the web interface lacks proper authorization checks, leading to arbitrary command execution with the privileges of the web server process (which may be root).
- **Code Snippet:**
  ```
  // Decompilation snippet showing the vulnerable code
  (**(iVar11 + -0x7f34))(&cStack_230, *(iVar11 + -0x7fdc) + -0x1dc, param_2, acStack_130);
  (**(iVar11 + -0x7e10))(&cStack_230); // system call
  
  // Assembly at 0x75c0:
  // 0x000075c0      8f9981f0       lw t9, -sym.imp.system(gp)
  // 0x000075c4      0320f809       jalr t9
  // 0x000075c8      02202021       move a0, s1
  // Where s1 contains the command string with unsanitized username.
  ```
- **Keywords:** param_2 (username input), /usr/sbin/set_passwd (command executed), system function call, usrAdd
- **Notes:** This vulnerability requires the attacker to have access to the user addition functionality, which may be restricted to administrative users in some configurations. However, if the web interface has improper access control, non-admin users could trigger it. The web server process privileges determine the impact; if running as root, full system compromise is possible. Further analysis should verify the access control mechanisms in the web application using this library. Other functions like sym.calculateSDUsedSize and sym.dropCache also use system but were not fully analyzed for similar issues. Associated with existing finding in user_mod.cgi via 'usrAdd' identifier.

---
### StackOverflow-user_del.cgi-fcn.00400a90

- **File/Directory Path:** `web/cgi-bin/config/user_del.cgi`
- **Location:** `user_del.cgi:Unknown line number fcn.00400a90 address 0x00400a90`
- **Risk Score:** 8.5
- **Confidence:** 7.5
- **Description:** In the fcn.00400a90 function of 'user_del.cgi', a stack buffer overflow vulnerability was discovered. This function processes the 'name' parameter from HTTP requests, using strcpy to copy it to a fixed stack address &cStack_420, without any size checks or boundary validation. An attacker, as a logged-in non-root user, can overflow the buffer by sending a maliciously long 'name' parameter (e.g., via a CGI request), overwriting the return address on the stack, potentially leading to arbitrary code execution. The vulnerability trigger condition is sending an HTTP request containing an overly long 'name' value. The exploit chain is complete: from the input point (HTTP 'name' parameter) to the dangerous operation (strcpy to stack buffer). Code logic shows that after comparing the parameter to 'name', data is copied directly using strcpy, lacking any filtering.
- **Code Snippet:**
  ```
  // From decompiled code snippet:
  if (iVar1 == 0) {
      (**(loc._gp + -0x7f84))(&cStack_420,piVar6[iVar2 + 0x81]); // strcpy call, target is &cStack_420, source is user input
      if (cStack_420 != '\0') {
          // ... subsequent processing
      }
  }
  ```
- **Keywords:** name
- **Notes:** The buffer size is not explicitly specified, but inferred from the stack variable 'cStack_420' and 'auStack_41f [1023]' layout, the overflow could overwrite the return address. Further dynamic testing is recommended to verify exploit feasibility and to check if other functions (like usrDelByName) involve more interaction. Since the file is a stripped ELF, line numbers are unavailable; addresses are based on decompilation. Note: The 'name' identifier also appears in a command injection vulnerability in param.cgi, but the two are independent.

---
### File-Permission-rcS

- **File/Directory Path:** `etc/rc.d/rcS`
- **Location:** `rcS:1 (file permissions) - Permissions set to 777, allowing all users to access`
- **Risk Score:** 8.0
- **Confidence:** 9.0
- **Description:** The file 'rcS' has global read, write, and execute permissions (-rwxrwxrwx), allowing any user (including non-root users) to modify this startup script. An attacker can inject malicious commands (such as a reverse shell or privilege escalation code), which will be executed with root privileges during system startup. The trigger condition is that the attacker modifies the file and waits for the system to restart (or actively triggers a restart). There is a lack of boundary checks or validation because the script is executed unconditionally as root. Potential attack methods include adding a persistent backdoor or directly obtaining a root shell.
- **Code Snippet:**
  ```
  File permissions: -rwxrwxrwx 1 user user 1226 Nov 28  2016 rcS
  File content includes commands executed at startup, such as the mount_jffs2 function and /etc/init.d/ script execution.
  ```
- **Keywords:** /etc/rc.d/rcS
- **Notes:** This vulnerability relies on a system restart to trigger the execution of malicious code. It is recommended to check if the system has an automatic restart mechanism or if an attacker can trigger a restart. Subsequent analysis should verify the permissions and content of other startup scripts to confirm if similar issues exist.

---
### Command Injection-httpd-runcgi

- **File/Directory Path:** `web/httpd`
- **Location:** `httpd:0x00402104 fcn.00402040 (execve call), httpd:0x004036ac fcn.00403038 (calls fcn.00402040)`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** In the fcn.00402040 function (labeled 'runcgi') of the httpd binary, a command injection vulnerability was discovered, allowing attackers to execute arbitrary commands via HTTP requests. The root cause is that the path parameter from the HTTP request (ending with '.cgi') is passed directly to the execve system call without proper path sanitization or validation. An attacker needs valid login credentials (non-root user) and can craft a malicious HTTP request with a path pointing to any executable file (e.g., via path traversal like '/../../../bin/sh' or an uploaded malicious script). The trigger condition is sending an HTTP request to a CGI endpoint where the path ends with '.cgi'. The data flow propagates from the HTTP request input (parsed via reqInit) to the execve call, lacking boundary checks, leading to arbitrary code execution. The exploitation probability is high because the attacker can directly control the execution path.
- **Code Snippet:**
  ```
  From decompiled code:
  - At 0x004036ac in fcn.00403038: iVar7 = strcmp(piStack_40, ".cgi"); if (iVar7 == 0) { fcn.00402040(&ppiStack_458, param_4, &uStack_454); }
  - At 0x00402104 in fcn.00402040: execve(*(*param_1 + 0x1c), uVar2, uVar1); // where *(*param_1 + 0x1c) is the user-controlled path
  ```
- **Keywords:** HTTP Request Path, reqInit function, execve system call, struct offset 0x1c, NVRAM: User authentication data (e.g., USER_ADMIN, Password1)
- **Notes:** Taint analysis confirmed the direct data flow from HTTP user input to execve. Further validation is needed regarding path construction details in reqInit and filesystem restrictions (e.g., web root constraints). Testing in a full firmware environment is recommended to confirm exploitability. Related functions include reqMakeArg and reqMakeEnv, which might introduce additional vulnerabilities if user input flows into arguments or environment variables.

---
### Untitled Finding

- **File/Directory Path:** `web/cgi-bin/config/user_mod.cgi`
- **Location:** `user_mod.cgi:0x00400ad0 fcn.00400ad0`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** In the fcn.00400ad0 function of 'user_mod.cgi', there exists a stack buffer overflow vulnerability. The issue manifests as using the strcpy function to directly copy user-controlled CGI parameters (name, newname, password, group) into fixed-size stack buffers, lacking length validation. The trigger condition is an attacker submitting a CGI request where the length of any parameter exceeds the buffer size (64 bytes for name, newname, group; 256 bytes for password). Constraints include that parameters cannot be empty, but there are no length restrictions. Potential attack methods include crafting overly long parameters to overwrite the return address, injecting shellcode, and controlling the execution flow, potentially escalating privileges (CGI typically runs as root). The relevant code logic involves a loop parsing CGI parameters and using strcpy to copy data.
- **Code Snippet:**
  ```
  // Example strcpy call for 'name' parameter
  iVar1 = (**(loc._gp + -0x7fb8))(uVar4, "name");
  if (iVar1 == 0) {
      (**(loc._gp + -0x7f7c))(pcStack_44, piVar2[iVar3 + 0x81]); // strcpy call, pcStack_44 points to 64 byte buffer
  }
  // Similar code for 'newname', 'password', 'group' parameters
  // Buffer declarations:
  // char cStack_288; uchar auStack_287[63]; // 64 byte buffer for name
  // char cStack_248; uchar auStack_247[63]; // 64 byte buffer for newname
  // uchar uStack_148; uchar auStack_147[255]; // 256 byte buffer for password
  // char cStack_1c8; uchar auStack_1c7[63]; // 64 byte buffer for group
  ```
- **Keywords:** name, newname, password, group, sym.imp.strcpy, fcn.00400ad0, usrAdd, usrDelByName
- **Notes:** The vulnerability is based on static code analysis, showing a complete attack chain: untrusted input (CGI parameters) -> unvalidated data flow (strcpy) -> dangerous operation (buffer overflow). It is recommended to further verify stack offsets and exploit feasibility, for example through dynamic testing or calculating specific offsets. Related functions include usrAdd and usrDelByName, possibly involving user management operations.

---
### Command-Injection-pppoe-status

- **File/Directory Path:** `sbin/pppoe-status`
- **Location:** `pppoe-status: Line 22-28 (Command line argument processing) and Line 31 (Configuration file loading)`
- **Risk Score:** 7.5
- **Confidence:** 9.0
- **Description:** A command injection vulnerability was discovered in the 'pppoe-status' script, allowing attackers to execute arbitrary commands through a malicious configuration file. Specific manifestation: The script accepts an optional configuration file path as a command line argument and uses the 'source' command to load this file. If an attacker can control the configuration file path and its content, they can inject malicious shell code. Trigger condition: An attacker runs 'pppoe-status /path/to/malicious/config', where the malicious configuration file contains arbitrary commands (e.g., 'malicious_command'). The script executes these commands with the current user's permissions, leading to privilege escalation or system compromise. Boundary check: The script only verifies if the configuration file exists and is readable ('[ ! -f "$CONFIG" -o ! -r "$CONFIG" ]'), but does not validate the content. Potential attack: An attacker creates and executes a malicious configuration file, potentially obtaining sensitive information, modifying files, or further escalating privileges.
- **Code Snippet:**
  ```
  case "$#" in
      1)
  	CONFIG="$1"
  	;;
  esac
  
  if [ ! -f "$CONFIG" -o ! -r "$CONFIG" ] ; then
      echo "$0: Cannot read configuration file '$CONFIG'" >& 2
      exit 1
  fi
  
  . $CONFIG
  ```
- **Keywords:** CONFIG (Environment variable/Command line argument), /etc/ppp/pppoe.conf (Default configuration file path), PIDFILE (Variable loaded from configuration file), PPPOE_PIDFILE, PPPD_PIDFILE
- **Notes:** Attack chain is complete and verifiable: Input point (command line argument) → Data flow (CONFIG variable) → Dangerous operation (source command). Further verification is needed on whether an attacker can create a malicious configuration file (e.g., in a user-writable directory). It is recommended to check system permissions and default configuration file locations. Associated file: /etc/ppp/pppoe.conf (default configuration). Subsequent analysis direction: Check if other scripts use a similar configuration file loading mechanism.

---
### BufferOverflow-cfg-main

- **File/Directory Path:** `usr/sbin/cfg`
- **Location:** `cfg:0x004008e0 main (sprintf and strcat call points in decompiled code)`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** A buffer overflow vulnerability was discovered in the 'cfg' program. When the program uses sprintf and strcat to construct file paths, the length of the path (controlled via the -p command line option) and configuration file name provided by the user is not validated. The stack buffer auStack_13c has a size of 260 bytes. If the combined length of the user-provided path and filename exceeds 260 bytes, it will overflow into adjacent stack variables (such as uStack_38, pcStack_34) and potentially the return address. An attacker, as a logged-in non-root user, can trigger the overflow by executing 'cfg -p <long path> <long filename> ...'. Carefully crafted input can overwrite the return address, leading to arbitrary code execution. Vulnerability trigger condition: the total length of the command line arguments exceeds 260 bytes, and the path and filename are controllable. Exploitation method: overwrite the return address via the overflow to jump to shellcode or existing code segments, achieving privilege escalation or command execution.
- **Code Snippet:**
  ```
  // Key code snippet extracted from the decompiled main function
  (**(loc._gp + -0x7fb8))(auStack_13c, "%s/", pcStack_34); // sprintf constructs the path, pcStack_34 is the user-input path
  (**(loc._gp + -0x7fa4))(auStack_13c, pcVar5); // strcat appends the filename, pcVar5 is the user-input conf_file
  // Buffer auStack_13c size is 260 bytes, no length check
  if (overflow occurs) {
      // May overwrite uStack_38 (action parameter), pcStack_34 (path pointer), etc., thereby affecting control flow
  }
  ```
- **Keywords:** Command line arguments, CfgGetField, CfgSetField, CfgRemoveField
- **Notes:** The vulnerability is based on actual code analysis; the stack layout was confirmed via decompilation. Further validation is needed for the return address offset and exploit feasibility, such as through dynamic testing or more detailed stack analysis. Recommended follow-up analysis: Check if other functions (such as CfgGetField) also have similar issues, and assess the exploitation difficulty in a real environment. The attack chain is complete: from user input (command line) to dangerous operation (buffer overflow), potentially leading to code execution.

---
### BufferOverflow-RTSP-RequestProcess

- **File/Directory Path:** `usr/sbin/rtsp/rtspd`
- **Location:** `rtspd:0x40443c RequestProcess`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** In the RequestProcess function, when handling RTSP PLAY requests, the code uses sprintf to format a URI string from user-controlled inputs without proper bounds checking. Specifically, at address 0x40443c, sprintf is called with a destination buffer that may be fixed-size, and the inputs include scheme, host, port, and path from the RTSP request. An attacker can craft a long URI in a PLAY request to overflow the buffer, potentially leading to arbitrary code execution. The trigger condition is sending a malicious PLAY request with an overly long URI. Constraints include the buffer size not being verified, and the attack can be performed by an authenticated non-root user via the RTSP interface.
- **Code Snippet:**
  ```
  // From RequestProcess decompilation
  if (*(param_1 + 0x4c) < 1) {
      sprintf(iVar11, "%s://%s/%s", *(param_1 + 0x3c), *(param_1 + 0x48), *(param_1 + 0x50));
  } else {
      sprintf(iVar11, "%s://%s:%d/%s", *(param_1 + 0x3c), *(param_1 + 0x48), *(param_1 + 0x4c), *(param_1 + 0x50));
  }
  ```
- **Keywords:** RTSP PLAY method, URI parameters
- **Notes:** This vulnerability is highly exploitable due to the use of sprintf without bounds checking. The destination buffer iVar11 is likely on the stack, making it susceptible to stack-based buffer overflow. Further analysis is needed to determine the exact buffer size and exploitability, but the presence of this pattern in a network-facing function makes it a prime target. Recommend testing with long URIs to confirm overflow.

---
### Command-Injection-userconfig-restore

- **File/Directory Path:** `usr/sbin/userconfig`
- **Location:** `File:userconfig Line number:Not specified (binary file) Function name:fcn.004014ec Address:0x004014ec`
- **Risk Score:** 6.5
- **Confidence:** 8.5
- **Description:** A command injection vulnerability was discovered in the -restore function of the 'userconfig' program. An attacker can create a malicious file where the group name or item name contains command injection characters (such as ;, |, &, $, etc.), and then execute 'userconfig -restore <file_path>'. The program uses sprintf when constructing the command string and embeds the group name and item name directly into the command without sufficient escaping or validation. Although the values are escaped for double quotes, backticks, and backslashes, the group name and item name are not escaped, leading to command injection. For example, if the group name is '; rm -rf /', the constructed command could become 'userconfig -write "; rm -rf /" "item" "value"', thereby executing arbitrary commands. The attacker needs file write permission to create the malicious file, but as a logged-in user, this is usually feasible. The vulnerability allows arbitrary command execution, but runs with the current user's privileges, so it does not directly escalate privileges, but could be used for information disclosure, lateral movement, or further attacks.
- **Code Snippet:**
  ```
  Key code snippet from decompilation:
  (**(loc._gp + -0x7f9c))(puStack_34, "%s -write \"%s\" \"%s\" \"%s\" 2>/dev/null 1>/dev/null", *&uStackX_0, iStack_44, iStack_40, pcStack_38);
  (**(loc._gp + -0x7f38))(puStack_34); // system call
  Where iStack_44 (group name) and iStack_40 (item name) come from user-provided file content and are not escaped; pcStack_38 is the value, which is escaped.
  ```
- **Keywords:** NVRAM variables: HW_NIC0_ADDR, HW_NIC1_ADDR, HW_WLAN0_WLAN_ADDR, Region, File paths: /etc/userconfig.ini, /tmp/sys_env, Command string: "%s -write \"%s\" \"%s\" \"%s\" 2>/dev/null 1>/dev/null"
- **Notes:** Vulnerability verified via code analysis: group name and item name are not escaped and are directly used in command construction. Attack chain is complete: user creates malicious file → executes userconfig -restore → command injection. It is recommended to check if other functions (like -backup) have similar issues, but the current focus is confirmed. Since it runs with user privileges, there is no direct privilege escalation, but it can be used in combination with other vulnerabilities.

---
### buffer-overflow-msger-main

- **File/Directory Path:** `usr/sbin/msger`
- **Location:** `msger:main (0x00401150), approximate address 0x00401310 for strcpy call`
- **Risk Score:** 6.5
- **Confidence:** 7.5
- **Description:** A buffer overflow vulnerability exists in the 'msger' binary when processing command-line arguments in inform mode (MsgType 0). The vulnerability occurs due to the use of strcpy to copy user-controlled input from argv[5] to a fixed-size stack buffer (auStack_12c, 65 uint elements, 260 bytes) without bounds checking. Additionally, a loop copies subsequent arguments using strtol, which may further contribute to buffer overflow. Trigger conditions include running the program with at least 6 arguments in inform mode, where the fifth argument is a string. An attacker can craft long arguments to overflow the buffer, overwrite the return address, and achieve code execution. The program's world-executable permissions (rwxrwxrwx) allow any user to exploit this vulnerability.
- **Code Snippet:**
  ```
  From main function decompilation:
  if (uVar1 == 0) { // Inform mode
      // ...
      iVar4 = (**(pcVar10 + -0x7fc4))(*(param_2 + 0x10)); // strlen(argv[4])
      if (iVar4 == 0) {
          (**(pcVar10 + -0x7f64))(auStack_12c, *(param_2 + 0x14)); // strcpy(auStack_12c, argv[5])
          // ...
      } else {
          // Loop for additional arguments
          puVar6 = auStack_12c;
          iVar7 = 5;
          do {
              uVar5 = (**(loc._gp + -0x7f84))(*(param_2 + 0x14), 0, 0); // strtol
              *puVar6 = uVar5;
              iVar7 = iVar7 + 1;
              param_2 = param_2 + 4;
              puVar6 = puVar6 + 1;
          } while (iVar7 < param_1);
      }
  }
  ```
- **Keywords:** argv, strcpy, msgInformEventStr, msgQueryParam, camsvr, eventd, sinfo, hwmon, netmgr
- **Notes:** The vulnerability is clear from static code analysis, but dynamic verification is needed to confirm exploitability on MIPS architecture. The binary interacts with various message servers (e.g., via msgInformEventStr), but the vulnerability is local to argument processing. Assumption: attacker has login credentials and can execute the binary. Further analysis should focus on crafting a working exploit and checking if the binary is called by other services with elevated privileges.

---
### Untitled Finding

- **File/Directory Path:** `web/cgi-bin/config/system_reboot.cgi`
- **Location:** `system_reboot.cgi:0x00400a20 main`
- **Risk Score:** 6.5
- **Confidence:** 7.0
- **Description:** In the main function of 'system_reboot.cgi', there is a parameter checking logic vulnerability that allows an attacker to trigger a system reboot through a carefully crafted HTTP request. Vulnerability trigger conditions: the attacker must send an HTTP request with at least 130 parameters, where the 4th parameter (argv[3]) must be 'reboot', and the 129th parameter (argv[128]) must be 'go'. The code uses strcmp to compare parameters but accesses out-of-bounds positions of the argv array (such as piVar3[iVar4 + 0x81]). If the conditions are met and the global variable *0x4110d4 (set by readUpFwStatus) is not 1, safeReboot(3) is called to perform a system reboot. Potential attack method: an attacker, as an authenticated user, sends a specially crafted request, causing the device to reboot, resulting in a denial of service. Vulnerability exploitation depends on the web server's limit on the number of parameters, but is theoretically feasible.
- **Code Snippet:**
  ```
  uint main(void)
  {
      // ... code omitted ...
      iVar2 = 0;
      do {
          iVar2 = strcmp(*(piVar3 + iVar2 + 4), "reboot");
          if (iVar2 == 0) {
              iVar2 = strcmp(piVar3[iVar4 + 0x81], "go");
              if (iVar2 == 0) {
                  *0x4110d0 = 1;
                  // ... output HTTP response ...
              }
          }
          iVar4 = iVar4 + 1;
          piVar3 = *(iVar1 + 0x58);
          iVar2 = iVar4 * 4;
      } while (iVar4 < *piVar3);
      // ... code omitted ...
      if ((*0x4110d0 != 0) && (*0x4110d4 != 1)) {
          safeReboot(3);
      }
      return 0;
  }
  ```
- **Keywords:** system_reboot.cgi, HTTP request parameter 'reboot', HTTP request parameter 'go', NVRAM variable (read via readUpFwStatus)
- **Notes:** Vulnerability exploitation requires the web server to allow a large number of parameters, which may be limited by actual configuration. It is recommended to further verify the web server's parameter limit and the behavior of readUpFwStatus. Related functions: cgiInit, safeReboot, readUpFwStatus. Subsequent analysis direction: check web server configuration and NVRAM settings to confirm exploitability.

---
### OOB-Read-Auth-Bypass-ACAS-main

- **File/Directory Path:** `web/cgi-bin/audio/ACAS.cgi`
- **Location:** `ACAS.cgi:main (address 0x00400c80, specifically around the out-of-bounds access)`
- **Risk Score:** 6.0
- **Confidence:** 8.0
- **Description:** The vulnerability occurs in the main function when processing CGI arguments. If the number of arguments (argc) is 1, the code checks if the first argument is "profileid". If true, it accesses argv[129] (0x81 index) via atoi without bounds checking, which is out-of-bounds for typical CGI requests. An attacker can exploit this by providing 130 or more arguments, with argv[1] as "profileid" and argv[129] as "2", to bypass the authentication check and proceed to audio streaming. The streaming then depends on the NVRAM variable 'MicEnable' being set to 1, which could lead to unauthorized audio streaming and information disclosure. Trigger conditions include: argc=1, argv[1]="profileid", argv[129]="2", and 'MicEnable'=1. Potential attack involves sending a crafted CGI request with many arguments to bypass checks and access audio data.
- **Code Snippet:**
  ```
  if (*piVar6 == 1) {
      iVar3 = strcmp(piVar6[1],"profileid");
      if (iVar3 == 0) {
          iVar3 = atoi(piVar6[0x81]);
          bVar1 = iVar3 == 2;
          goto code_r0x00400d18;
      }
  }
  ```
- **Keywords:** CGI arguments (argv), NVRAM variables: AUDIO_PROFILE0, NVRAM variables: MicEnable, NVRAM variables: QoS, NVRAM variables: AudioDSCP
- **Notes:** The exploit requires the attacker to have valid login credentials (as per scenario) and the ability to send CGI requests with many arguments. The success also depends on the 'MicEnable' NVRAM variable being set to 1, which may not be under attacker control if they are non-root. Web server argument limits could affect exploitability. Further analysis could explore other functions in ACAS.cgi for additional vulnerabilities, but this was the primary finding.

---
### CGI-Args-Null-Deref-main

- **File/Directory Path:** `web/cgi-bin/audio/ACAS-AAC.cgi`
- **Location:** `main function (0x00400c80) at addresses where piVar6[1] and piVar6[0x81] are accessed`
- **Risk Score:** 5.5
- **Confidence:** 8.0
- **Description:** The main function accesses CGI arguments without proper bounds checking. When argc is 1 (no arguments provided), the code calls strcmp on argv[1], which is NULL, leading to a segmentation fault and denial-of-service. Additionally, if argc is 2 and argv[1] is 'profileid', the code accesses argv[129] using atoi, which is always out-of-bounds for normal CGI requests. This could read arbitrary stack memory, potentially disclosing sensitive information like environment variables or return addresses. An attacker can trigger this by crafting a CGI request with 'profileid' as the first argument and no additional arguments, causing a crash or memory leak. However, full code execution is unlikely without control over memory layout.
- **Code Snippet:**
  ```
  if (*piVar6 == 1) {
      iVar3 = strcmp(piVar6[1], "profileid");
      if (iVar3 == 0) {
          iVar3 = atoi(piVar6[0x81]);
          // ...
      }
  }
  ```
- **Keywords:** profileid, argv
- **Notes:** This vulnerability is reliably triggered with specific CGI arguments but requires further analysis to determine if information disclosure can be leveraged for privilege escalation. The web server's handling of argc/argv may affect exploitability.

---
### Audio-Stream-OOB-Read-main

- **File/Directory Path:** `web/cgi-bin/audio/ACAS-AAC.cgi`
- **Location:** `main function (0x00400c80) in the loop after pfRead calls`
- **Risk Score:** 4.5
- **Confidence:** 7.0
- **Description:** In the audio streaming loop, the program uses pfRead to read data and then calls skAsyncWrite with fixed offsets (0x1c and 0x44) and sizes. If pfRead returns less than 0x44 bytes, the second skAsyncWrite call may read beyond the buffer boundaries, leading to an out-of-bounds read. This could result in memory disclosure (e.g., heap or stack data) or a crash. An attacker might exploit this by controlling the input source to pfRead (e.g., via a malicious audio file or stream), but practical exploitation requires influence over the audio data source. The vulnerability is conditional on pfRead behavior and may not directly lead to code execution.
- **Code Snippet:**
  ```
  do {
      iVar5 = pfRead(iVar3);
      if (0 < iVar5) break;
      // ...
      iVar4 = skAsyncWrite(1, *(iVar3 + 8) + 0x1c, 0x28, 0x3c);
      if (iVar4 < 0) break;
      iVar5 = skAsyncWrite(1, *(iVar3 + 8) + 0x44, iVar5 - 0x44, 0x3c);
  } while (-1 < iVar5);
  ```
- **Keywords:** pfRead, skAsyncWrite
- **Notes:** The exploitability depends on the implementation of pfRead and skAsyncWrite, and whether an attacker can control the audio stream. Further analysis of these functions and the audio source is recommended to assess full impact.

---
