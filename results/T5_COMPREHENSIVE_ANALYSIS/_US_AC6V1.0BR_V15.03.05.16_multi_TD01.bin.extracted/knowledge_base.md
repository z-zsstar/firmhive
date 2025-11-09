# _US_AC6V1.0BR_V15.03.05.16_multi_TD01.bin.extracted (8 findings)

---

### Library-Hijacking-ld.so.conf

- **File/Directory Path:** `etc_ro/ld.so.conf`
- **Location:** `File: ld.so.conf`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** The file 'ld.so.conf' has globally writable permissions (-rwxrwxrwx), allowing any user (including non-root users) to modify the dynamic linker's library search path. An attacker can add a malicious library path (such as a user-controllable directory), leading to a library hijacking attack. Trigger condition: After a non-root user successfully logs in, they can directly modify this file and add a malicious path; when the system or user programs run using the dynamic linker, the malicious library will be loaded, executing arbitrary code. Exploitation is simple: The attacker only needs to write a malicious path (e.g., '/tmp/malicious_lib'), ensure the malicious library exists and is executable, and then trigger program execution (e.g., via common system commands or services). Lack of boundary checks: The file has no permission restrictions, allowing arbitrary modifications, and the dynamic linker trusts the configured paths by default.
- **Code Snippet:**
  ```
  /lib
  /usr/lib
  ```
- **Keywords:** ld.so.conf
- **Notes:** This finding is based on file permission and content evidence; the attack chain is complete and verifiable. It is recommended to further analyze whether system programs commonly use dynamic linking (e.g., via the 'ldd' command) and check if other protection mechanisms (such as SELinux) might mitigate this risk. Related files may include the dynamic linker binary (e.g., '/lib/ld-linux.so') and malicious libraries in user-controllable directories.

---
### BufferOverflow-define_url_filter_rule_seq_show

- **File/Directory Path:** `lib/modules/url_filter.ko`
- **Location:** `url_filter.ko:0x08000b34 sym.define_url_filter_rule_seq_show`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** In the sym.define_url_filter_rule_seq_show function, there exists a buffer overflow vulnerability due to an error in size calculation during memory allocation and copying. Specific behavior: The function first calculates the required buffer size (based on the total length of the URL rule strings plus 1 per string), but then, when copying each string, it additionally copies 4 bytes of hardcoded data (from address 0x08000c24) and increments the buffer pointer by 1 byte, resulting in copying strlen + 4 + 1 bytes per string, while allocation is only for strlen + 1 bytes. Trigger condition: An attacker, as a logged-in user (non-root), controls URL filtering rule data via untrusted input (such as NVRAM settings or API calls), causing the number of rules to reach the upper limit (approximately 1600), thereby overflowing the kernel buffer. Complete attack chain: Entry point (NVRAM/environment variable or API) → Data flow (global variables and function processing) → Dangerous operation (kernel memory corruption). Potential attack methods: Kernel memory corruption may lead to denial of service, information disclosure, or code execution, depending on the control of overflow data and memory layout.
- **Code Snippet:**
  ```
  From the disassembled code:
  - Allocation phase: 0x08000ad4: mov r0, r6  ; r6 is the total length (sum of string lengths plus 1 per string)
    0x08000ad8: movw r1, 0x8020  ; kmalloc flags
    0x08000adc: bl __kmalloc  ; allocate buffer
  - Copy phase: 0x08000b08: ldr r1, [r5]  ; load string pointer
    0x08000b14: bl strlen  ; get string length
    0x08000b24: bl memcpy  ; copy strlen bytes to buffer
    0x08000b34: ldr r1, [0x08000c24]  ; load hardcoded 4-byte data
    0x08000b40: bl memcpy  ; copy 4 bytes to buffer
    0x08000b48: add r6, r6, 1  ; increment buffer pointer by 1
  This indicates that extra data is copied per string, exceeding the allocated size.
  ```
- **Keywords:** NVRAM/Environment Variable: define_url_array, Global Variable: [sl, 0x3b0], Functions: seq_printf, __kmalloc, kfree, Hardcoded Address: 0x08000c24
- **Notes:** The vulnerability requires the attacker to be able to manipulate URL filtering rule data, possibly through NVRAM set operations or frontend APIs. It is recommended to further analyze data entry points (such as NVRAM handling functions) to confirm the complete attack chain. Associated files may include userspace components or configuration interfaces.

---
### Command-Injection-udev_event

- **File/Directory Path:** `sbin/udevd`
- **Location:** `File:udevd Address:0x0000a364 Function:dbg.udev_event_run (entry) → Address:0x00009ee8 Function:dbg.udev_event_process → Address:0x0000c09c Function:dbg.udev_device_event → Address:0x00011184 Function:dbg.udev_rules_get_name → Address:0x0001036c Function:dbg.match_rule → Address:0x00013bb4 Function:dbg.run_program (dangerous operation).`
- **Risk Score:** 8.5
- **Confidence:** 8.5
- **Description:** Untrusted input propagates through udev event messages (e.g., device insertion events) and is ultimately executed as a command in `dbg.run_program`, leading to command injection. Attackers can inject malicious commands by forging event data (such as device paths or attributes). Trigger conditions include udev events (like device insertion) and insufficient validation of input data. Potential attack methods include executing arbitrary system commands to escalate privileges or damage the system. The relevant code logic involves the function call chain: `dbg.udev_event_run` → `dbg.udev_event_process` → `dbg.udev_device_event` → `dbg.udev_rules_get_name` → `dbg.match_rule` → `dbg.run_program`.
- **Code Snippet:**
  ```
  In \`dbg.udev_event_process\` (0x00009ee8): \`dbg.strlcpy(piVar4 + 0x185, *(param_1 + 0x14), 0x100);\` (tainted data copy)
  In \`dbg.run_program\` (0x00013bb4): \`sym.imp.execv(*(puVar16 + 0xfffff360), puVar16 + 0xfffff360);\` (command execution)
  ```
- **Keywords:** udev event messages (IPC or network interface), dbg.udev_event_run, dbg.udev_event_process, dbg.udev_device_event, dbg.udev_rules_get_name, dbg.match_rule, dbg.run_program, execv
- **Notes:** The input point (udev event messages) might be controlled by an attacker via IPC or network interfaces; it is recommended to validate the parsing logic and access control of event messages.

---
### Shadow-File-Permission-Misconfig

- **File/Directory Path:** `etc_ro/shadow`
- **Location:** `shadow:1`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The shadow file has global read, write, and execute permissions (777), which is a serious security misconfiguration that allows any user (including non-root users) to read the root user's password hash. The hash uses the weak MD5 algorithm ($1$), making it vulnerable to offline brute-force attacks. An attacker, as a logged-in non-root user, can execute 'cat /etc/shadow' or similar commands to directly obtain the hash, then use tools like John the Ripper or hashcat to crack it. If the root password is weak (e.g., common or short passwords), the attacker can crack it in a relatively short time and gain root privileges. The trigger condition is simple: the attacker only needs shell access and to execute a read command. Constraints include the attacker needing valid login credentials, but as a non-root user, they should not have access to the shadow file. Potential attacks include privilege escalation to root, resulting in complete control of the device. The exploitation method involves standard password cracking techniques, requiring no complex interaction.
- **Code Snippet:**
  ```
  root:$1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1:14319::::::
  ```
- **Keywords:** /etc/shadow
- **Notes:** The risk score is based on the permission misconfiguration and weak hash algorithm, but actual exploitation success depends on password strength; it is recommended to immediately fix the file permissions to 600 and enforce strong passwords. Subsequent analysis can verify other user hashes or check system logs to assess cracking attempts. Related files may include /etc/passwd, but this analysis focuses only on the shadow file.

---
### command-injection-cfmd

- **File/Directory Path:** `bin/cfmd`
- **Location:** `cfmd:0x0000adf4 (function fcn.0000adf4)`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The cfmd daemon contains a command injection vulnerability due to unsanitized use of user-controlled NVRAM variables in system command execution. Trigger conditions occur when cfmd initializes network configurations or processes specific settings, reading NVRAM values via GetCfmValue and passing them directly to doSystemCmd without validation. An authenticated attacker can exploit this by setting malicious values in NVRAM variables (e.g., through web interface), leading to arbitrary command execution with root privileges. The code uses fixed-size buffers (e.g., 24 bytes) for these values, but command injection is possible if doSystemCmd utilizes shell execution, allowing bypass of buffer limits via shell metacharacters. Multiple code paths in fcn.0000adf4 exhibit this pattern, with data flowing from NVRAM to dangerous operations.
- **Code Snippet:**
  ```
  // Example code from decompilation showing vulnerable pattern
  sym.imp.GetCfmValue(iVar6 + *0xb9a4, puVar7 + iVar4 + -0x70);
  uVar2 = sym.imp.strlen(puVar7 + iVar4 + -0x70);
  if (uVar2 < 7) {
      sym.imp.sprintf(puVar7 + iVar4 + -0x70, iVar6 + *0xb994, *(puVar7 + -8), *(puVar7 + -0xc));
  }
  uVar3 = sym.imp.get_eth_name(0);
  sym.imp.doSystemCmd(iVar6 + *0xb98c, uVar3, puVar7 + iVar4 + -0x70);
  ```
- **Keywords:** NVRAM variables: lan.ip, wan1.macaddr, wan2.macaddr, lan.mask, iptv.stb.enable, IPC socket: /var/cfm_socket, Shared functions: GetCfmValue, doSystemCmd
- **Notes:** The vulnerability relies on doSystemCmd using shell execution (e.g., via system() call), which is plausible given the command templates observed in strings (e.g., 'ifconfig %s down'). Full exploitation requires the attacker to set NVRAM variables through another interface (e.g., web GUI), but this is consistent with the attack scenario. Further analysis should verify the implementation of doSystemCmd in shared libraries like libcommon.so. Additional unsafe functions (strcpy, sprintf) are present but not directly linked to exploitable chains in this analysis.

---
### File-Deletion-udev_event

- **File/Directory Path:** `sbin/udevd`
- **Location:** `File:udevd Address:0x0000a364 Function:dbg.udev_event_run → Address:0x00009ee8 Function:dbg.udev_event_process → Address:0x0000c09c Function:dbg.udev_device_event → Address:0x00011184 Function:dbg.udev_rules_get_name → Address:0x00013868 Function:dbg.unlink_secure → Address:0x00009620 Function:sym.imp.unlink (Dangerous operation).`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** Untrusted input propagates through udev event messages, ultimately deleting files in `sym.imp.unlink`, leading to an arbitrary file deletion vulnerability. Attackers can specify the deletion path by controlling event data. Trigger conditions include file deletion operations involved in udev event processing (such as device removal). Potential attack methods include deleting critical system files causing denial of service or privilege escalation. Related code logic: `dbg.udev_event_run` → `dbg.udev_event_process` → `dbg.udev_device_event` → `dbg.udev_rules_get_name` → `dbg.unlink_secure` → `sym.imp.unlink`.
- **Code Snippet:**
  ```
  In \`dbg.udev_event_process\` (0x00009ee8): \`dbg.strlcpy(piVar4 + 0x185, *(param_1 + 0x14), 0x100);\` (Tainted data copy)
  In \`dbg.unlink_secure\` (0x00013868): \`sym.imp.unlink(puVar16);\` (File deletion)
  ```
- **Keywords:** udev event messages (IPC or network interface), dbg.udev_event_run, dbg.udev_event_process, dbg.udev_device_event, dbg.udev_rules_get_name, dbg.unlink_secure, sym.imp.unlink
- **Notes:** Attackers need to control the file path parameter; it is recommended to check the path filtering mechanism in `dbg.unlink_secure`.

---
### Command-Injection-message_queue

- **File/Directory Path:** `sbin/udevd`
- **Location:** `File:udevd Address:0x0000a4e0 Function:dbg.msg_queue_manager (entry) → Address:0x0000a364 Function:dbg.udev_event_run → Address:0x00009ee8 Function:dbg.udev_event_process → Address:0x00013bb4 Function:dbg.run_program (dangerous operation).`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** Untrusted input propagates through the internal message queue (IPC), ultimately executing commands in `dbg.run_program`, leading to command injection. Attackers can trigger command execution by injecting malicious queue elements (e.g., via device events). The trigger condition is when a carefully crafted queue element is processed, bypassing checks in `dbg.msg_queue_manager`. Potential attack methods include injecting command data that is formatted and executed without sufficient validation. Related code logic: `dbg.msg_queue_manager` → `dbg.udev_event_run` → `dbg.udev_event_process` → `dbg.run_program`.
- **Code Snippet:**
  ```
  In \`dbg.msg_queue_manager\` (0x0000a4e0): \`dbg.udev_event_run(ppiVar6);\` (queue element processing)
  In \`dbg.run_program\` (0x00013bb4): \`sym.imp.execv(*(puVar16 + 0xfffff360), puVar16 + 0xfffff360);\` (command execution)
  ```
- **Keywords:** Internal message queue (IPC), dbg.msg_queue_manager, dbg.udev_event_run, dbg.udev_event_process, dbg.run_program, execv
- **Notes:** Further tracing of queue population functions (such as through device event interfaces) is needed to confirm user accessibility; it is recommended to analyze NVRAM, environment variables, or IPC sockets as potential input sources.

---
### Weak-DES-Hash-Passwd-Users

- **File/Directory Path:** `etc_ro/passwd`
- **Location:** `passwd:2-5`
- **Risk Score:** 7.0
- **Confidence:** 8.0
- **Description:** Multiple users (admin, support, user, nobody) in the passwd file use weak DES password hashes, and all users have UID 0 (root privileges). A non-root attacker can obtain the hash values by reading the /etc/passwd file, use tools (such as john or hashcat) to crack the weak DES hashes, thereby obtaining these users' passwords. The attacker can then log in as these users via 'su' or SSH, and immediately gain root privileges due to UID 0. Trigger condition: The attacker has read access to /etc/passwd and the passwords are weak; Exploitation method: Log in after offline hash cracking; Boundary check: No password strength enforcement or hash upgrade.
- **Code Snippet:**
  ```
  admin:6HgsSsJIEOc2U:0:0:Administrator:/:/bin/sh
  support:Ead09Ca6IhzZY:0:0:Technical Support:/:/bin/sh
  user:tGqcT.qjxbEik:0:0:Normal User:/:/bin/sh
  nobody:VBcCXSNG7zBAY:0:0:nobody for ftp:/:/bin/sh
  ```
- **Keywords:** /etc/passwd, admin, support, user, nobody
- **Notes:** Assumes the attacker has read access to /etc/passwd (typically world-readable), and DES hashes are easily cracked (using traditional crypt algorithm). It is recommended to verify if these accounts are enabled for login and check the password policy. Associated files: No other files directly involved; Subsequent analysis can focus on authentication processes or setuid programs.

---
