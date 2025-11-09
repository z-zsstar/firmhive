# TX-VG1530 (25 findings)

---

### File-Permission-sa2

- **File/Directory Path:** `usr/lib/sa/sa2`
- **Location:** `sa2:1 (Entire file, permission settings)`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** The file 'sa2' has global read, write, and execute permissions (-rwxrwxrwx), allowing any user (including non-root users) to modify the script's content. If the script is executed by the system with higher privileges (such as root) (e.g., via a cron job), a non-root user can gain root privileges by inserting malicious code (such as 'rm -rf /' or a reverse shell). The trigger condition is a non-root user modifying the script and waiting for the scheduled task to execute; the constraint is that the script must be invoked with root privileges, which is common in typical sysstat setups. Potential attack methods include directly editing the script to add malicious commands, which is simple and reliable.
- **Code Snippet:**
  ```
  File permissions: -rwxrwxrwx
  Partial script content:
  #!/bin/sh
  # /usr/lib/sa/sa2
  ...
  ${ENDIR}/sar $* -f ${DFILE} > ${RPT}
  ...
  ```
- **Keywords:** /usr/lib/sa/sa2
- **Notes:** This vulnerability relies on the script being executed with higher privileges; it is recommended to check system cron jobs (such as /etc/cron.d/sysstat) to confirm the execution context. The attack chain is complete and verifiable: non-root user modifies script -> cron executes as root -> privilege escalation. There are no other obvious entry points (such as command-line arguments or environment variables) that could directly lead to injection, because the parameters are passed to the 'sar' command and are not quoted, but 'sar' might handle them safely; configuration files are not writable, so they do not pose a direct threat.

---
### Config-DefaultAdminCredentials

- **File/Directory Path:** `etc/default_config.xml`
- **Location:** `default_config.xml (in the Services.StorageService.UserAccount instance=1 section)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** Default administrator credentials (Username: admin, Password: admin) are configured in the StorageService section. Attackers (non-root users who already possess valid login credentials) may use these credentials to log into the management interface, elevate privileges to super user (X_TP_SupperUser val=1), and thereby perform dangerous operations such as modifying system configurations, enabling services, or accessing sensitive data. Trigger conditions include the management interface being accessible and the credentials not being changed. Potential exploitation methods include privilege escalation and complete system control.
- **Code Snippet:**
  ```
  <UserAccount instance=1 >
    <Enable val=1 />
    <Username val=admin />
    <Password val=admin />
    <X_TP_Reference val=0 />
    <X_TP_SupperUser val=1 />
  </UserAccount>
  ```
- **Keywords:** StorageService.UserAccount.instance=1.Username, StorageService.UserAccount.instance=1.Password, StorageService.UserAccount.instance=1.X_TP_SupperUser
- **Notes:** Evidence clearly shows default credentials. The attack chain requires verification of the management interface's accessibility, but assuming the attacker is already connected to the device, exploitation may occur from the internal network. It is recommended to check other files (such as web interface scripts) to confirm the attack path.

---
### BufferOverflow-Midware_cli_insert_entry

- **File/Directory Path:** `usr/lib/libmidware_mipc_client.so`
- **Location:** `libmidware_mipc_client.so:0x1838 (Midware_cli_insert_entry), strcpy calls at 0x186c and 0x1898`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** Buffer overflow vulnerability in `Midware_cli_insert_entry` function due to unsafe use of `strcpy` on user-controlled inputs `name` and `arg` without bounds checking. The function copies these inputs to fixed-size stack buffers (256 bytes each) using `strcpy`, which does not validate length. If `name` or `arg` exceed 255 bytes (plus null terminator), it will overflow the buffer, corrupting the stack. This can overwrite saved registers, including the return address, leading to arbitrary code execution. The function is exposed via CLI or IPC interfaces, and an authenticated non-root user can trigger this by providing overly long strings. The vulnerability is triggered when the function is called with long inputs, and exploitation involves crafting input to overwrite the return address and execute shellcode.
- **Code Snippet:**
  ```
  if (*(puVar2 + -0x20c) != 0) {
      sym.imp.strcpy(puVar2 + iVar1 + -0x208, *(puVar2 + -0x20c)); // Copies 'name' to stack buffer
  }
  ...
  if (*(puVar2 + -0x214) != 0) {
      sym.imp.strcpy(puVar2 + 4 + -0x104, *(puVar2 + -0x214)); // Copies 'arg' to stack buffer
  }
  ```
- **Keywords:** Midware_cli_insert_entry, name, arg, mipc_send_cli_msg
- **Notes:** This finding is based on decompilation evidence from Radare2. The function lacks any length checks on inputs before copying. Similar vulnerabilities likely exist in other CLI functions (e.g., `Midware_cli_update_entry`, `Midware_cli_remove_entry`) due to repeated `strcpy` usage. Further analysis should verify the exact stack layout and potential mitigations (e.g., stack canaries), but the absence of bounds checking makes exploitation feasible. Recommend testing with long inputs to confirm crash and code execution.

---
### BufferOverflow-omci_api_call

- **File/Directory Path:** `usr/lib/libomci_mipc_client.so`
- **Location:** `libomci_mipc_client.so:0x0000524c dbg.omci_api_call`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** The function 'dbg.omci_api_call' contains a buffer overflow vulnerability due to the use of 'memcpy' without bounds checking. The function copies data from 'param_2' (user-controlled input) to a stack buffer of fixed size (2048 bytes) using 'param_3' (length) without validating if 'param_3' exceeds the buffer size. This can lead to stack-based buffer overflow, allowing an attacker to overwrite return addresses and execute arbitrary code. The function is central to API handling and is called with untrusted data from IPC or CLI sources. An attacker with login credentials could craft a malicious IPC message or API call with a large 'param_3' to trigger the overflow. The vulnerability is triggered when 'param_2' is non-null and 'param_3' is larger than 2048 bytes.
- **Code Snippet:**
  ```
  sym.imp.memcpy(puVar2 + 0 + -0x800, *(puVar2 + *0x53c4 + 4), *(puVar2 + *0x53c8 + 4));
  ```
- **Keywords:** omci_api_call, mipc_send_sync_msg
- **Notes:** The vulnerability is directly in the code and can be exploited if the calling process passes untrusted input. Further analysis of callers is needed to confirm the full attack chain, but the library's use in IPC and CLI contexts makes exploitation likely. Recommend analyzing processes that use this library for input validation flaws.

---
### DHCPv6-StackOverflow-fcn.0001a284

- **File/Directory Path:** `usr/sbin/dhcp6s`
- **Location:** `dhcp6s:0x0001ae70 fcn.0001a284`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** In the fcn.0001a284 function of the dhcp6s binary, there is a stack buffer overflow vulnerability when processing DHCPv6 option type 5 (Request Option). An attacker can send a specially crafted DHCPv6 packet over the network with option type 5 and the length field (r8) set to a large even value (e.g., >= 10) to trigger the vulnerability. The code first checks if the option length is even, then right-shifts by one to get the number of items, but does not perform bounds checking on the item count. In the loop, memcpy is used to copy 2 bytes of data each time to the stack buffer var_194h (which only has 8 bytes of space). When the number of items exceeds 4, it overflows the stack frame, overwriting the return address or critical variables. An attacker can carefully craft the option data to control the overflow content, hijack the control flow, and achieve arbitrary code execution. Trigger condition: The attacker is connected to the device and has valid login credentials (non-root user), sending a malicious DHCPv6 packet to the dhcp6s service. Exploitation method: By overwriting the return address, jumping to shellcode or a ROP chain, it may be possible to escalate privileges (since dhcp6s may run with root privileges).
- **Code Snippet:**
  ```
  0x0001ae14      000058e3       cmp r8, 0                   ; Check option length
  0x0001ae18      0830a011       movne r3, r8
  0x0001ae1c      01308803       orreq r3, r8, 1
  0x0001ae20      010013e3       tst r3, 1                   ; Check if even
  0x0001ae24      1101001a       bne 0x1b270                 ; If not, jump to error handling
  0x0001ae28      c880b0e1       asrs r8, r8, 1             ; Right shift by one, get item count
  0x0001ae2c      54feff0a       beq 0x1a784                 ; If 0, skip loop
  ...
  0x0001ae70      650f8de2       add r0, var_194h            ; Destination buffer address
  0x0001ae74      0510a0e1       mov r1, r5                  ; Source data pointer
  0x0001ae78      0220a0e3       mov r2, 2                   ; Copy 2 bytes
  0x0001ae7c      020080e2       add r0, r0, 2               ; Increment destination address
  0x0001ae80      c6d8ffeb       bl sym.imp.memcpy           ; Execute copy
  0x0001ae64      025085e2       add r5, r5, 2               ; Increment source pointer
  0x0001ae68      060055e1       cmp r5, r6                  ; Check loop condition
  0x0001ae6c      44feff0a       beq 0x1a784                 ; End loop
  ```
- **Keywords:** DHCPv6 Option Type 5, var_194h (stack buffer), r8 (option length register), sym.imp.memcpy
- **Notes:** The vulnerability is located in the DHCPv6 option processing logic of dhcp6s, with the input point being recvmsg from the network. The attack chain is complete: from untrusted network input to dangerous operation (memcpy overflow). It is necessary to verify if dhcp6s runs with root privileges (common for DHCP servers); if not, exploitation may be limited. Subsequent testing is recommended for actual exploitation, including crafting packets and checking mitigation measures (such as ASLR, stack protection). Related function: fcn.0001411c (main message processing) calls fcn.0001a284.

---
### BufferOverflow-iptvCliMgShowAll_mipc

- **File/Directory Path:** `usr/lib/libigmp_mipc_client.so`
- **Location:** `libigmp_mipc_client.so:0x1910 in dbg.iptvCliMgShowAll_mipc`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** The function iptvCliMgShowAll_mipc uses strcpy to copy a user-controlled string (passed as an argument) into a fixed-size stack buffer without any bounds checking. This occurs in the code at address 0x1910, where strcpy is called with the source directly from the function argument and the destination as a local stack buffer. The stack buffer is allocated with a size of approximately 288 bytes, but the specific destination buffer is at an offset that allows overflow after 268 bytes, enabling overwrite of the saved return address at fp+4. An attacker with CLI access can trigger this by providing a long string as the argument, leading to stack buffer overflow and potential arbitrary code execution. The vulnerability is directly exploitable due to the lack of input validation and the attacker's ability to control the input via CLI commands.
- **Code Snippet:**
  ```
  0x000018f4      10311be5       ldr r3, [src]               ; igmp_mipc_client.c:288 ; 0x110
  0x000018f8      000053e3       cmp r3, 0
  0x000018fc      0400000a       beq 0x1914
  0x00001900      10311be5       ldr r3, [src]               ; igmp_mipc_client.c:289 ; 0x110
  0x00001904      412f4be2       sub r2, dest
  0x00001908      0200a0e1       mov r0, r2                  ; char *dest
  0x0000190c      0310a0e1       mov r1, r3                  ; const char *src
  0x00001910      d8fcffeb       bl sym.imp.strcpy           ; char *strcpy(char *dest, const char *src)
  ```
- **Keywords:** iptvCliMgShowAll_mipc, mipc_send_cli_msg, strcpy
- **Notes:** This finding is representative of multiple similar vulnerabilities in other CLI functions (e.g., iptvCliMgShowValid_mipc, iptvCliHostShowAll_mipc) that also use strcpy without bounds checking. The exploitability depends on the attacker having access to invoke these CLI commands, which is plausible given the user context. Further analysis could involve tracing the data flow from input sources to these functions, but the current evidence supports a viable attack chain. Additional functions using memcpy or other dangerous operations should be investigated for completeness.

---
### BufferOverflow-oam_cli_cmd_voip_sip_user_config_set

- **File/Directory Path:** `usr/lib/liboam_mipc_client.so`
- **Location:** `liboam_mipc_client.so:0x000051f0 oam_cli_cmd_voip_sip_user_config_set`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** Function `oam_cli_cmd_voip_sip_user_config_set` contains multiple stack buffer overflow vulnerabilities due to the use of `strcpy` without input length validation. The function copies up to five user-controlled parameters (param_1 to param_4) into fixed-size stack buffers (each 256 bytes). If any parameter exceeds 256 bytes, `strcpy` will overflow the buffer, overwriting adjacent stack data including saved registers and return addresses. Trigger condition: An authenticated user executes a CLI command with parameters longer than 256 bytes. Potential attack: By carefully crafting long strings, an attacker can overwrite the return address to control program execution flow, leading to arbitrary code execution. The function uses `mipc_send_cli_msg` to send messages after copying, but the overflow occurs locally before any IPC communication.
- **Code Snippet:**
  ```
  if (*(puVar2 + -0x50c) != 0) {
      sym.imp.strcpy(puVar2 + 4 + -0x508, *(puVar2 + -0x50c));
  }
  if (*(puVar2 + -0x514) != 0) {
      sym.imp.strcpy(puVar2 + 4 + -0x404, *(puVar2 + -0x514));
  }
  if (*(puVar2 + -0x518) != 0) {
      sym.imp.strcpy(puVar2 + 4 + -0x304, *(puVar2 + -0x518));
  }
  if (*(puVar2 + 8) != 0) {
      sym.imp.strcpy(puVar2 + 4 + -0x204, *(puVar2 + 8));
  }
  if (*(puVar2 + 0xc) != 0) {
      sym.imp.strcpy(puVar2 + 4 + -0x104, *(puVar2 + 0xc));
  }
  ```
- **Keywords:** param_1, param_2, param_3, param_4, mipc_send_cli_msg
- **Notes:** The vulnerability is confirmed through decompilation, but the full attack chain depends on external factors: the function must be accessible to authenticated users via CLI or IPC, and the system must lack stack protection (e.g., stack canaries). Further analysis should verify the calling context in components like CLI handlers and check for mitigations. This function is a high-priority target due to multiple input points.

---
### Command-Injection-upnpd-UPnP

- **File/Directory Path:** `usr/bin/upnpd`
- **Location:** `fcn.00016694:0x166a4 (system call), fcn.00018380:0x183bc (system call), Possible event handler functions such as fcn.00017ac0`
- **Risk Score:** 8.5
- **Confidence:** 7.5
- **Description:** In the 'upnpd' binary, a potential command injection vulnerability chain was discovered. Attackers can inject commands by sending malicious UPnP requests (such as AddPortMapping or DeletePortMapping). Specifically, function fcn.00016694 directly calls the 'system' function, and its parameter param_1 may come from external input and is unvalidated. Furthermore, function fcn.00018380 uses snprintf to construct a command string before calling 'system', but the input source may not be sufficiently filtered. UPnP requests are received via the network interface and, after parsing, are passed to these functions. An attacker, as an authenticated non-root user, can craft specialized requests, embedding shell metacharacters (such as ';', '|', or '`') in the parameters, thereby executing arbitrary commands. Trigger conditions include sending UPnP SOAP requests containing malicious parameters. Exploitation methods may include injecting commands in fields like 'NewPortMappingDescription' or similar, leading to privilege escalation or device control.
- **Code Snippet:**
  ```
  // fcn.00016694 code snippet
  uint fcn.00016694(uint param_1) {
      int32_t iVar1;
      iVar1 = sym.imp.system(param_1); // Direct call to system, param_1 may come from external input
      // ...
  }
  
  // fcn.00018380 code snippet (partial)
  sym.imp.snprintf(piVar6 + -0xb, 0x20, *0x18708, *0x1870c); // Construct command string
  iVar1 = sym.imp.system(piVar6 + -0xb); // Execute system command
  // Similar pattern repeated elsewhere
  ```
- **Keywords:** NewPortMappingDescription, NewInternalClient, NewProtocol, /var/tmp/upnpd/pm.db, urn:upnp-org:serviceId:WANIPConn1
- **Notes:** Evidence is based on static analysis, showing 'system' calls associated with potential external input. However, dynamic validation is required to confirm the input source and exploitability. Further analysis of UPnP request parsing functions (such as fcn.00017ac0) and data flow is recommended. Related files include /var/tmp/upnpd/pm.db (port mapping database) and configuration file /var/tmp/upnpd/upnpd.conf. The attack chain may involve multiple components, including XML parsing and action handling.

---
### command-injection-fcn.00013094

- **File/Directory Path:** `usr/bin/voip`
- **Location:** `voip:0x13094 fcn.00013094 (multiple addresses: 0x134e0, 0x135d0, 0x136e0, 0x1381c, 0x139a8, 0x13b04, 0x13c64)`
- **Risk Score:** 8.5
- **Confidence:** 7.5
- **Description:** The vulnerability arises from the handling of IPC messages in the voip process. IPC messages received via mipc_receive_msg are processed in fcn.00015194, which dispatches to various functions based on message ID. Cases 1 and 2 call fcn.00013d5c and fcn.00013eb8, respectively, which in turn call fcn.00013094. fcn.00013094 constructs shell commands using sprintf and strcat with parameters derived directly from IPC messages (e.g., IP addresses, netmasks, gateways) and executes them via system calls. The lack of input sanitization allows command injection if an attacker controls these parameters. For example, parameters like IP addresses could contain shell metacharacters (e.g., ';' or '|') to inject additional commands. The trigger condition is sending a crafted IPC message with malicious data to the voip process, which is accessible to authenticated users.
- **Code Snippet:**
  ```
  // Example from fcn.00013094 showing command construction and system call
  sym.imp.sprintf(piVar6 + -0x14, *0x13d28, piVar6[-0x9b]);  // Format string with parameter
  sym.imp.strcat(piVar6 + -0x25c, piVar6 + -0x14);          // Append to command buffer
  iVar1 = sym.imp.system(piVar6 + -0x25c);                   // Execute command
  ```
- **Keywords:** mipc_receive_msg, mipc_response_msg, VOIP_setGlobalParam_F, VOIP_updateHostIpAddr_F, voice_ip_mode, iad_ip_addr, iad_net_mask, iad_def_gw
- **Notes:** The vulnerability requires further validation through dynamic testing to confirm exploitability. The attack chain involves IPC communication, which may have access controls. Assumed that authenticated users can send IPC messages to the voip process. Recommended to analyze the IPC mechanism and message structure for precise exploitation. Related functions: fcn.00013d5c, fcn.00013eb8, fcn.00015194, fcn.00015c9c.

---
### BufferOverflow-I2c_cli_show_xvr_a2d_values

- **File/Directory Path:** `usr/lib/libi2c_mipc_client.so`
- **Location:** `libi2c_mipc_client.so:0x990 I2c_cli_show_xvr_a2d_values`
- **Risk Score:** 8.5
- **Confidence:** 7.5
- **Description:** The function I2c_cli_show_xvr_a2d_values contains a stack-based buffer overflow vulnerability due to the use of strcpy without bounds checking. The function copies the input parameter 'param_1' directly into a fixed-size stack buffer (248 bytes) using strcpy. If 'param_1' is longer than 248 bytes, it will overflow the buffer, potentially overwriting the return address and allowing arbitrary code execution. The function is called via CLI commands through IPC (mipc_send_cli_msg), and since the attacker has valid login credentials, they can trigger this function with a maliciously long input. The lack of stack canaries or other mitigations in the binary increases the exploitability.
- **Code Snippet:**
  ```
  if (*(puVar2 + -0x10c) != 0) {
      sym.imp.strcpy(puVar2 + iVar1 + -0x104, *(puVar2 + -0x10c));
  }
  ```
- **Keywords:** param_1, mipc_send_cli_msg
- **Notes:** The input source 'param_1' is likely controlled via CLI commands. Further analysis is needed to trace the exact data flow from user input to this function. The binary lacks stack canaries based on r2 analysis, but ASLR might be enabled on the system, which could affect exploit reliability.

---
### BufferOverflow-I2c_cli_show_xvr_thresholds

- **File/Directory Path:** `usr/lib/libi2c_mipc_client.so`
- **Location:** `libi2c_mipc_client.so:0xa2c I2c_cli_show_xvr_thresholds`
- **Risk Score:** 8.5
- **Confidence:** 7.5
- **Description:** The function I2c_cli_show_xvr_thresholds exhibits the same stack-based buffer overflow vulnerability as I2c_cli_show_xvr_a2d_values. It uses strcpy to copy 'param_1' into a 248-byte stack buffer without bounds checking. An attacker with CLI access can provide a long input to overflow the buffer and potentially execute arbitrary code. The function is part of IPC communication via mipc_send_cli_msg.
- **Code Snippet:**
  ```
  if (*(puVar2 + -0x10c) != 0) {
      sym.imp.strcpy(puVar2 + iVar1 + -0x104, *(puVar2 + -0x10c));
  }
  ```
- **Keywords:** param_1, mipc_send_cli_msg
- **Notes:** Similar to I2c_cli_show_xvr_a2d_values, this function is vulnerable. The consistency across multiple CLI functions suggests a pattern of insecure coding. Verification of the input context is recommended.

---
### BufferOverflow-I2c_cli_show_xvr_alarms_and_warnings

- **File/Directory Path:** `usr/lib/libi2c_mipc_client.so`
- **Location:** `libi2c_mipc_client.so:0xac8 I2c_cli_show_xvr_alarms_and_warnings`
- **Risk Score:** 8.5
- **Confidence:** 7.5
- **Description:** The function I2c_cli_show_xvr_alarms_and_warnings also contains a stack-based buffer overflow due to strcpy without bounds checking. The input 'param_1' is copied into a 248-byte stack buffer, and overflow can lead to code execution. This function is accessible via CLI commands through IPC.
- **Code Snippet:**
  ```
  if (*(puVar2 + -0x10c) != 0) {
      sym.imp.strcpy(puVar2 + iVar1 + -0x104, *(puVar2 + -0x10c));
  }
  ```
- **Keywords:** param_1, mipc_send_cli_msg
- **Notes:** This function follows the same vulnerable pattern. Analysis of I2c_cli_show_xvr_inventory and I2c_cli_show_xvr_capability reveals identical issues, indicating widespread insecurity in the library.

---
### Untitled Finding

- **File/Directory Path:** `usr/lib/libpm_mipc_client.so`
- **Location:** `libpm_mipc_client.so:0x1370 dbg.Apm_cli_set_pm_interval`
- **Risk Score:** 8.5
- **Confidence:** 7.5
- **Description:** A stack buffer overflow vulnerability exists in the function dbg.Apm_cli_set_pm_interval. Due to the use of the strcpy function to copy the user-controlled parameter param_1 into a fixed-size stack buffer (estimated 256 bytes) without length validation, an attacker can overwrite the return address, frame pointer, or other critical data on the stack by providing a string larger than the buffer size, leading to arbitrary code execution. Trigger condition: An attacker (a non-root user with valid login credentials) can invoke this function via CLI command or IPC interface and control the param_1 parameter (e.g., by passing a long string). Exploitation method: Craft a long string containing shellcode or overwrite the return address to jump to attacker-controlled code, thereby escalating privileges or performing malicious actions. The vulnerability lacks bounds checking, only verifying that param_1 is non-zero but not checking its length, allowing an attacker to easily trigger the overflow.
- **Code Snippet:**
  ```
  uchar dbg.Apm_cli_set_pm_interval(uint param_1,uint param_2) { ... if (puVar2[-0x42] != 0) { sym.imp.strcpy(puVar2 + -0x100, puVar2[-0x42]); } ... }
  ```
- **Keywords:** dbg.Apm_cli_set_pm_interval, param_1, strcpy, mipc_send_cli_msg, Apm_cli_set_pm_interval
- **Notes:** Buffer size and stack layout require further verification (e.g., using a debugger to confirm the overflow point); the function may be called via IPC or CLI commands, requiring the attacker to have permissions; it is recommended to analyze the calling context (such as network services or CLI handlers) and perform practical tests for exploitability; associated files may include components that call this function (such as apm or network daemons).

---
### BufferOverflow-zread_ipv4_add

- **File/Directory Path:** `usr/sbin/zebra`
- **Location:** `zebra:0x0001250c dbg.zread_ipv4_add`
- **Risk Score:** 8.5
- **Confidence:** 7.5
- **Description:** A buffer overflow vulnerability exists in the zread_ipv4_add function when handling IPv4 route addition requests from clients. The function reads a prefix length value (iVar5) from the client stream, which is attacker-controlled, and uses it to calculate the size for reading data into a fixed-size stack buffer (auStack_1c, 28 bytes). The calculation (iVar5 + 7) >> 3 can result in a size of up to 32 bytes when iVar5 is 255, causing a 4-byte overflow. This overflow can overwrite saved registers or the return address on the stack, potentially leading to arbitrary code execution. The vulnerability is triggered when a client sends a message of type 6 (IPv4 add) with a crafted large prefix length value. As zebra typically runs with root privileges to manage kernel routing tables, successful exploitation could grant root access to the attacker.
- **Code Snippet:**
  ```
  iVar5 = dbg.stream_getc(uVar7);
  dbg.stream_get(puVar11 + -0xc, uVar7, iVar5 + 7U >> 3);
  ```
- **Keywords:** client stream data, iVar5 (prefix length field), IPC socket for zebra communication
- **Notes:** The vulnerability was identified through static analysis using Radare2 decompilation. The exact stack layout and exploitability would benefit from dynamic analysis or further verification. Additional input points like other zread_* functions or netlink handlers should be examined for similar issues. The IPC socket path for zebra is not hardcoded in the binary but is typically configured in system files, which should be identified for complete attack chain validation.

---
### strcpy-stack-overflow-fcn.0001e05c

- **File/Directory Path:** `usr/bin/vsftpd`
- **Location:** `vsftpd:0x1e0b0 fcn.0001e05c`
- **Risk Score:** 8.0
- **Confidence:** 8.5
- **Description:** Function fcn.0001e05c calls strcpy at addresses 0x1e0b0 and 0x1e138, similarly lacking bounds checking. This function processes user input or configuration data, likely triggered via FTP commands such as USER or PASS. An attacker can cause a buffer overflow by sending an overly long username or password. Trigger condition: The attacker is authenticated and can send malicious FTP commands; input data must exceed the buffer size. Exploitation methods include overwriting the return address or function pointers on the stack.
- **Code Snippet:**
  ```
  0x0001e0b0      bl sym.imp.strcpy           ; char *strcpy(char *dest, const char *src)
  0x0001e138      bl sym.imp.strcpy           ; char *strcpy(char *dest, const char *src)
  ```
- **Keywords:** USER, PASS
- **Notes:** FTP command processing is a common attack vector. The actual input length limit and buffer size need to be tested. May be affected by vsftpd configuration (e.g., max_clients).

---
### StackOverflow-client6_recv

- **File/Directory Path:** `usr/sbin/dhcp6c`
- **Location:** `dhcp6c:0x000196a0 client6_recv (specifically in the case 0xfc processing section)`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** When processing DHCPv6 message type 252 (0xfc) in the client6_recv function, an insecure string copy operation (strncpy but missing length parameter restriction) is used to copy network data into a fixed-size stack buffer (256 bytes). Due to the lack of input length validation, an attacker can send string data longer than 256 bytes, causing a stack buffer overflow. The overflow may overwrite the return address or other critical stack data, allowing remote code execution. Trigger conditions include: the attacker possesses valid login credentials (non-root user) and can send a specially crafted DHCPv6 message to the target device. Potential exploitation methods include controlling network input to overwrite the return address, executing arbitrary shellcode, or jumping to malicious code. Constraints include insufficient message length checks (uVar12 should equal 15, but the condition allows other values), and the copy operation does not use a length parameter restriction.
- **Code Snippet:**
  ```
  case 0xfc:
      iVar7 = puVar17 + -0x17c;  // Points to stack buffer auStack_1a0 [256]
      sym.imp.memset(iVar7, 0, 0x100);  // Clear 256-byte buffer
      sym.imp.strncpy(iVar7, puVar9);   // Insecure copy of network data puVar9, missing length parameter
      iVar4 = sym.imp.strlen(iVar7);    // Get string length
      *(puVar17 + -0x20) = iVar7;
      *(puVar17 + -0x24) = iVar4 + 1;
      // Subsequent call to fcn.00017e04
  ```
- **Keywords:** DHCPv6 message input (type 252), sym.imp.strncpy, client6_recv function, stack buffer auStack_1a0
- **Notes:** The stack buffer overflow vulnerability requires further validation of the stack layout (such as return address offset) to confirm exploitability. The attacker must be able to send DHCPv6 messages, possibly through a local network interface. Dynamic testing is recommended to reproduce the vulnerability. The associated function fcn.00017e04 may involve subsequent processing, but no additional vulnerabilities were found.

---
### BufferOverflow-oam_cli_cmd_set_onu_loid

- **File/Directory Path:** `usr/lib/liboam_mipc_client.so`
- **Location:** `liboam_mipc_client.so:0x00003234 oam_cli_cmd_set_onu_loid`
- **Risk Score:** 7.5
- **Confidence:** 9.0
- **Description:** Function `oam_cli_cmd_set_onu_loid` uses `strcpy` to copy three user-controlled parameters into fixed-size stack buffers (256 bytes each) without bounds checks. If any parameter length exceeds 256 bytes, a buffer overflow occurs, potentially overwriting the return address. Trigger condition: An authenticated user provides long strings via CLI commands. Potential attack: Overflow can lead to arbitrary code execution by hijacking the return address. The function calls `mipc_send_cli_msg` after copying, but the overflow happens locally.
- **Code Snippet:**
  ```
  if (*(puVar2 + -0x30c) != 0) {
      sym.imp.strcpy(puVar2 + iVar1 + -0x304, *(puVar2 + -0x30c));
  }
  if (*(puVar2 + -0x310) != 0) {
      sym.imp.strcpy(puVar2 + 4 + -0x204, *(puVar2 + -0x310));
  }
  if (*(puVar2 + -0x314) != 0) {
      sym.imp.strcpy(puVar2 + 4 + -0x104, *(puVar2 + -0x314));
  }
  ```
- **Keywords:** param_1, param_2, param_3, mipc_send_cli_msg
- **Notes:** The stack layout suggests the buffers are adjacent, increasing the risk of overwriting critical data. Exploitability is high if the function is exposed to user input. Recommend analyzing the CLI interface to confirm accessibility.

---
### BufferOverflow-omci_cli_debug_set_frame_dump

- **File/Directory Path:** `usr/lib/libomci_mipc_client.so`
- **Location:** `libomci_mipc_client.so:0x00001c80 dbg.omci_cli_debug_set_frame_dump`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** Multiple CLI functions (e.g., 'dbg.omci_cli_debug_set_frame_dump') use 'strcpy' to copy input strings to fixed-size stack buffers without bounds checking, leading to buffer overflows. For instance, 'dbg.omci_cli_debug_set_frame_dump' copies 'param_1' (a string) to a 256-byte stack buffer using 'strcpy'. If 'param_1' is longer than 256 bytes, it overflows the buffer, potentially allowing code execution. These functions are invoked via CLI commands, and an attacker with login credentials can provide crafted long strings to trigger the overflow. The vulnerability is triggered when the input string exceeds the buffer size, and the function sends the data via IPC using 'mipc_send_cli_msg'.
- **Code Snippet:**
  ```
  if (puVar2[-0x42] != 0) {
      sym.imp.strcpy(puVar2 + -0x100, puVar2[-0x42]);
  }
  ```
- **Keywords:** omci_cli_debug_set_frame_dump, mipc_send_cli_msg
- **Notes:** This vulnerability affects numerous CLI functions (over 70 instances of 'strcpy' found). Exploitation depends on CLI accessibility to non-root users. Recommend reviewing command injection points in system services that use these functions.

---
### command-injection-hotplug

- **File/Directory Path:** `sbin/hotplug`
- **Location:** `hotplug:0x10db8 system_call`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** A potential command injection vulnerability was discovered in the 'hotplug' program. The program obtains input from the environment variable 'ACTION' and, when processing 'remove' events, uses 'snprintf' to construct a command string, which is then executed via the 'system' function. The environment variable 'ACTION' is a user-controllable input point, but the program does not perform adequate validation or filtering of the input, allowing an attacker to inject malicious commands to execute arbitrary code. Trigger condition: When a hotplug event triggers a 'remove' action, the program executes the constructed command. Exploitation method: An attacker can set the 'ACTION' environment variable to a value containing shell metacharacters (such as ';', '|', or '`'), thereby injecting and executing arbitrary commands.
- **Code Snippet:**
  ```
  0x00010db8      9bfeffeb       bl sym.imp.system           ; int system(const char *string)
  ...
  0x00010d90      40019fe5       ldr r0, str.ACTION          ; [0x10dd8:4]=0x11060 str.ACTION
  0x00010d94      6cfeffeb       bl sym.imp.getenv           ; char *getenv(const char *name)
  0x00010d98      10000be5       str r0, [fp, -0x10]         ; 16
  0x00010d9c      10301be5       ldr r3, [fp, -0x10]         ; 16
  0x00010da0      000053e3       cmp r3, 0
  0x00010da4      0100001a       bne 0x10db0
  ...
  0x00010db0      492f4be2       sub r2, fp, 0x124
  0x00010db4      24104be2       sub r1, fp, -0x24
  0x00010db8      9bfeffeb       bl sym.imp.system           ; int system(const char *string)
  ```
- **Keywords:** ACTION
- **Notes:** Exploiting this vulnerability requires the attacker to be able to control the environment variable 'ACTION', which might be achieved through a logged-in user or network request. It is recommended to further verify how the environment variable is set and the program's execution context to confirm exploitability. Associated files may include startup scripts or network service components.

---
### strcpy-stack-overflow-fcn.0001bf54

- **File/Directory Path:** `usr/bin/vsftpd`
- **Location:** `vsftpd:0x1c1cc fcn.0001bf54`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** In the fcn.0001bf54 function of vsftpd, at address 0x1c1cc, strcpy is used to copy data without boundary checks. The target buffer is a local variable on the stack, and the source data is read from a file (such as '/var/vsftp/var/%s'). If an attacker can control the file content (for example, by uploading or modifying a user configuration file), it may trigger a stack buffer overflow, leading to code execution. Trigger conditions include: the attacker possesses valid login credentials and can access and modify the relevant file; the file content must be long enough to overwrite the return address. Exploitation methods may include crafting file content to inject shellcode or ROP chains.
- **Code Snippet:**
  ```
  0x0001c1c4      add r0, dest                ; char *dest
  0x0001c1c8      add r1, src                 ; const char *src
  0x0001c1cc      bl sym.imp.strcpy           ; char *strcpy(char *dest, const char *src)
  ```
- **Keywords:** /var/vsftp/var/%s, /proc/%s/cmdline
- **Notes:** Further verification is needed regarding the writability of the file path and specific exploitation conditions. Attackers may upload malicious files via FTP commands (such as STOR) or exploit other vulnerabilities to modify files. It is recommended to check vsftpd configuration and file permissions.

---
### BufferOverflow-oam_cli_cmd_llid_queue_strcmd_parse

- **File/Directory Path:** `usr/lib/liboam_mipc_client.so`
- **Location:** `liboam_mipc_client.so:0x000041e0 oam_cli_cmd_llid_queue_strcmd_parse`
- **Risk Score:** 6.5
- **Confidence:** 8.5
- **Description:** Function `oam_cli_cmd_llid_queue_strcmd_parse` uses `strcpy` to copy two user-controlled parameters into 256-byte stack buffers without validation. Overflow can occur if inputs exceed 256 bytes, potentially leading to code execution. Trigger condition: User provides long strings via CLI. The function uses `mipc_send_cli_msg` for IPC, but the overflow is local.
- **Code Snippet:**
  ```
  if (*(puVar2 + -0x22c) != 0) {
      sym.imp.strcpy(puVar2 + iVar1 + -0x228, *(puVar2 + -0x22c));
  }
  if (*(puVar2 + -0x230) != 0) {
      sym.imp.strcpy(puVar2 + 4 + -0x128, *(puVar2 + -0x230));
  }
  ```
- **Keywords:** param_1, param_2, mipc_send_cli_msg
- **Notes:** The vulnerability is clear, but the function's specific use case might limit exploitability. Further analysis should determine how parameters are passed and if the function is called directly from user input.

---
### XSS-xml.js-functions

- **File/Directory Path:** `web/omci/xml.js`
- **Location:** `xml.js functions createInput, createbridge, creategemport, gemhtml`
- **Risk Score:** 6.5
- **Confidence:** 8.0
- **Description:** Multiple functions (such as `createInput`, `createbridge`, `creategemport`, `gemhtml`) directly write data loaded from the XML file 'me_mib.xml' into the DOM using `document.writeln` or `innerHTML`, without sanitizing or encoding the data content. This allows attackers to inject malicious JavaScript code. Specific manifestation: When users trigger these functions through UI elements (such as button clicks), if the XML data contains script tags (e.g., `<script>alert('XSS')</script>`), it will be executed in a new window or the current page. Trigger conditions include: the attacker can modify the content of the 'me_mib.xml' file (e.g., through file upload or configuration vulnerabilities), and the victim user accesses the relevant page and interacts. Potential exploitation methods: session theft, privilege escalation, or arbitrary action execution. In the code logic, data is obtained via `mib.getElementsByTagName` and directly concatenated into an HTML string for writing.
- **Code Snippet:**
  ```
  // Example from the createInput function
  function createInput(name,type)
  {
      myWindow=window.open();
      var a="";
      try {
          node=mib.getElementsByTagName(name)[0];
          father=node.childNodes;
      } catch(e) {
          alert(e.message);
          type.disabled="disabled";
          return;
      }
      if(father==null) return;
      for(var j=0;j<father.length;j++) {
          child=father[j].childNodes;
          n=j+1;
          var b="ME number: "+n+"<br>";
          for(var i=0;i<25;i++) {
              try { a=child[i].text+"\n"; } catch(e) { break; }
              b=b+"<div>"+a+"</div>"; // Unsanitized data directly concatenated
          }
          myWindow.document.writeln(b,"<br>"); // Directly written to DOM, potential script execution
      }
      type.title=a;
  }
  ```
- **Keywords:** me_mib.xml, createInput, createbridge, creategemport, gemhtml, mouseover, mouseover2
- **Notes:** The attack chain is complete but relies on the attacker being able to modify the 'me_mib.xml' file. It is recommended to verify file system permissions and upload mechanisms. Associated files may include web interface-related HTML/JS. Subsequent analysis should focus on file upload functionality or XML parsing configuration.

---
### DoS-FTP-Port-Conflict

- **File/Directory Path:** `web/main/ftpSrv.htm`
- **Location:** `ftpSrv.htm: checkConflictPort function and doApply function`
- **Risk Score:** 6.5
- **Confidence:** 7.0
- **Description:** A potential Denial of Service (DoS) attack chain was discovered in the 'ftpSrv.htm' file. An attacker can trigger the `checkConflictPort` function by modifying the FTP service port number, causing other network services (such as port mapping, DMZ, UPnP) to be disabled. Specific attack steps: 1) The attacker logs into the web interface as a non-root user; 2) Navigates to the FTP settings page; 3) Changes the port number to one that conflicts with an existing service (e.g., port 80 for HTTP service); 4) Clicks the 'Apply' button to trigger the `doApply` function; 5) The `checkConflictPort` function detects the conflict and pops up a confirmation dialog; 6) If the user confirms (or bypasses it via automation tools), the conflicting service is disabled via the `$.act` call. This may lead to service interruption, affecting network functionality. The attack relies on user interaction (confirmation dialog), but can be bypassed using browser automation tools (like Selenium).
- **Code Snippet:**
  ```
  function checkConflictPort(port) {
    // ... Port conflict check logic
    if (confirm(c_str.ftp_vs_conflict)) {
      $.act(ACT_SET, WAN_IP_CONN_PORTMAPPING, this.__stack, null, ["portMappingEnabled=0"]);
    } else {
      ret = false;
      return;
    }
    // ... Similar logic for other services
  }
  
  function doApply() {
    // ... Port validation
    if ($.id("inetAccess_en").checked) {
      if(0 == checkConflictPort(port)) {
        return;
      }
      $.act(ACT_SET,FTP_SERVER,null,null,["accessFromInternet=1"]);
    }
    // ... Set port
  }
  ```
- **Keywords:** FTP_SERVER, WAN_IP_CONN_PORTMAPPING, WAN_PPP_CONN_PORTMAPPING, IP_CONN_PORTTRIGGERING, PPP_CONN_PORTTRIGGERING, DMZ_HOST_CFG, UPNP_CFG, UPNP_PORTMAPPING
- **Notes:** The attack chain is complete but requires user interaction (confirmation dialog). Actual exploitability depends on whether the attacker can automate web interactions. It is recommended to further analyze backend processing functions (such as the implementation of `$.act`) to confirm the impact of permission checks and service modifications. Related files may include other configuration pages (such as 'usbFolderBrowse.htm') and backend components.

---
### BufferOverflow-Apm_cli_set_avc_value_str

- **File/Directory Path:** `usr/lib/libavc_mipc_client.so`
- **Location:** `libavc_mipc_client.so:0x11f8 and 0x122c in function Apm_cli_set_avc_value_str`
- **Risk Score:** 6.5
- **Confidence:** 7.0
- **Description:** The function Apm_cli_set_avc_value_str uses strcpy to copy user-controlled input parameters ('name' and 'value') into fixed-size stack buffers (256 bytes) without any bounds checking. This can lead to stack-based buffer overflows if the input exceeds the buffer size. An attacker with valid non-root credentials could trigger this by providing overly long strings via CLI or IPC mechanisms, potentially overwriting the return address and achieving arbitrary code execution. The trigger condition is when the 'name' or 'value' parameters are non-null and longer than 256 bytes. The function lacks any input validation or size checks, making it highly susceptible to exploitation.
- **Code Snippet:**
  ```
  From decompilation:
  if (*(puVar2 + -0x214) != 0) {
      sym.imp.strcpy(puVar2 + iVar1 + -0x20c, *(puVar2 + -0x214)); // Copies 'name' into buffer auStack_210 [256]
  }
  if (*(puVar2 + -0x220) != 0) {
      sym.imp.strcpy(puVar2 + 4 + -0x104, *(puVar2 + -0x220)); // Copies 'value' into buffer auStack_108 [256]
  }
  ```
- **Keywords:** mipc_send_cli_msg
- **Notes:** This vulnerability is shared across multiple exported functions (e.g., Apm_cli_create_avc_entity, Apm_cli_delete_avc_entity) as identified via cross-references to strcpy. Further analysis is recommended to trace how user input reaches these functions via IPC or CLI interfaces, and to assess the exploitation feasibility in the broader system context. The library's role in AVC and IPC communication suggests potential impact on system stability and security if exploited.

---
### CodeExecution-ALSA_MIXER_SIMPLE_MODULES

- **File/Directory Path:** `usr/lib/alsa-lib/smixer/smixer-ac97.so`
- **Location:** `smixer-ac97.so:0x98c mixer_simple_basic_dlopen`
- **Risk Score:** 6.0
- **Confidence:** 8.0
- **Description:** The mixer_simple_basic_dlopen function in smixer-ac97.so uses the environment variable ALSA_MIXER_SIMPLE_MODULES to dynamically construct a library path that is passed to snd_dlopen for loading. An attacker with local login credentials can set this environment variable to point to a malicious shared library in a directory they control. When the ALSA mixer is initialized (e.g., by running ALSA commands like 'amixer' or 'aplay'), the function is triggered, loading the malicious library and executing arbitrary code in the context of the user. The attack requires the attacker to: 1) craft a malicious shared library, 2) set ALSA_MIXER_SIMPLE_MODULES to the library's path, and 3) trigger mixer initialization through ALSA utilities. The code lacks validation of the environment variable content, and the buffer allocation (based on strlen + 0x11) is sufficient to prevent overflow due to fixed append strings, but the uncontrolled path leads to arbitrary library loading. This provides a reliable code execution mechanism for local attackers, though it does not inherently escalate privileges beyond the user's existing access.
- **Code Snippet:**
  ```
  iVar3 = sym.imp.getenv(*0xc2c + 0x9d4); // Get ALSA_MIXER_SIMPLE_MODULES
  bVar13 = iVar3 == 0;
  if (bVar13) {
      iVar3 = *0xc30; // Use default if not set
  }
  if (bVar13) {
      iVar3 = iVar3 + 0x9e4;
  }
  iVar4 = sym.imp.strlen(iVar3);
  iVar4 = sym.imp.malloc(iVar4 + 0x11); // Allocate buffer
  iVar8 = iVar4 + 0;
  if (iVar8 != 0) {
      sym.imp.strcpy(iVar4, iVar3); // Copy environment variable value
      sym.imp.strcat(iVar8, *0xc34 + 0xa24); // Append first string (e.g., "/")
      sym.imp.strcat(iVar8, *0xc38 + 0xa34); // Append second string (e.g., "smixer-sbase.so")
      iVar3 = sym.imp.snd_dlopen(iVar8, 2); // Load library
      // ... (error handling omitted)
  }
  ```
- **Keywords:** ALSA_MIXER_SIMPLE_MODULES
- **Notes:** The vulnerability is directly exploitable by local users for code execution but does not provide privilege escalation without additional context. Further analysis could investigate if privileged processes (e.g., system daemons) use this mixer, which might increase the risk. The strings 'ALSA_MIXER_SIMPLE_MODULES', '/usr/lib/alsa-lib/smixer', and 'smixer-sbase.so' were identified in the binary, confirming the data flow. No buffer overflow was detected due to proper allocation sizes, but the lack of path validation remains the key issue.

---
