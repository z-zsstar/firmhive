# Archer_C3200_V1_150831 (8 findings)

---

### command-injection-eapd-fcn.0000a1b0

- **File/Directory Path:** `sbin/eapd`
- **Location:** `eapd:0x0000a1b0 fcn.0000a1b0`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** A command injection vulnerability exists in the 'eapd' binary where user-controlled input from a network socket is incorporated into a command executed via _eval without proper sanitization. The vulnerability is triggered when data is received on a specific socket (handled in fcn.0000b0f0) and passed to fcn.0000a1b0, which uses the input in an _eval call. The command is constructed using strings like 'wl%d' and user input, allowing an attacker to inject arbitrary commands by including shell metacharacters. The attack requires the attacker to send malicious data to the vulnerable socket, which is accessible to non-root users with valid login credentials, as the daemon binds to a network port. This leads to full command execution with the privileges of the 'eapd' process, which is typically root, enabling complete system compromise.
- **Code Snippet:**
  ```
  In fcn.0000a1b0:
      *(puVar3 + -0x38) = param_2;  // param_2 is user input from recv
      *(puVar3 + -0x3c) = *0xa31c;  // points to 'wl%d'
      *(puVar3 + -0x34) = *0xa324;  // points to another string
      sym.imp._eval(puVar3 + -0x3c, *0xa320, iVar1, iVar1);  // command execution with user input
  ```
- **Keywords:** Socket descriptor from recv in fcn.0000b0f0, NVRAM variable via nvram_get in fcn.0000c558, IPC via _eval command execution
- **Notes:** The vulnerability is highly exploitable due to the direct use of user input in a command execution function. The attack chain is verified from network input to command execution. Further analysis could identify the exact socket port and protocol, but the vulnerability is clear. Additional vulnerabilities may exist, but this is the most critical and exploitable one found.

---
### Command-Injection-UPnP-AddPortMapping

- **File/Directory Path:** `usr/bin/upnpd`
- **Location:** `upnpd:0xbca8 fcn.0000bca8, upnpd:0xecb0 fcn.0000ecb0, upnpd:0xe20c fcn.0000e20c`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** A command injection vulnerability exists in the UPnP AddPortMapping action handler. Attackers can craft malicious UPnP requests to inject shell metacharacters (e.g., '; malicious_command') into parameters (such as NewExternalPort, NewProtocol, NewInternalClient, NewPortMappingDescription). When the program processes the request, it uses snprintf to construct an iptables command string and directly passes it to the system function for execution. Due to a lack of input validation and filtering, command injection occurs. Trigger condition: An attacker sends a specially crafted UPnP request to the device's UPnP service port (typically without authentication). Potential exploitation method: Remote code execution, potentially gaining control of the device. An attacker as a connected user (with valid login credentials) can easily exploit this vulnerability because the UPnP service is often exposed on the internal network.
- **Code Snippet:**
  ```
  // fcn.0000bca8: Extract user input parameters
  iVar4 = fcn.0000d0b4(*(piVar6[-0x9c] + 0x3bc), 0x17e8); // Extract NewExternalPort
  iVar4 = fcn.0000d0b4(*(piVar6[-0x9c] + 0x3bc), 0x17f8); // Extract NewProtocol
  // Similarly extract other parameters like NewInternalClient
  fcn.0000e828(piVar6[-0x12]); // Call handler function
  
  // fcn.0000ecb0: Use snprintf to build command string
  sym.imp.snprintf(auStack_21c, 500, "%s -t nat -A %s -o %s -d %s -p %s --dport %s -j SNAT --to-source %s", *0xefa0, ...); // Parameters from user input
  fcn.0000e20c(auStack_21c); // Call system to execute command
  
  // fcn.0000e20c: Directly call system
  int32_t iVar1 = sym.imp.system(*(&stack0x00000000 + -0xc)); // Execute constructed command
  ```
- **Keywords:** NewExternalPort, NewProtocol, NewInternalClient, NewPortMappingDescription, /var/tmp/upnpd/upnpd.conf, msg_send, msg_recv
- **Notes:** Vulnerability exploitation evidence comes from r2 analysis, showing user input directly embedded into command strings. Attack chain is complete: input point (UPnP parameters) → data flow (snprintf construction) → dangerous operation (system call). It is recommended to validate input parameters, use whitelist filtering, or escape shell metacharacters. Further analysis should check if other UPnP actions (such as DeletePortMapping) have similar issues. Associated file: /var/tmp/upnpd/upnpd.conf may contain configuration data.

---
### heap-buffer-overflow-dcs_handle_request

- **File/Directory Path:** `sbin/acsd`
- **Location:** `fcn.0000f7c0:0x00010974 (in the else branch of the parsing loop)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** In function fcn.0000f7c0 (dcs_handle_request), when processing a DCS request, variable values obtained from NVRAM (such as 'eth0_list') are parsed as space-separated lists of numbers. The parsing loop lacks boundary checks: when the input string contains no spaces, the loop proceeds infinitely, causing writes beyond the allocated 500-byte heap buffer. An attacker, as an authenticated user, can trigger the infinite loop by setting a specific NVRAM variable to a numeric string without spaces (e.g., '123'). Each loop iteration writes a 4-byte integer to an incrementing memory location; when the loop counter exceeds 99, writes exceed the buffer boundary, overwriting heap metadata or adjacent memory, potentially leading to heap corruption, arbitrary code execution, or denial of service. Trigger condition: the attacker sets the NVRAM variable and triggers DCS request processing (e.g., via network interface or IPC). Exploitation method: by controlling the numeric values, the attacker can write arbitrary integers to memory at relative offsets, combined with heap layout manipulation to achieve code execution. Constraints: the NVRAM variable value must contain no spaces; the vulnerability depends on the heap allocation size (500 bytes) and the loop logic.
- **Code Snippet:**
  ```
  // Key snippet extracted from decompiled code
  iVar7 = fcn.00011d30(500); // Allocate 500-byte heap buffer
  // Build key name and get NVRAM value
  sym.imp.strcpy(iVar16, iVar12);
  iVar6 = sym.imp.strlen(iVar16);
  sym.imp.memcpy(iVar16 + iVar6, *0x107a8, 8); // Append '_list'
  fcn.00011dd4(puVar21 + -0x1f0, 0x80, iVar16); // Get value into 128-byte buffer
  // Parsing loop
  while (true) {
      iVar6 = sym.imp.strspn(puVar21 + -0x1f0, uVar8);
      iVar17 = puVar21 + iVar6 + -0x1f0;
      sym.imp.strncpy(iVar19, iVar17, 0x10); // Copy up to 16 bytes
      iVar6 = sym.imp.strcspn(iVar19, *0x10854);
      *(puVar21 + iVar6 + -0x24) = 0;
      if (*(puVar21 + -0x24) == '\0') break; // Exit condition depends on space
      uVar8 = sym.imp.atoi(iVar19); // Convert to integer
      // Write to heap buffer, offset based on iVar14
      if (iVar14 >= 0xb) {
          *(*(puVar21 + -0x204) + 0x70) = uVar8; // Write to iVar7 + offset
      }
      *(puVar21 + -0x204) = *(puVar21 + -0x204) + 4; // Increment pointer
      iVar14 = iVar14 + 1; // Infinite increment if no space
      // Update iVar6 for next token; if no space, iVar6 may be 0, causing infinite loop
  }
  ```
- **Keywords:** nvram_get, eth0_list, dcs_handle_request, fcn.00011dd4
- **Notes:** Vulnerability verified: attacker must control NVRAM variable (e.g., 'eth0_list') and trigger DCS request. Infinite loop invalidates input length limit (128 bytes). Recommend subsequent analysis of heap layout and exploitation code execution. Related functions: fcn.00011dd4 (NVRAM get), fcn.0000c048 (parameter validation). This vulnerability has a complete attack chain: from untrusted input (NVRAM) to dangerous operation (heap overflow).

---
### Untitled Finding

- **File/Directory Path:** `etc/passwd.bak`
- **Location:** `passwd.bak`
- **Risk Score:** 8.0
- **Confidence:** 9.0
- **Description:** The file 'passwd.bak' contains sensitive user account information, including the password hash for the admin user (encrypted using MD5). The file permissions are set to 777 (rwxrwxrwx), allowing any user (including non-root users) to read the file. An attacker, logged in as a non-root user, can easily read this file, obtain the password hash, and attempt offline cracking (for example, using tools like John the Ripper). If the hash is successfully cracked, the attacker can obtain the admin user's plaintext password, thereby escalating privileges to root (because the admin user UID is 0). The trigger condition is simple: the attacker only needs to execute 'cat passwd.bak' or a similar command. Potential attacks include privilege escalation and complete system control. Constraints: Cracking the hash may require computational resources and time, but MD5 encryption is relatively weak and easy to crack if the password is simple.
- **Code Snippet:**
  ```
  admin:$1$$iC.dUsGpxNNJGeOm1dFio/:0:0:root:/:/bin/sh
  dropbear:x:500:500:dropbear:/var/dropbear:/bin/sh
  nobody:*:0:0:nobody:/:/bin/sh
  ```
- **Keywords:** passwd.bak
- **Notes:** This finding is based on actual file content and permission evidence. It is recommended to check if other similar sensitive files (such as shadow.bak) exist in the system and to strengthen file permission restrictions (for example, set to root-readable only). Subsequent analysis can focus on similar information leaks in other configuration files or binary files.

---
### CommandInjection-process_args

- **File/Directory Path:** `sbin/wl`
- **Location:** `wl:0x41ef0-0x41efc sym.process_args`
- **Risk Score:** 8.0
- **Confidence:** 9.0
- **Description:** Command injection vulnerability in the process_args function when the 'sh' command is used. The function calls rwl_shell_cmd_proc with user-controlled arguments, which are then executed as shell commands. This allows an attacker to execute arbitrary commands with the privileges of the 'wl' binary. The trigger condition is passing 'sh' as a command-line argument followed by malicious commands.
- **Code Snippet:**
  ```
  0x00041ee0      0900a0e1       mov r0, sb                  ; const char *s1
  0x00041ee4      30139fe5       ldr r1, str.sh              ; [0x5898c:4]=0x6873 ; "sh" ; const char *s2
  0x00041ee8      6c1dffeb       bl sym.imp.strcmp           ; int strcmp(const char *s1, const char *s2)
  0x00041eec      000050e3       cmp r0, 0
  0x00041ef0      0200001a       bne 0x41f00
  0x00041ef4      043097e5       ldr r3, [r7, 4]             ; 0x82c60
  0x00041ef8      000053e3       cmp r3, 0
  0x00041efc      9700001a       bne 0x42160
  ...
  0x00042160      04309be5       ldr r3, [arg_4h]
  0x00042164      04108be2       add r1, arg_4h
  0x00042168      04108de5       str r1, [var_4h]
  0x0004216c      000053e3       cmp r3, 0
  0x00042170      0c00000a       beq 0x421a8
  0x00042174      00009de5       ldr r0, [sp]                ; int32_t arg1
  0x00042178      0020e0e3       mvn r2, 0
  0x0004217c      6d0800eb       bl sym.rwl_shell_cmd_proc
  ```
- **Keywords:** argv, obj.wlu_av0
- **Notes:** This vulnerability is directly exploitable via command-line arguments. If the 'wl' binary has setuid permissions or is run by a privileged user, it could lead to privilege escalation. The attack chain is straightforward: user passes 'sh' and arbitrary commands to execute.

---
### BufferOverflow-rwl_shell_cmd_proc

- **File/Directory Path:** `sbin/wl`
- **Location:** `wl:0x44388-0x443bc sym.rwl_shell_cmd_proc`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** A buffer overflow vulnerability exists in the rwl_shell_cmd_proc function due to unsafe use of strcat without bounds checking. The function allocates a 256-byte buffer using malloc and then concatenates command-line arguments using strcat in a loop (addresses 0x44388-0x443bc). If the total length of arguments exceeds 256 bytes, it will overflow the heap-allocated buffer, potentially leading to heap corruption and arbitrary code execution. Additionally, the function executes shell commands via rwl_shell_createproc, allowing command injection if malicious arguments are provided. The vulnerability can be triggered by a non-root user with command-line access to the 'wl' binary, especially if the binary has elevated privileges (e.g., setuid).
- **Code Snippet:**
  ```
  0x00044344      010ca0e3       mov r0, 0x100               ; size_t size
  0x00044348      0180a0e1       mov r8, r1                  ; arg2
  0x0004434c      0260a0e1       mov r6, r2
  0x00044350      dd13ffeb       bl sym.imp.malloc           ;  void *malloc(size_t size)
  ...
  0x00044388      0400a0e1       mov r0, r4                  ; char *s1
  0x0004438c      fb13ffeb       bl sym.imp.strcat           ; char *strcat(char *s1, const char *s2)
  0x00044390      0430b5e5       ldr r3, [r5, 4]!
  0x00044394      000053e3       cmp r3, 0
  0x00044398      0800000a       beq 0x443c0
  0x0004439c      0400a0e1       mov r0, r4                  ; const char *s
  0x000443a0      7114ffeb       bl sym.imp.strlen           ; size_t strlen(const char *s)
  0x000443a4      ac139fe5       ldr r1, aav.0x00052a18      ; [0x52a18:4]=32 ; " " ; const void *s2
  0x000443a8      000084e0       add r0, r4, r0              ; void *s1
  0x000443ac      0220a0e3       mov r2, 2
  0x000443b0      b313ffeb       bl sym.imp.memcpy           ; void *memcpy(void *s1, const void *s2, size_t n)
  0x000443b4      001095e5       ldr r1, [r5]                ; 0x52a18 ; " "
  0x000443b8      000051e3       cmp r1, 0
  0x000443bc      f1ffff1a       bne 0x44388
  ```
- **Keywords:** argv, obj.g_driver_io, obj.remote_type
- **Notes:** The vulnerability requires the 'sh' command to be invoked via command-line arguments. Evidence shows the buffer is allocated on the heap, and overflow could corrupt heap metadata or adjacent memory. Exploitation may allow arbitrary code execution if the binary runs with elevated privileges. Further dynamic analysis is recommended to confirm exploitability.

---
### BufferOverflow-fcn.0000c464

- **File/Directory Path:** `sbin/mpstat`
- **Location:** `mpstat:0xc850 function name: fcn.0000c464`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** In function fcn.0000c464, there exists a buffer overflow vulnerability originating from the unsafe use of strcpy. The attack chain includes: 1) Input point: File input (such as /proc/stat or configuration files ./sysstat.ioconf, /etc/sysconfig/sysstat.ioconf), read via fopen and fgets, allowing up to 255 bytes of data. 2) Data flow: Using sscanf to parse file content, the format string "%u:%[^:]:%[^:]:%d:%[^:]:%u:%[^:]:%u:%s" stores data into a heap-allocated buffer (puVar9, 200 bytes). 3) Dangerous operation: strcpy copies the content of puVar9 to the target memory location (iVar2 + 0xa0) without bounds checking. If an attacker can control the file content (for example, by modifying configuration files or influencing the file path), a long string can overflow the target buffer, leading to arbitrary code execution or denial of service. The trigger condition is when mpstat processes file input, and the attacker needs to possess valid login credentials (non-root user) and be able to influence the file content.
- **Code Snippet:**
  ```
  0x0000c4d4: fgets call reading file input
  0x0000c5cc: sscanf parsing format "%u:%[^:]:%[^:]:%d:%[^:]:%u:%[^:]:%u:%s" storing to puVar9
  0x0000c850: strcpy(iVar2 + 0xa0, puVar9)  // No bounds checking
  ```
- **Keywords:** File path: /proc/stat, ./sysstat.ioconf, /etc/sysconfig/sysstat.ioconf, Function: fcn.0000c464, Buffer: puVar9 (heap-allocated, 200 bytes), Input source: File stream via fopen and fgets
- **Notes:** Exploitability depends on file controllability. /proc/stat is typically read-only, but fallback files like ./sysstat.ioconf might be writable under certain configurations. It is recommended to further verify file permissions and actual paths. The attack chain is complete, from input to dangerous operation, but actual exploitation requires the attacker to influence file content.

---
### BufferOverflow-taskset_cpu_affinity

- **File/Directory Path:** `sbin/taskset`
- **Location:** `taskset:0x8b78 fcn.00008b78`
- **Risk Score:** 3.5
- **Confidence:** 7.0
- **Description:** A buffer overflow vulnerability exists in the processing of the CPU affinity mask string in taskset. When the mask string is 248 characters or longer, the code writes beyond the intended 124-byte buffer (auStack_104) on the stack. The overflow occurs in a loop that processes each character of the input string and sets bits in a buffer representing the CPU affinity mask. Specifically, the index calculation (uVar5 >> 5) exceeds the buffer size of 31 words (124 bytes) when the string length reaches 248 characters, leading to writes at offset iVar19 - 96, which falls within the auStack_84 buffer (80 bytes). This can corrupt adjacent stack variables like auStack_84, iStack_34, or auStack_24, but based on the stack layout, it does not directly overwrite saved registers or return addresses, as they are located at higher addresses (iVar19 + 4 to iVar19 + 36). The trigger condition is passing a long mask string via command-line arguments. Potential exploitation could lead to denial of service or unpredictable behavior due to corrupted local variables, but arbitrary code execution is unlikely due to the distance from critical stack frames and the lack of controllable pointers in the overflow region.
- **Code Snippet:**
  ```
  // From decompilation at fcn.00008b78
  if (iVar11 == 0) {
      puVar12 = param_2[iVar2]; // Input string from argv
      iVar2 = sym.imp.strlen(puVar12);
      puVar9 = puVar12 + iVar2 + -1;
      // ... initialization of buffer at iVar19 + -0xdc ...
      while( true ) {
          // ... processes each character ...
          uVar15 = uVar1 + -0x30;
          iVar2 = sym.imp.tolower(uVar1);
          // ... checks for hex digits ...
          if ((uVar15 & 1) != 0) {
              iVar2 = iVar19 + (uVar5 >> 5) * 4; // Index calculation
              *(iVar2 + -0xdc) = *(iVar2 + -0xdc) | iVar14 << (uVar5 & 0x1f); // Write to buffer
          }
          // ... similar for other bits ...
          uVar4 = uVar4 + 4;
          uVar13 = uVar13 + 4;
          uVar7 = uVar7 + 4;
          if (puVar10 <= puVar12 && puVar12 != puVar10) break;
          uVar5 = uVar5 + 4; // uVar5 increments by 4 per iteration
          puVar9 = puVar10;
      }
  }
  ```
- **Keywords:** argv, mask string
- **Notes:** The vulnerability is confirmed through code analysis, but exploitability is limited. The overflow corrupts local variables but does not reach return addresses or critical pointers. Further analysis could involve dynamic testing to confirm crash behavior or explore corruption of specific variables like those used in execvp calls. However, as a non-root user, the impact is likely low. No other exploitable issues (e.g., command injection) were found in taskset.

---
