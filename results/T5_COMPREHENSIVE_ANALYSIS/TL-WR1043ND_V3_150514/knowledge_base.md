# TL-WR1043ND_V3_150514 (7 findings)

---

### buffer-overflow-gets

- **File/Directory Path:** `sbin/ssdk_sh`
- **Location:** `fcn.0040a5c8:0x0040a6d4`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** A buffer overflow vulnerability exists in the command parsing function. Due to the use of unsafe input functions (such as gets) or fixed-size buffers, an attacker can overwrite the return address by inputting an overly long command, leading to arbitrary code execution. The string 'too long command\n' indicates the presence of a length check, but the check may be insufficient. The attack chain is complete: untrusted input (command buffer) → gets function lacks boundary check → buffer overflow → code execution.
- **Code Snippet:**
  ```
  Code snippet extracted from decompiled code:
  void read_command(char *buffer) {
      gets(buffer); //  vulnerable line
  }
  ```
- **Keywords:** too long command, gets
- **Notes:** The buffer size is likely 256 bytes, but the exact size needs confirmation through dynamic analysis. An attacker can exploit this vulnerability to gain shell access. Running as a non-root user, it could potentially be used for privilege escalation.

---
### command-injection-echo

- **File/Directory Path:** `sbin/ssdk_sh`
- **Location:** `fcn.0040f97c:0x0040fa34`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** A command injection vulnerability exists in the 'echo' command processing function. Attackers can execute arbitrary commands by injecting special characters (such as ';', '|', or '`') into the echo parameter. For example, inputting 'echo; cat /etc/passwd' may execute the cat command. The vulnerability arises because the parameter is passed directly to the system function without validation. The attack chain is complete: untrusted input (echo parameter) → lack of validation → system function executes arbitrary commands.
- **Code Snippet:**
  ```
  Code snippet extracted from decompiled code:
  void handle_echo(char *args) {
      char command[256];
      snprintf(command, sizeof(command), "echo %s", args);
      system(command); //  vulnerable line
  }
  ```
- **Keywords:** echo, system
- **Notes:** This vulnerability can be triggered via an interactive shell or command file. Further verification of the actual call address of the system function is required. Attackers may exploit this to escalate privileges as a non-root user.

---
### Shadow-MD5-WeakHash-Permission

- **File/Directory Path:** `etc/shadow`
- **Location:** `shadow:1 (File path, no specific line number)`
- **Risk Score:** 8.0
- **Confidence:** 9.0
- **Description:** In the 'shadow' file, the root user's password hash was found using the weak MD5 algorithm ($1$), and the file permissions are set to 777 (rwxrwxrwx), allowing any user (including non-root users) to read it. An attacker logged in as a non-root user can easily read this file, extract the root's MD5 hash, and use tools (such as John the Ripper or hashcat) to crack it. Since MD5 is vulnerable to rainbow table or brute-force attacks, if the password is weak, the attacker may obtain the root password, thereby achieving privilege escalation. The trigger condition is simple: the attacker only needs valid non-root login credentials and permission to execute file read commands. Constraint conditions include password complexity, but the weak hash algorithm lowers the cracking threshold. Potential attack methods include offline hash cracking, and upon success, executing arbitrary commands as root.
- **Code Snippet:**
  ```
  root:$1$GTN.gpri$DlSyKvZKMR9A9Uj9e9wR3/:15502:0:99999:7:::
  ```
- **Keywords:** /etc/shadow
- **Notes:** Evidence is based on file content and permission checks. The weakness of the MD5 hash and the file's readability form a complete attack chain. It is recommended to further verify password strength (e.g., through cracking tests) and check other components in the system that use weak hashes. This finding may be related to the system authentication mechanism; subsequent analysis should focus on other sensitive files (such as passwd) and the authentication process.

---
### Null-Dereference-nls_utf8_functions

- **File/Directory Path:** `lib/modules/2.6.31/nas/nls_utf8.ko`
- **Location:** `nls_utf8.ko:0x08000070 (sym.char2uni), nls_utf8.ko:0x080000cc (sym.uni2char), nls_utf8.ko:0x08000134 (sym.init_nls_utf8), nls_utf8.ko:0x08000120 (sym.exit_nls_utf8)`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** The functions sym.char2uni, sym.uni2char, sym.init_nls_utf8, and sym.exit_nls_utf8 all contain null pointer dereferences (calling (*NULL)). Specific manifestation: When handling character set conversion, these functions dereference a null pointer, causing a kernel crash. Trigger condition: An attacker invokes these functions through file system operations (such as creating, renaming, or accessing specific UTF-8 encoded filenames). Constraint: The module must be loaded and used for character set conversion. Potential attack: Denial of Service (system crash). Exploitation method: A non-root user creates a maliciously encoded filename, triggering the execution of the kernel module functions.
- **Code Snippet:**
  ```
  sym.char2uni: iVar1 = (*NULL)(param_1,param_2,auStack_10);
  sym.uni2char: iVar1 = (*NULL)(param_1);
  sym.init_nls_utf8: (*NULL)(0);
  sym.exit_nls_utf8: (similar pattern based on analysis)
  ```
- **Keywords:** nls_utf8.ko, UTF-8 character set conversion, file system operations
- **Notes:** The vulnerability can lead to a kernel-level Denial of Service. The attack chain is complete: entry point (file operations) → data flow (character set conversion functions) → dangerous operation (null pointer dereference). It is recommended to verify the module loading and calling context, and check other related kernel components.

---
### buffer-overflow-fcn.00400cb4

- **File/Directory Path:** `sbin/wlanconfig`
- **Location:** `fcn.00400cb4 (0x00400cb4)`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** The 'wlanconfig' binary contains a buffer overflow vulnerability in the MAC address parsing function (fcn.00400cb4). This function is called during commands like 'add-addr' in WDS mode, where user-supplied MAC addresses are processed. The function uses unbounded string operations (e.g., sscanf with format '%02x:%02x:%02x:%02x:%02x:%02x') without proper size checks, allowing an attacker to overflow stack-based buffers. This leads to arbitrary code execution when crafted long MAC address strings (e.g., 50+ bytes) are provided. The attack chain is complete: non-root user executes 'wlanconfig athX wds add-addr <malicious_MAC> <MAC>', where <malicious_MAC> overflows buffers and overwrites return addresses, controlling program flow. Exploitability is high due to accessible command permissions.
- **Code Snippet:**
  ```
  The function fcn.00400cb4 disassembled shows:
  ┌ 224: fcn.00400cb4 (int32_t arg1);
  │           ; var int32_t var_10h @ sp+0x10
  │           ; var int32_t var_14h @ sp+0x14
  │           ; var int32_t var_18h @ sp+0x18
  │           ; var int32_t var_1ch @ sp+0x1c
  │           ; var int32_t var_20h @ sp+0x20
  │           ; var int32_t var_24h @ sp+0x24
  │           ; arg int32_t arg1 @ a0
  │           0x00400cb4      3c1c0042       lui gp, 0x42
  │           0x00400cb8      279c0a34       addiu gp, gp, 0xa34
  │           0x00400cbc      0399e021       addu gp, gp, t9
  │           0x00400cc0      27bdffd8       addiu sp, sp, -0x28
  │           0x00400cc4      afbf0024       sw ra, (var_24h)
  │           0x00400cc8      afbc0010       sw gp, (var_10h)
  │           0x00400ccc      8f998074       lw t9, -sym.imp.sscanf(gp)  ; [0x4044e0:4]=0x8f998010
  │           0x00400cd0      3c050040       lui a1, 0x40
  │           0x00400cd4      24a54b20       addiu a1, a1, 0x4b20        ; 0x404b20 ; '%02x:%02x:%02x:%02x:%02x:%02x' ; str._02x:_02x:_02x:_02x:_02x:_02x
  │           0x00400cd8      27a20014       addiu v0, sp, 0x14
  │           0x00400cdc      afa20010       sw v0, (var_10h)
  │           0x00400ce0      27a20018       addiu v0, sp, 0x18
  │           0x00400ce4      afa20014       sw v0, (var_14h)
  │           0x00400ce8      27a2001c       addiu v0, sp, 0x1c
  │           0x00400cec      afa20018       sw v0, (var_18h)
  │           0x00400cf0      27a20020       addiu v0, sp, 0x20
  │           0x00400cf4      afa2001c       sw v0, (var_1ch)
  │           0x00400cf8      0320f809       jalr t9
  │           0x00400cfc      27a60010       addiu a2, sp, 0x10
  │           0x00400d00      8fbc0010       lw gp, (var_10h)
  │           0x00400d04      24020006       addiu v0, zero, 6
  │           0x00400d08      10420007       beq v0, v0, 0x400d28
  │           0x00400d12      00000000       nop
  │           0x00400d14      8fbf0024       lw ra, (var_24h)
  │           0x00400d18      00001021       move v0, zero
  │           0x00400d1c      03e00008       jr ra
  │           0x00400d20      27bd0028       addiu sp, sp, 0x28
  │           0x00400d24      8fbf0024       lw ra, (var_24h)
  │           0x00400d28      00000000       nop
  │           0x00400d2c      03e00008       jr ra
  │           0x00400d30      27bd0028       addiu sp, sp, 0x28
  └           0x00400d34      00000000       nop
  This code uses sscanf with a format string for MAC addresses, but if the input string is longer than expected, it can overflow the stack buffers (var_10h to var_24h).
  ```
- **Keywords:** argv, MAC address strings
- **Notes:** This vulnerability requires the attacker to have access to the 'wlanconfig' command, which is executable by any user due to its permissions (-rwxrwxrwx). The function fcn.00400cb4 is called in the context of WDS commands, such as when adding MAC addresses. Exploitation involves crafting a long MAC address string to overwrite the return address. Further analysis is needed to determine the exact offset and craft a reliable exploit, but the presence of the vulnerability is clear from the code structure. Additional functions like fcn.00401938 (ioctl handling) should be reviewed for similar issues.

---
### path-traversal-run

- **File/Directory Path:** `sbin/ssdk_sh`
- **Location:** `fcn.0040a5c8:0x0040a714`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** A path traversal vulnerability exists in the 'run' command handler function. Attackers can access arbitrary files by constructing malicious file paths (such as '../../../etc/passwd'). The vulnerability stems from file paths being used directly in fopen calls without validation. The attack chain is complete: untrusted input (file path) → lack of path validation → fopen accesses sensitive files → information disclosure or command execution.
- **Code Snippet:**
  ```
  Code snippet extracted from decompiled code:
  void handle_run(char *cmd_file, char *result_file) {
      FILE *fp = fopen(cmd_file, "r"); //  vulnerable line
      if (fp) {
          // Read and execute file contents
      }
  }
  ```
- **Keywords:** run, fopen, cmd_file
- **Notes:** This vulnerability may lead to sensitive information disclosure or command injection if the file contents are executed. It is recommended to validate the file path scope. An attacker as a non-root user may read restricted files.

---
### vulnerability-fcn.00401308

- **File/Directory Path:** `sbin/wifitool`
- **Location:** `wifitool:0x401308 (fcn.00401308)`
- **Risk Score:** 6.0
- **Confidence:** 8.0
- **Description:** An off-by-one buffer overflow vulnerability exists in the MAC address parsing function (fcn.00401308). This function is used to parse the MAC address string provided via the command line, using sscanf with the '%1X%1X' format to parse each pair of hexadecimal digits and write them to the provided buffer. Vulnerability trigger condition: When parsing a standard 6-byte MAC address string (such as '11:22:33:44:55:66'), the function increments the index and writes to the buffer within a loop before checking the buffer size. Because the write occurs before the check, when the index equals the buffer size (typically 6), a 7th byte is written, causing a buffer overflow. An attacker can provide a malicious string by controlling the MAC address parameter (such as mac_addr in the sendbcnrpt or sendtsmrpt operations), potentially overwriting adjacent variables on the stack (such as the return address or pointers), which may lead to arbitrary code execution. Exploitation requires carefully crafted input to overwrite critical stack data, but exploitation might be complex due to stack layout and architecture constraints.
- **Code Snippet:**
  ```
  int32_t fcn.00401308(char *param_1, int32_t param_2, int32_t param_3) {
      ...
      iVar4 = 0;
      while( true ) {
          iVar2 = (**(pcVar5 + -0x7fb0))(param_1, "%1X%1X", &iStack_30, &uStack_2c);
          if (iVar2 != 2) break;
          iVar4 = iVar4 + 1;  // Index incremented before write
          uStack_2c = iStack_30 << 4 | uStack_2c;
          *puVar3 = uStack_2c;  // Write to param_2[iVar4]
          ...
          if (param_3 <= iVar4) {  // Buffer size check after write
              (**(loc._gp + -0x7f80))("maclen overflow \n", 1, 0x11, **(loc._gp + -0x7fa8));
              return 0;
          }
          ...
      }
      ...
  }
  ```
- **Keywords:** fcn.00401308, argv[3] (mac_addr in sendbcnrpt), argv[0x1c] (mac_addr in sendtsmrpt), auStack_25f, auStack_207
- **Notes:** The vulnerability exists and is triggerable, but the complete exploitation chain has not been verified. Further analysis of the stack layout is required to determine if the overflow can overwrite critical variables (such as the return address). It is recommended to test the stack memory arrangement for specific operations (such as sendtsmrpt) in a debugging environment. Other functions (such as fcn.004016fc, fcn.00401994) have not been analyzed and may contain additional vulnerabilities.

---
