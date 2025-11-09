# TL-MR3040_V2_150921 (7 findings)

---

### p2pgo_noa-stack-buffer-overflow

- **File/Directory Path:** `sbin/wlanconfig`
- **Location:** `wlanconfig:0x004031b8 main function (specifically in the parameter parsing loop)`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** In the 'p2pgo_noa' subcommand of 'wlanconfig', there exists a stack buffer overflow vulnerability. When multiple parameter sets (each set includes iteration count, offset value, and duration) are provided, the program uses a fixed-size stack buffer 'auStack_173[11]' to store the parsed data, but lacks boundary checks. An attacker can trigger an overflow by providing two or more parameter sets, writing beyond the buffer boundary and overwriting adjacent stack variables (such as 'iStack_168'). This may lead to arbitrary code execution because the overflow could overwrite the return address or critical stack variables, controlling the program flow. Trigger condition: The attacker executes 'wlanconfig <interface> p2pgo_noa <iter1> <offset1> <duration1> <iter2> <offset2> <duration2>', where the parameter values are controlled by the attacker. Exploitation method: By carefully crafting parameter values, overwrite the return address to jump to attacker-controlled code or shellcode.
- **Code Snippet:**
  ```
  // Relevant code snippet from decompiled output:
  pcVar18 = &cStack_174;
  piVar16 = param_2 + 0xc; // argv[3]
  iVar4 = 0;
  iVar3 = *piVar16;
  pcVar14 = pcVar18;
  while( true ) {
      if (iVar3 == 0) break;
      iVar3 = (**(pcVar20 + -0x7fcc))(iVar3); // strtoul converts iteration count
      ...
      iVar6 = iVar4 * 5; // Calculate index
      iVar4 = iVar4 + 1;
      uVar12 = (*pcVar19)(iVar6); // Convert offset value
      ...
      auStack_173[iVar3] = (uVar12 & 0xffff) >> 8; // Store offset high byte
      auStack_173[iVar3 + 1] = uVar12 & 0xffff; // Store offset low byte (truncated)
      ...
      uVar12 = (*pcVar19)(iVar6); // Convert duration
      auStack_173[iVar3 + 2] = uVar12 >> 8; // Store duration high byte
      auStack_173[iVar3 + 3] = uVar12; // Store duration low byte (truncated)
      ...
      if ((iVar3 == 0) || (iVar4 == 2)) { // Process up to 2 sets
          break;
      }
  }
  // When iVar4=2, iVar3=10, writing to auStack_173[10] to [13], but buffer size is only 11, causing overflow
  ```
- **Keywords:** Command line arguments argv[3] and subsequent arguments (used for the 'p2pgo_noa' subcommand), Stack buffer auStack_173, Local variable iStack_168
- **Notes:** The vulnerability has been verified through code analysis, and a complete attack chain exists: from command line input point to buffer overflow, potentially controlling the return address. Actual exploitation may require bypassing stack protection or ASLR, but protections might be weaker in embedded MIPS environments. It is recommended to further verify stack layout and exploit feasibility, for example through dynamic testing or debugging. Related functions: main, strtoul. Future analysis directions: Check if other subcommands (such as 'create') have similar vulnerabilities, and analyze the security of ioctl calls.

---
### stack-buffer-overflow-get_string

- **File/Directory Path:** `usr/sbin/chat`
- **Location:** `chat:0x0040533c (get_string) memmove call location`
- **Risk Score:** 8.5
- **Confidence:** 7.5
- **Description:** A stack buffer overflow vulnerability was discovered in the 'chat' program's get_string function. This function processes input strings using a fixed-size stack buffer (1024 bytes). When input data exceeds the buffer capacity, the code calls memmove to move data, but the size parameter (iVar1) is calculated based on the input string length, with a minimum of 49 bytes. If an attacker provides a long input string (e.g., exceeding 1024 bytes), when the buffer is full, memmove will copy a large amount of data from the current pointer position (which may already be beyond the buffer) to the start of the buffer, causing a stack overflow. This may overwrite the return address or other critical stack data, allowing the attacker to control the program execution flow. Trigger condition: Attacker provides an overly long string (>1024 bytes) via command line argument or input file. Exploitation method: Carefully craft input to overwrite the return address, achieving arbitrary code execution.
- **Code Snippet:**
  ```
  // Decompiled code snippet from get_string
  if (puStack_20 <= puStack_1c) {
      // ...
      puStack_1c = puStack_1c - iVar1;
      (**(loc._gp + -0x7f3c))(auStack_424, puStack_1c, iVar1); // memmove call
      puStack_438 = puStack_438 + auStack_424 + -puStack_1c;
      puStack_1c = auStack_424 + iVar1;
  }
  // iVar1 calculation: iVar1 = uStack_14 - 1, where uStack_14 = max(strlen(input), 0x32)
  ```
- **Keywords:** stdin, chat-script, chat-file
- **Notes:** The vulnerability may be difficult to exploit on MIPS architecture, but the theoretical attack chain is complete. It is recommended to further verify the stack layout and exploit feasibility. Related functions: get_string, memmove. Input points include standard input and file parameters. Attacker context: Non-root users with login credentials may trigger this vulnerability via command line or file input if the 'chat' program has appropriate permissions. Need to confirm program accessibility and architecture-specific exploit difficulty.

---
### command-injection-modeSwitchByCmd-modeSwitchByCfgFile

- **File/Directory Path:** `usr/sbin/handle_card`
- **Location:** `handle_card:0x00408188 (modeSwitchByCmd), handle_card:0x004082dc (modeSwitchByCfgFile)`
- **Risk Score:** 8.0
- **Confidence:** 9.0
- **Description:** The handle_card binary contains a command injection vulnerability in the modeSwitchByCmd and modeSwitchByCfgFile functions. These functions construct a command string using sprintf with user-provided input from the -c command-line option (usb mode switch cmd) and execute it via system without proper sanitization. An attacker with access to the handle_card command can inject arbitrary commands by including shell metacharacters (e.g., ;, &, |) in the -c argument. This could lead to arbitrary command execution with the privileges of the handle_card process. Given that handle_card likely handles USB device operations, it may run with elevated privileges, potentially allowing privilege escalation. The vulnerability is triggered when the -c option is used with malicious input during add or delete operations. The attack chain is complete and exploitable: input from -c flows directly to system call without validation, enabling command injection.
- **Code Snippet:**
  ```
  // From modeSwitchByCmd function
  sprintf(auStack_188, "usb_modeswitch -v 0x%04x -p 0x%04x -I -W %s &", vid, pid, cmd);
  system(auStack_188);
  
  // From modeSwitchByCfgFile function  
  sprintf(auStack_88, "usb_modeswitch -v 0x%04x -p 0x%04x -I -W -c %s &", vid, pid, cfg_file);
  system(auStack_88);
  ```
- **Keywords:** -c (command-line option for usb mode switch cmd)
- **Notes:** The exploit requires the attacker to have valid login credentials and access to execute handle_card. The binary may be run via services or with elevated privileges, increasing the impact. Further investigation is recommended to determine the exact execution context and permissions of handle_card in the system. Additional analysis of other functions (e.g., card_del) may reveal similar vulnerabilities.

---
### buffer-overflow-wpatalk-fcn.00402470

- **File/Directory Path:** `sbin/wpatalk`
- **Location:** `wpatalk:0x402470 fcn.00402470`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** A stack-based buffer overflow vulnerability exists in the function fcn.00402470, which processes command-line arguments for wpatalk. The function uses sprintf in a loop to concatenate user-provided arguments into a fixed-size stack buffer (at sp+0x24) without proper bounds checking. When an attacker supplies multiple long arguments, the buffer can be overflowed, potentially overwriting return addresses and allowing arbitrary code execution. The vulnerability is triggered when wpatalk is invoked with crafted arguments, such as in raw command mode or built-in commands like configme or configthem. As a non-root user with login credentials, an attacker could exploit this to achieve privilege escalation if wpatalk is executed with elevated privileges (e.g., setuid root). The overflow occurs due to the unbounded use of sprintf in a loop, with no size limits on the input arguments.
- **Code Snippet:**
  ```
  0x004024a0      8f998078       lw t9, -sym.imp.sprintf(gp) ; [0x4034a0:4]=0x8f998010
  0x004024a4      27b10024       addiu s1, sp, 0x24
  ...
  0x004024d0      0320f809       jalr t9
  0x004024d4      a073000c       sb s3, (var_24h)
  0x004024d8      8fbc0010       lw gp, (var_10h)
  0x004024dc      00511021       addu v0, v0, s1
  0x004024e0     .string "_Q" ; len=2
  0x004024e4      02821821       addu v1, s4, v0
  0x004024e8      8e020000       lw v0, (s0)
  0x004024ec      8f998078       lw t9, -sym.imp.sprintf(gp) ; [0x4034a0:4]=0x8f998010
  0x004024f0      02b12021       addu a0, s5, s1             ; arg1
  0x004024f4      26100004       addiu s0, s0, 4
  0x004024f8      1440fff5       bnez v0, 0x4024d0
  0x004024fc      00402821       move a1, v0
  ```
- **Keywords:** argv, sp+0x24 (stack buffer), sprintf, CONFIGME, CONFIGTHEM
- **Notes:** The vulnerability is in the command processing logic and is reachable via user input. Exploitability depends on the stack layout and mitigations; however, the use of sprintf without bounds checking makes it highly likely. Further analysis is needed to determine if wpatalk has setuid permissions or is called from privileged contexts. Additional functions like fcn.00401688 use fgets with a fixed buffer, which appears safe, but other parts should be reviewed for similar issues.

---
### buffer-overflow-arp-sym.arp_set

- **File/Directory Path:** `usr/arp`
- **Location:** `arp:0x004032c8 sym.arp_set`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** In the sym.arp_set function of the 'arp' binary, a stack buffer overflow vulnerability was discovered. The vulnerability arises when processing the netmask command-line parameter, where the strcpy function is used to directly copy user input into a fixed-size stack buffer (located at fp + 0x1c) without boundary checks. An attacker can trigger the overflow by providing an overly long netmask string (for example, when setting an ARP entry via the -s option), overwriting the return address or critical data on the stack, potentially leading to arbitrary code execution. Trigger condition: The attacker executes the 'arp' command as a non-root user and controls the netmask parameter. Constraints: The buffer size is not explicitly defined, but the stack frame size is 0x108 bytes, and the input length is only limited by the command-line arguments. Potential attack methods include overwriting the return address to jump to malicious code or executing a ROP chain.
- **Code Snippet:**
  ```
  0x004032c8      8c430000       lw v1, (v0)
  0x004032cc      27c2001c       addiu v0, fp, 0x1c
  0x004032d0      00402021       move a0, v0
  0x004032d4      00602821       move a1, v1
  0x004032d8      8f998024       lw t9, -sym.imp.strcpy(gp)  ; [0x405040:4]=0x8f998010
  0x004032dc      0320f809       jalr t9
  0x004032e0      00000000       nop
  ```
- **Keywords:** netmask command-line parameter, obj.device, obj.sockfd
- **Notes:** The vulnerability was confirmed through static analysis but lacks dynamic validation to prove the complete attack chain. Further testing is recommended to verify exploitability, such as examining the stack layout and overwrite points via a debugger. The file permissions are permissive (-rwxrwxrwx), allowing non-root users to exploit it, but the attacker requires command-line access. Related functions: sym.INET_resolve and sym.arp_getdevhw may involve other input processing, but no direct vulnerabilities were found.

---
### command-injection-fcn.00401154

- **File/Directory Path:** `usr/sbin/modem_scan`
- **Location:** `File:modem_scan Address:0x00401154 Function:fcn.00401154`
- **Risk Score:** 6.0
- **Confidence:** 9.0
- **Description:** A command injection vulnerability was discovered in 'modem_scan'. Attackers can inject arbitrary commands through the command line parameter '-f', which is directly passed to the execl call executing '/bin/sh -c param_1', with no input validation or filtering. Trigger condition: run './modem_scan -f "malicious command"', where the malicious command is any shell command. Constraint: The program does not have the setuid bit, commands are executed with the current user's privileges, and root privileges cannot be obtained. Potential attack: Attackers can execute arbitrary commands as a non-root user, used for file operations, network access, or other user-level malicious activities. Exploitation is simple, only requiring valid login credentials and program execution permissions.
- **Code Snippet:**
  ```
  In fcn.00401154:
  (**(loc._gp + -0x7f9c))("/bin/sh","sh","-c",param_1,0);
  where param_1 comes from the command line parameter '-f' and is directly passed to the shell for execution.
  ```
- **Keywords:** Command line parameter '-f', Function fcn.00401154, execl call
- **Notes:** The vulnerability is practically exploitable but offers no privilege escalation; risk is limited to user-level operations. It is recommended to verify if the program is called by other privileged processes to assess potential impact. Subsequent analysis could examine other functions (such as fcn.00400c0c) or strings to identify additional input points.

---
### command-injection-apstart-topology-parsing

- **File/Directory Path:** `sbin/apstart`
- **Location:** `fcn.00400d0c (Multiple locations, for example at command construction: File: Decompiled code Function fcn.00400d0c)`
- **Risk Score:** 5.0
- **Confidence:** 8.0
- **Description:** During the topology file parsing of 'apstart', `sprintf` is used to construct command strings and `system` is called to execute them, but the input is not adequately sanitized or escaped. An attacker can inject shell commands (such as using semicolons or backticks) in the interface name or other fields by creating a malicious topology file. The trigger condition is: the attacker executes `apstart` and specifies the path to the malicious topology file, and does not use the `-dryrun` mode. Potential exploitation methods include executing arbitrary commands as the current user (non-root), which may lead to service disruption, data leakage, or lateral movement, but cannot directly escalate privileges because the file has no setuid bit and runs with the current user's permissions. This is a complete and verifiable attack chain: untrusted input (topology file) → data flow (parsing and command construction) → dangerous operation (system call).
- **Code Snippet:**
  ```
  Example extracted from decompiled code:
  (**(loc._gp + -0x7fbc))(auStack_f8, "ifconfig %s down", iVar17);  // iVar17 from topology file
  iVar9 = fcn.00400c7c(auStack_f8, 0);  // Execute command
  Similar code appears in command constructions for "brctl delbr %s", "wlanconfig %s destroy", etc.
  ```
- **Keywords:** Topology file path, apstart, system, fcn.00400c7c, fcn.00400a4c
- **Notes:** Further verification is needed to determine if it is invoked with higher privileges (e.g., via sudo or setuid) in actual deployments; it is recommended to check the system configuration. Related functions include fcn.00400c7c (command execution) and fcn.00400a4c (file parsing). Subsequent analysis directions include checking other input points (such as environment variables) or interactions with IPC/NVRAM. Based on current analysis, this is a practically exploitable vulnerability chain.

---
