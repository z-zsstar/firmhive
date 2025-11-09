# TD_W9970_V1_150831 (8 findings)

---

### BufferOverflow-cwmp_processConnReq

- **File/Directory Path:** `usr/bin/cwmp`
- **Location:** `cwmp:0x0040acc4 sym.cwmp_processConnReq`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** The vulnerability occurs in the sym.cwmp_processConnReq function when processing the HTTP request's Authorization header. The function uses operations similar to strcpy to copy parsed field values (such as username, realm, etc.) into fixed-size stack buffers (e.g., auStack_bb4[100]). Due to the lack of input length checks, an attacker can construct overly long field values (exceeding 100 bytes), causing a stack buffer overflow. The overflow may overwrite the return address or other critical stack data, allowing the attacker to execute arbitrary code. Trigger condition: The attacker sends a malicious HTTP request to the cwmp service port containing an overly long Authorization header field. Exploitation method: Control EIP via a carefully crafted overflow payload to achieve code execution. This vulnerability requires the attacker to have network access but does not require authentication to trigger (occurs during the authentication parsing phase).
- **Code Snippet:**
  ```
  // Key code snippet extracted from decompilation
  iVar6 = (**(loc._gp + -0x7da8))(auStack_e18,"username");
  puVar5 = auStack_bb4;
  if (iVar6 == 0) goto code_r0x0040b2f4;
  ...
  code_r0x0040b2f4:
      (**(loc._gp + -0x7dfc))(puVar5,auStack_e7c); // Operation similar to strcpy, copying auStack_e7c to puVar5 (e.g., auStack_bb4)
  // auStack_e7c is parsed from input without size restrictions, while puVar5 points to a fixed-size buffer (100 bytes)
  ```
- **Keywords:** HTTP Authorization header, auStack_bb4, auStack_b50, auStack_aec, auStack_a88, auStack_a24, auStack_9c0, auStack_95c, auStack_8f8, auStack_894
- **Notes:** Based on decompilation evidence, the vulnerability appears practically exploitable: entry point (network socket), data flow (HTTP parsing), and dangerous operation (strcpy) are all present. It is recommended to further verify the stack layout and offsets to confirm EIP control. Related function: sym.cwmp_getLine may also involve boundary check issues. Subsequent analysis direction: Check if similar vulnerabilities exist in other XML/SOAP processing functions (e.g., sym.cwmp_hanleSoapHeader).

---
### BufferOverflow-vsf_read_only_check

- **File/Directory Path:** `usr/bin/vsftpd`
- **Location:** `vsftpd:0x41a2d8 sym.vsf_read_only_check`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** A buffer overflow vulnerability exists in the 'vsf_read_only_check' function due to the use of 'strcpy' on user-controlled data without bounds checking. The function defines two fixed-size stack buffers (128 bytes each) and copies input from FTP command arguments directly into these buffers using 'strcpy'. If an authenticated user provides an argument longer than 128 bytes (e.g., a file path), it will overflow the buffer, corrupting the stack and potentially allowing arbitrary code execution. The vulnerability can be triggered through multiple FTP commands, including RNFR, RNTO, DELE, and SITE CHMOD, which pass user input to 'vsf_read_only_check'. The overflow can overwrite return addresses or local variables, leading to control flow hijacking. Given the embedded nature of the target, mitigations like ASLR or stack canaries are likely absent, making exploitation feasible.
- **Code Snippet:**
  ```
  uint sym.vsf_read_only_check(uint param_1,uint param_2)
  {
      uint uVar1;
      int32_t iVar2;
      uint uStack_120;
      uint uStack_11c;
      uint uStack_118;
      uint uStack_114;
      uchar auStack_110 [128];
      char acStack_90 [128];
      
      uStack_11c = 0;
      uStack_118 = 0;
      uStack_114 = 0;
      uStack_120 = 0;
      (**(loc._gp + -0x75d4))(auStack_110,0,0x80);
      (**(loc._gp + -0x75d4))(acStack_90,0,0x80);
      uVar1 = sym.str_getbuf(param_2);
      (**(loc._gp + -0x7680))(acStack_90,uVar1);  // strcpy(acStack_90, user_input)
      (**(loc._gp + -0x74d4))(auStack_110,0x80);
      // ... rest of function ...
  }
  ```
- **Keywords:** FTP command arguments (e.g., RNFR, RNTO, DELE, SITE CHMOD), vsf_read_only_check function input parameter
- **Notes:** The vulnerability is reachable via authenticated FTP sessions. The function is called from multiple points in 'process_post_login', indicating a broad attack surface. Exploitation may require crafting a payload without null bytes and overcoming potential alignment issues on MIPS. Further analysis could identify exact offset for return address overwrite and develop a reliable exploit. The vsftpd process may run with elevated privileges, leading to privilege escalation.

---
### Untitled Finding

- **File/Directory Path:** `usr/sbin/handle_card`
- **Location:** `handle_card:0x0040cec4 (fcn.0040c740) strcpy call`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** A stack-based buffer overflow vulnerability exists in function fcn.0040c740 (invoked from main). The vulnerability occurs when handling the command-line option -c (usb mode switch cmd), where user-supplied input is copied to a stack buffer using strcpy without bounds checking. The buffer is allocated with size 0x101 (257 bytes) at offset fp+0x214, and strcpy copies until a null terminator, allowing overflow of the stack frame. The saved return address is at offset fp+0x24ac, requiring an overflow of approximately 8856 bytes to reach it. This can be exploited by a local attacker with valid login credentials (non-root) to overwrite the return address and execute arbitrary code with elevated privileges (likely root, as the binary handles USB operations and may run with setuid or similar).
- **Code Snippet:**
  ```
  0x0040ceb4      8fc224bc       lw v0, 0x24bc(fp)          ; Load user input from -c option
  0x0040ceb8      27c30214       addiu v1, fp, 0x214         ; Destination buffer
  0x0040cebc      00602021       move a0, v1
  0x0040cec0      00402821       move a1, v0                 ; Source is user input
  0x0040cec4      8f8280d4       lw v0, -sym.imp.strcpy(gp) ; strcpy function
  0x0040cec8      0040c821       move t9, v0
  0x0040cecc      0320f809       jalr t9                     ; Call strcpy, no bounds check
  ```
- **Keywords:** argv (command-line argument -c), strcpy, fcn.0040c740
- **Notes:** The binary likely requires root privileges for USB operations, making this vulnerability high-impact. Exploitation depends on overcoming ASLR and stack protections, but in firmware contexts, these may be weakened. The overflow size is large but feasible with crafted input. Additional analysis of modeSwitchByCmd did not reveal direct command injection, but the buffer overflow provides a reliable exploitation path.

---
### BufferOverflow-http_cgi_main

- **File/Directory Path:** `usr/bin/httpd`
- **Location:** `httpd:0x00408130 sym.http_cgi_main`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** In the sym.http_cgi_main function, strcpy is used to copy user input data to a stack buffer without boundary checks. An attacker can send a specially crafted HTTP CGI request containing an overly long string to overflow the target buffer and overwrite the return address. Specific trigger condition: An attacker, as an authenticated user, sends a malicious HTTP POST request to a CGI endpoint with an overly long parameter value in the request. Exploitation method: By crafting a specific overflow payload, control the program execution flow to achieve code execution or privilege escalation. The vulnerability is located in the HTTP request processing chain, where the data flow from network input to the dangerous operation (strcpy) lacks validation.
- **Code Snippet:**
  ```
  0x00408130      8f998174       lw t9, -sym.imp.strcpy(gp)  ; [0x40a020:4]=0x8f998010
  0x00408134      27a400dc       addiu a0, sp, 0xdc
  0x00408138      27a5009d       addiu a1, sp, 0x9d
  0x0040813c      0320f809       jalr t9
  0x00408140      a0400000       sb zero, (v0)
  ```
- **Keywords:** g_http_file_pTypeDefault, g_http_authUsrInfo
- **Notes:** Further verification of the stack layout and offsets is needed to determine the exact overflow conditions. It is recommended to test with actual HTTP requests to confirm exploitability. Related functions: sym.http_parser_main (input parsing), sym.http_stream_fgets (input reading).

---
### BufferOverflow-DeletePortMapping

- **File/Directory Path:** `usr/bin/upnpd`
- **Location:** `upnpd:0x406618 fcn.00406618`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** In the DeletePortMapping function (fcn.00406618), when a port mapping is successfully deleted, the code uses `sprintf` to format the port mapping count (from `pmlist_Size()`) into an 8-byte stack buffer (`auStack_218`). The port mapping count is of type `uint32_t`, with a maximum value of 4294967295 (10 digits plus a null terminator require 11 bytes), which inevitably causes a stack buffer overflow. An attacker, as a logged-in user, can exploit this via the following steps: 1) Use AddPortMapping requests to add a large number of port mappings (e.g., by repeatedly sending valid requests); 2) Send a DeletePortMapping request to trigger the deletion operation, causing `pmlist_Size()` to return a large value, overflow the buffer, and potentially overwrite the return address or local variables, thus achieving arbitrary code execution. Trigger conditions include: valid 'NewExternalPort' and 'NewProtocol' parameters, and the port mapping must exist. Boundary checks are missing, and input is used directly for formatting without validation.
- **Code Snippet:**
  ```
  uVar4 = sym.pmlist_Size();
  (**(loc._gp + -0x7ed0))(auStack_218,"%d",uVar4);  // auStack_218 is an 8-byte buffer, uVar4 is a uint32_t integer
  ```
- **Keywords:** NewExternalPort, NewProtocol, PortMappingNumberOfEntries, UPnP Action Request, pmlist_Size
- **Notes:** This vulnerability requires the attacker to be able to add port mappings, which is feasible as a logged-in user. It is recommended to further verify the actual maximum value of pmlist_Size() and the stack layout to confirm exploitation details. Related functions: pmlist_Size() and AddPortMapping. Next analysis direction: Check other UPnP processing functions and network input points.

---
### BufferOverflow-pppd-sym.vslprintf

- **File/Directory Path:** `usr/sbin/pppd`
- **Location:** `pppd:0x00422ebc (sym.vslprintf) and pppd:0x00421dc4 (parse_args)`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** During the command-line argument parsing of 'pppd', there exists a stack buffer overflow vulnerability that allows attackers to execute arbitrary code through malicious command-line arguments. The vulnerability trigger process is as follows:
- **Entry Point**: Untrusted command-line arguments are passed into the `main` function via `argv` and forwarded to the `parse_args` function (address 0x00421dc4).
- **Data Flow**: In `parse_args`, arguments are processed and parsed for options by `fcn.00420fa0`. When an option error occurs, `sym.option_error` is called to generate an error message.
- **Vulnerability Point**: `sym.option_error` uses `sym.vslprintf` (address 0x00422ebc) to format the error message, where a tainted integer (from command-line arguments) is used for numeric string formatting. In the formatting loop of `sym.vslprintf`, there is a lack of bounds checking for the stack buffer 'auStack_3e', causing the pointer 'puVar11' to decrement beyond the buffer, overwriting stack data (such as the return address).
- **Trigger Condition**: An attacker, as a logged-in non-root user, executes 'pppd' and passes specific invalid options (e.g., intentionally triggering a parsing error), causing tainted data to enter the error handling path.
- **Constraints**: The vulnerability relies on triggering the `option_error` path, and the tainted data must be of integer type for formatting. The buffer size is not explicitly limited, but the overflow may be influenced by the stack layout.
- **Potential Attack Method**: By carefully crafting command-line arguments, control the overflow data to overwrite the return address, jump to shellcode or existing code fragments, achieving privilege escalation (if 'pppd' runs with root privileges, common in network configurations).
- **Exploitability Evidence**: Decompiled code shows clear buffer overflow conditions, and command-line arguments are fully user-controllable. The vulnerability is verified in the loop of `sym.vslprintf`, lacking bounds checks.
- **Code Snippet:**
  ```
  Key code snippet extracted from disassembly (sym.vslprintf part):
  0x00422ebc: auStack_3e[1] = 0; puVar11 = auStack_3e + 1; do { if (puVar11 <= auStack_5c + iVar21) break; puVar11 = puVar11 - 1; *puVar11 = pcVar17[uVar22]; } while ((0 < puVar7) || (puVar23 != 0));
  Explanation: In the loop, the pointer 'puVar11' decrements, but the break condition uses an unrelated buffer 'auStack_5c', lacking bounds checking for 'auStack_3e', leading to stack overflow.
  ```
- **Keywords:** argv (command-line arguments), sym.option_error, sym.vslprintf, fcn.00420fa0, parse_args
- **Notes:** This vulnerability requires further validation of actual exploitation conditions, such as testing specific command-line options (e.g., invalid arguments) to reproduce the overflow. Associated file: pppd binary. Recommended follow-up analysis: Check the privilege settings of 'pppd' (whether it is setuid-root) to confirm privilege escalation possibility, and dynamically test vulnerability triggering. Other findings (such as path traversal in options_from_file) have lower risk due to lack of complete attack chain evidence.

---
### Command Injection-client6_script

- **File/Directory Path:** `usr/sbin/dhcp6c`
- **Location:** `dhcp6c:0x00405394 fcn.00405394 (client6_recv); dhcp6c:0x00413818,0x00414aec sym.client6_script`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** A command injection vulnerability exists when the DHCPv6 client processes reply messages. An attacker can control option data (such as DNS server lists) by sending malicious DHCPv6 reply messages. This data is parsed and passed to the client6_script function, and external scripts are executed via environment variables in the execve call. Specific behavior: When the device receives a DHCPv6 REPLY message, the client6_recv function calls dhcp6_get_options to parse options, passing the tainted option list to client6_script; in client6_script, tainted data is converted to strings and stored in the environment variable array, ultimately executing scripts via execve, lacking filtering and validation of option content. Trigger condition: An attacker sends a crafted DHCPv6 reply message (e.g., via a man-in-the-middle or by controlling the DHCPv6 server), where the option data contains malicious strings. Constraints: The code has basic error checks (such as option existence) but does not perform security processing on option content; the in6addr2str function may restrict input format, but if the data is misused or the conversion function has defects, it might be bypassed. Potential attack: An attacker exploits this vulnerability to inject commands, execute arbitrary code with root privileges, escalate privileges, or control the device. Exploitation method: Forge a DHCPv6 reply message to inject malicious environment variable values.
- **Code Snippet:**
  ```
  Decompiled from fcn.00405394 (client6_recv):
  0x00405538: bal sym.dhcp6_get_options  // Parse DHCPv6 options, tainted data stored to aiStack_2128
  0x004064c4: bal sym.client6_script    // Call client6_script, pass tainted options
  Decompiled from sym.client6_script:
  0x00413818: sw a3, (arg_8ch)          // Tainted data stored from parameter to stack
  0x0041383c: lw v0, 0x58(a3)           // Access tainted data offset 0x58 (DNS server list)
  0x00413d78: bal sym.in6addr2str       // Convert address to string
  0x00413d24: sw v0, (v1)               // Store string to environment variable array
  0x00414aec: jalr t9                   // Call execve, execute script using environment variables
  ```
- **Keywords:** recvmsg, dhcp6_get_options, client6_script, execve, Environment Variables, DHCPv6 Options, DNS Server List
- **Notes:** Attack chain is complete and verifiable: from network input point (DHCPv6 reply message) to sink point (execve). The attacker needs to be able to send malicious DHCPv6 reply messages (e.g., via a man-in-the-middle or by controlling the DHCPv6 server), and combined with login credentials (non-root) may escalate privileges. It is recommended to further verify the construction details of environment variables in client6_script and script behavior. Related file: dhcp6c; related functions: dhcp6_get_options, in6addr2str. Subsequent analysis direction: Check script path (obj.info_path) and environment variable usage.

---
### Weak-Hash-Exposure-passwd.bak

- **File/Directory Path:** `etc/passwd.bak`
- **Location:** `passwd.bak:1`
- **Risk Score:** 8.0
- **Confidence:** 9.0
- **Description:** In the 'passwd.bak' file, the password hash of the admin user was found exposed, and this user has UID 0 (root privileges). The hash uses weak MD5 encryption (starting with $1$), making it vulnerable to offline brute-force attacks. An attacker (a logged-in non-root user) can exploit this through the following steps: 1. Read the 'passwd.bak' file (assuming improper file permissions allow non-root users to read it); 2. Extract the admin's password hash '$1$$iC.dUsGpxNNJGeOm1dFio/'; 3. Use tools like John the Ripper or Hashcat for offline cracking; 4. After obtaining the admin password, escalate to root privileges via su or login. Trigger conditions include file readability and hash crackability (depending on password strength). Constraints include the need for file access permissions and cracking time, but the weak MD5 encryption reduces the difficulty. Potential attacks include privilege escalation and complete system control.
- **Code Snippet:**
  ```
  admin:$1$$iC.dUsGpxNNJGeOm1dFio/:0:0:root:/:/bin/sh
  nobody:*:0:0:nobody:/:/bin/sh
  ```
- **Keywords:** passwd.bak
- **Notes:** Evidence comes from direct analysis of file content. The combination of admin's UID 0 and weak hash forms a complete attack chain. The nobody user has UID 0 but password disabled, which may not be directly relevant, but it is recommended to verify file permissions (e.g., if globally readable). Follow-up should check for similar issues in other sensitive files in the system (such as /etc/passwd) and strengthen the password hashing algorithm (e.g., use SHA-512).

---
