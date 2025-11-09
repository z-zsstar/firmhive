# _US_AC15V1.0BR_V15.03.05.18_multi_TD01.bin.extracted (23 findings)

---

### key-exposure-privkeySrv.pem

- **File/Directory Path:** `webroot_ro/pem/privkeySrv.pem`
- **Location:** `privkeySrv.pem`
- **Risk Score:** 9.5
- **Confidence:** 10.0
- **Description:** The file 'privkeySrv.pem' contains a valid RSA private key in PEM format. It has world-readable, writable, and executable permissions (-rwxrwxrwx), allowing any user, including non-root users with valid login credentials, to read and potentially modify the private key. This exposure enables attackers to steal the key, which could be used to decrypt secure communications (e.g., TLS/SSL traffic), impersonate the server, perform man-in-the-middle attacks, or forge digital signatures if the key is actively used by services. The trigger condition is straightforward: an attacker simply needs to read the file, which requires no elevated privileges or complex exploitation steps. Constraints include the key's validity and its usage in cryptographic operations, but the lack of access controls makes exploitation highly probable.
- **Code Snippet:**
  ```
  -----BEGIN RSA PRIVATE KEY-----
  MIIEowIBAAKCAQEAp/iFMY2xpU6y9OMkor5N1SOR8mhRJ4aTBEC/5639e5x3zrV5
  fcKr2A9a4kAZbfDKwG+uBF0pvKVbFJK3tqRdnCHK1miIDPAHSN11NFXKr4gHslq3
  21RZLCQPAlLtMgzQR9/pgahweKDkZPCturdajZl7lXhptN8AKlUTGnVxSK9g8JFf
  lwR2Bq5jwrGHjmzkZzyRkY8l+GFD6Ru1eX5LH0rBHoSg1nmX8k/vApIpq1sLzbeB
  ap6wnnVqJ8mI3PsqPXAIDRvHxH97SCCeVVh1jdenau0OKHWLlhVp1vnIj5CfSyCf
  VRPAfS2s9yGz8+tdVW8M6NeJY3hMm61g2BxZkwIDAQABAoIBADgu71ZI38+8SC2T
  QHDTGLOfJzUe4W5IHCrDAa2by/qptoVEvDNthw9I64xcBmV4ski10k4RX2GDKbjy
  7lJAHjOYNgGLi15Qdw9PS+HKhHY8GN72ayMIzp7uHLsZQ8+G66/u3GsLDTu8DUka
  G/IlXDuax/SSB0GBicufEzm5aL/3poIAwJkqdmBvNu52qPhpeiMhDHRS8ReX0fZu
  lqf23I/jAxQ+JL+Li1z8EqUTGl3QdT+5oBl+LMTOJtjhay0JIKCIbefma7KO0bg/
  1ed0IsBVZnS3IKcUuFAozFNi8bFMPC6SuMVwVZQAtn4NbxsL/negsDnxf9gh0CsR
  InqTBIkCgYEA3R0pswbD3uV7RW7G3086AEUMqIhXSN7jbnL6jrbiQ9o65Yd5JvhQ
  oaJkw2nF6RrBKd76azE3HEJduhJTcE8FIW8HmfFCZyTDTqUlA71sG/MRw90CszBd
  iS3UGlpbSjhCLMhP5TkzzVrl0AhdeMgKzXdXbC3/fv2ibjEpGL1DIt0CgYEAwnjl
  Jn9gX1H/E2CXpI5BcpQPYSGcDARI5rsPYEH3i4qHiZICRg4JoV6mzFXTZOifW+MM
  1Aq8I5gkrZuPY/S8/WaKXLRLOOIJ1PGJSIDYsWt/WrrkuNw2nRZ1gb9/YbD8JQ0T
  avCYAt9QXuc5JAf0Hfw1dLf5aHKLoFjp+0nWDy8CgYB2w5A/QZX5Zic1HxAgp8xO
  ksf+yeSgFl/wVj+wYhjcOx5BZOe0/9FHUBNxRqHv19gC5mp5IuEoA5mWNPuuKjNm
  Rt29WPHCtuNUna1o+dhUltVm75Hgr0y+PuhbE0dPcTJSHXGUfIoPdhBUEfoqwr/S
  ppRFXduK2S7iovMg/59M3QKBgB/K19t1U3IB26t1TRUv1G9A2UrNzc8BHFHsHtVj
  s25ylTneTtTZEqX47VfWaBrFFNhWxBAeOSewhb6EAesbZZIfo1sIdou0GFthqUnb
  FpHauxVAHIhEKAGCXG97uP1li7Ma8iO3dYJys5bwQh0r17LXOn38XZ+/qifqoUXd
  ikstAoGBAKfg2UO030hq71xhPoT3OxehgSgT2cTD3vIyoUqiriB/8Zu2xmBjvx3c
  IMdjjimvfrsxeR71fviWKRRU61REkZD7KAa0VF2ekhuUqyUIbte08KJrls8PF/IJ
  71wT0dGe6kZ8s7hIx/arnYZXPHGwqL5Z68+O0p8t3KlBPsOzVV89
  -----END RSA PRIVATE KEY-----
  ```
- **Keywords:** privkeySrv.pem
- **Notes:** The private key exposure is critical and requires immediate remediation, such as restricting file permissions to root-only access and rotating the key if it has been compromised. Further analysis should verify if this key is used by any services (e.g., web servers, VPNs) to fully assess the impact. Additionally, check for corresponding public keys or certificates in the system to understand the scope of potential attacks.

---
### Vulnerability-group-permissions

- **File/Directory Path:** `etc_ro/group`
- **Location:** `group`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** The file 'group' has global read and write permissions (777), allowing any user to modify system group definitions. An attacker as a non-root user can directly edit this file to add their username to the root group (for example, changing 'root:x:0:' to 'root:x:0:attacker'). After modification, the attacker can activate root group privileges by re-logging into the session or using the 'newgrp root' command, thereby gaining root-level system access. The trigger condition is simple: the attacker only needs file write permission (already satisfied), and the system relies on this file for group verification (typical behavior). The exploitation method is direct, requires no complex steps, and has a high success rate.
- **Code Snippet:**
  ```
  File content: root:x:0:
  File permissions: -rwxrwxrwx 1 user user 10 May 10 2017 group
  ```
- **Keywords:** group
- **Notes:** This vulnerability relies on the system reading the group file in real-time or activating changes via commands; in standard Unix-like systems, group changes typically take effect in new sessions or after using 'newgrp'. It is recommended to further verify how the system loads group information (for example, check if NSS or cache is used) and check if other related files (such as 'passwd' or 'shadow') have similar permission issues. This finding may be related to the system authentication mechanism and requires manual confirmation of the actual usage scenario of the group file in the firmware.

---
### command-injection-fcn.0000ae64

- **File/Directory Path:** `bin/cfmd`
- **Location:** `cfmd:0xae64 fcn.0000ae64`
- **Risk Score:** 9.0
- **Confidence:** 8.5
- **Description:** The 'cfmd' daemon contains a command injection vulnerability that allows authenticated non-root users to execute arbitrary commands with root privileges. The attack chain starts from the Unix domain socket '/var/cfm_socket', which is accessible to non-root users due to missing permission restrictions. When a client connects, messages are received and processed by functions like RecvMsg and passed to command execution via doSystemCmd. In function fcn.0000ae64, user-controlled data from NVRAM variables or socket messages is incorporated into system commands using sprintf and then executed via doSystemCmd without proper input validation or sanitization. For example, commands like 'ifconfig' and 'reboot' are constructed with user input, allowing injection of shell metacharacters. An attacker can exploit this by sending crafted messages to the socket or manipulating NVRAM variables to execute arbitrary commands, leading to full system compromise.
- **Code Snippet:**
  ```
  // Example from fcn.0000ae64 decompilation:
  // User input from NVRAM or socket is used in sprintf
  sprintf(buffer, "ifconfig %s hw ether %s", interface, user_controlled_mac);
  doSystemCmd(buffer);
  // No validation on user_controlled_mac, allowing injection of commands like "; malicious_command"
  ```
- **Keywords:** /var/cfm_socket, bcm_nvram_get, bcm_nvram_set, doSystemCmd
- **Notes:** The vulnerability requires the attacker to have access to the Unix socket, which may be world-writable based on default permissions. Further verification is needed on the socket permissions in a live system. The function fcn.0000ae64 handles multiple system commands, and similar patterns may exist in other functions. Recommended to check all uses of doSystemCmd and sprintf/strcpy for similar issues.

---
### Untitled Finding

- **File/Directory Path:** `lib/modules/privilege_ip.ko`
- **Location:** `privilege_ip.ko:0x08000228 (fcn.080001e8) and 0x08000398 (pi_rcv_msg)`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** A buffer overflow vulnerability exists in the 'privilege_ip.ko' kernel module due to lack of bounds checking when adding entries to the global array 'g_k_privi_ip_item'. The function 'fcn.080001e8' (called from 'pi_rcv_msg' with arg1=0) uses memcpy to copy 8 bytes of user-controlled data from message parameters into the array. The array size is fixed at 60 elements (480 bytes), but the count stored at offset 0x1e0 in the global structure is incremented without checking against the array limit. An attacker can send more than 60 messages of type 0 to overflow the array, corrupting adjacent kernel memory. This can lead to kernel crash or privilege escalation by overwriting critical data structures. The vulnerability is triggered when processing messages via 'pi_rcv_msg', which is likely registered as a message handler during module initialization.
- **Code Snippet:**
  ```
  In fcn.080001e8:
  0x08000228: add r0, r5, r7, lsl 3  ; r5 points to g_k_privi_ip_item, r7 is the current index
  0x0800022c: bl memcpy        ; copies 8 bytes from r6 (user data) to the array
  0x08000298: str r2, [r3, 0x1e0]  ; increments the count without bounds check
  
  In pi_rcv_msg:
  0x080003e0: ldr r6, [r5], 4   ; loads message type
  0x0800041c: bl fcn.080001e8   ; called when type is 0
  0x08000430: bl fcn.080001e8   ; called for other types
  ```
- **Keywords:** g_k_privi_ip_item, pi_rcv_msg, fcn.080001e8
- **Notes:** The vulnerability is highly exploitable as it allows controlled kernel memory corruption. The attack requires sending multiple messages to 'pi_rcv_msg', which must be accessible to the attacker. Further verification is needed on how 'pi_rcv_msg' is invoked (e.g., via IPC or sysfs), but the code logic confirms the overflow. Exploitation could lead to full system compromise. Recommended to test in a controlled environment and patch by adding bounds checks in fcn.080001e8.

---
### StackOverflow-qos_proc_write_debug_level

- **File/Directory Path:** `lib/modules/qos.ko`
- **Location:** `qos.ko:0x080009e8 sym.qos_proc_write_debug_level`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** In the qos_proc_write_debug_level function of the qos.ko module, a stack buffer overflow vulnerability was discovered. This function processes user input through the proc filesystem. When using sscanf to parse the input string, the format string contains a %s specifier without a width limit (e.g., 'debug_level=%d,%s'), causing user-controllable data to overflow the local buffer on the stack. Trigger condition: An attacker writes a string exceeding the stack buffer size (e.g., containing a long IP address or debug data) to /proc/qos/debug_level. Constraint: The input size is limited to 0x1000 bytes, but the stack buffer size is limited (approximately 0x4c bytes). The overflow may overwrite saved registers (including lr), thereby controlling the program counter. Potential attack method: A carefully crafted input can overwrite the return address, execute arbitrary code in kernel mode, escalate privileges, or cause a system crash. Related code logic includes copy_from_user copying user data to a kernel buffer, followed by sscanf parsing without boundary checks.
- **Code Snippet:**
  ```
  0x080009e8: ldr r1, [0x08000b74]  ; Load format string address (e.g., 'debug_level=%d,%s')
  0x080009ec: add r2, sp, 0x44      ; Local buffer address
  0x080009f0: mov r3, r7
  0x080009f4: bl sscanf               ; Parse input, using %s without boundary check
  ...
  0x08000a48: ldr r6, [sp, 0x14]   ; Stack location potentially affected by overflow
  ```
- **Keywords:** /proc/qos/debug_level, g_qos_debug_level
- **Notes:** The vulnerability has been verified through disassembly, and a complete attack chain exists: user input -> proc write -> copy_from_user -> sscanf overflow -> return address overwrite. It is recommended to further verify triggering the vulnerability through dynamic testing. Related functions include qos_proc_write_enable (but no similar vulnerability was found). Subsequent analysis should focus on other input points such as qos_rcv_msg and IPC communication.

---
### BufferOverflow-fastnat_conf_proc_port_add

- **File/Directory Path:** `lib/modules/fastnat_configure.ko`
- **Location:** `fastnat_configure.ko:0x080003f4 sym.fastnat_conf_proc_port_add`
- **Risk Score:** 8.5
- **Confidence:** 9.0
- **Description:** The function 'sym.fastnat_conf_proc_port_add' in the 'fastnat_configure.ko' kernel module handles user input from the /proc filesystem entry 'port_add'. It expects input in the format 'layer=%s protocol=%s port=%d' and uses strchr to locate delimiters ('=' and ',') before copying the substring fields into fixed-size stack buffers (16 bytes each) via memcpy. However, no bounds checking is performed on the length of these substrings, allowing stack buffer overflow if any field exceeds 16 bytes. Trigger conditions include writing a malformed string with long 'layer', 'protocol', or 'port' fields to the proc entry. This can corrupt the kernel stack, overwriting adjacent variables or return addresses, leading to denial-of-service or arbitrary code execution in kernel context. Potential attacks involve crafting input to overwrite critical stack data and hijack control flow. The code logic involves multiple memcpy operations (e.g., at addresses 0x08000550, 0x080005a8, 0x08000604) without size validation.
- **Code Snippet:**
  ```
  0x08000550      feffffeb       bl memcpy                   ; Copy to var_1ch (layer buffer)
  0x080005a8      feffffeb       bl memcpy                   ; Copy to var_ch (protocol buffer)
  0x08000604      feffffeb       bl memcpy                   ; Copy to var_2ch (port buffer)
  // Stack buffers are 16 bytes each, defined via 'var_2ch', 'var_1ch', 'var_ch'
  ```
- **Keywords:** proc_fastnat_port_add, /proc/fastnat/port_add
- **Notes:** The vulnerability is directly exploitable if the /proc entry is writable by non-root users, which is common in embedded systems. Attack chain involves user writing to /proc/fastnat/port_add with oversized fields. Further analysis should verify proc entry permissions and test for exploitability. Related functions like 'sym.fastnat_conf_proc_port_del' may have similar issues and should be examined.

---
### Command-Injection-formexeCommand

- **File/Directory Path:** `bin/httpd`
- **Location:** `httpd:0x7bc0c sym.formexeCommand`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** A command injection vulnerability was discovered in the 'formexeCommand' function of 'httpd'. This function processes user input from HTTP requests and executes system commands via 'doSystemCmd'. User input is obtained through 'fcn.0002babc' and copied to a fixed-size buffer (512 bytes) using 'strcpy', lacking boundary checks. Subsequently, the input is directly passed to 'doSystemCmd', allowing attackers to inject malicious commands. Trigger condition: An attacker sends a specially crafted HTTP request to an exposed CGI endpoint (such as paths related to '/cgi-bin/'), requiring valid login credentials. Exploitation method: Embed command separators (such as ';', '|', or backticks) in the input to inject arbitrary commands for execution, potentially leading to privilege escalation or device control.
- **Code Snippet:**
  ```
  // Get data from user input
  uVar2 = fcn.0002babc(*(puVar5 + (0xdcec | 0xffff0000) + iVar1 + -0xc), iVar4 + *0x7befc, iVar4 + *0x7bf00);
  *(puVar5 + -0xc) = uVar2;
  // Copy input to buffer using strcpy, lacking boundary checks
  sym.imp.strcpy(puVar5 + iVar1 + -0x21c, *(puVar5 + -0xc));
  // Directly execute system command using user input
  sym.imp.doSystemCmd(iVar4 + *0x7bf14, puVar5 + iVar1 + -0x21c);
  ```
- **Keywords:** HTTP request parameters, CGI processing endpoint, doSystemCmd function call, fcn.0002babc input acquisition
- **Notes:** Complete attack chain: from HTTP input point to command execution. Need to verify actual HTTP endpoint paths and authentication mechanisms. It is recommended to check other functions that call doSystemCmd (such as formMfgTest) for similar issues. Subsequent analysis should focus on the input validation function (such as fcn.0002babc) and the implementation of doSystemCmd.

---
### command-injection-usbeject-handler

- **File/Directory Path:** `usr/bin/app_data_center`
- **Location:** `app_data_center:0x0000a6e8 fcn.0000a6e8`
- **Risk Score:** 8.5
- **Confidence:** 8.0
- **Description:** In function fcn.0000a6e8 (handling the 'usbeject' command), an attacker can inject arbitrary commands by controlling the 'dev_name' parameter. This parameter is extracted from user input without filtering or escaping, and is directly embedded into the fixed format string 'cfm post netctrl 51?op=3,string_info=%s', which is then executed via the system function. Trigger condition: An attacker, as an authenticated user (non-root), sends a malicious HTTP request (POST or GET) to invoke the 'usbeject' command and provides a controllable 'dev_name' parameter. Constraint: Input length is limited by the snprintf buffer (0x800 bytes), but command injection is still feasible. Potential attack methods: Injecting semicolons or command separators (e.g., '; rm -rf /' or a reverse shell), leading to arbitrary command execution, which may escalate privileges or damage the system.
- **Code Snippet:**
  ```
  Key code snippet:
    - 0x0000a730: ldr r0, [var_818h] ; movw r1, 0xaef0 ; movt r1, 1 ; bl fcn.00009b30  // Extract 'dev_name' value
    - 0x0000a7ac: ldr r3, [var_14h] ; mov r2, r3 ; bl sym.imp.snprintf  // Use snprintf to build command string, format is 'cfm post netctrl 51?op=3,string_info=%s'
    - 0x0000a7c0: bl sym.imp.system  // Execute command, injection risk exists
  ```
- **Keywords:** param_3 (dev_name), Command string 'cfm post netctrl 51?op=3,string_info=%s', Environment variable REQUEST_METHOD, Environment variable QUERY_STRING
- **Notes:** This vulnerability requires the attacker to have valid login credentials (non-root user) and to invoke the 'usbeject' command through a network interface (such as an HTTP API). Related functions: fcn.00009de8 (command dispatcher), fcn.00009b30 (key-value extractor). It is recommended to verify the actual exploitation steps, for example, by injecting commands through crafted HTTP requests. Subsequent analysis should check if other command handling functions (such as 'request', 'usblist') have similar issues.

---
### BufferOverflow-fcn.00015aa8

- **File/Directory Path:** `usr/sbin/nas`
- **Location:** `nas:0x16124 fcn.00015aa8`
- **Risk Score:** 8.0
- **Confidence:** 8.0
- **Description:** A buffer overflow vulnerability exists in the 'nas' binary due to the use of strcpy without bounds checking in function fcn.00015aa8. The vulnerability is triggered when processing the '-p' command-line option, where user-supplied input is copied to a stack buffer. Specifically, when the input string length is exactly 5 or 13 characters, strcpy is used to copy the string to a local buffer without size validation, leading to a stack-based buffer overflow. This can overwrite critical stack data, including the return address, allowing an attacker to execute arbitrary code. The attack requires the attacker to have valid login credentials and access to the command-line interface, but no root privileges are needed.
- **Code Snippet:**
  ```
  // From fcn.00015aa8 decompilation
  switch(iVar8 + -5) {
  case 0:
  case 8:
      uVar4 = sym.imp.strlen(*(puVar9 + -0xc));
      *(puVar9 + -0x10) = uVar4;
      sym.imp.strcpy(puVar9 + iVar1 + -0x7c, *(puVar9 + -0xc)); // Vulnerable strcpy call
      break;
  // ... other cases ...
  }
  ```
- **Keywords:** Command-line option: -p, Function: fcn.00015aa8, Function: fcn.00014704, Imported function: strcpy
- **Notes:** The vulnerability is directly exploitable via command-line input, and the attack chain is verified through static analysis. However, dynamic testing is recommended to confirm the exact stack layout and exploitation feasibility. The binary is stripped, which may complicate analysis, but the vulnerability is clear. Additional vulnerabilities may exist in other functions, but this is the most prominent finding.

---
### format-string-insert_user_in_smbpasswd

- **File/Directory Path:** `usr/sbin/smbpasswd`
- **Location:** `smbpasswd:0x00001a00 sym.insert_user_in_smbpasswd fprintf call`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** In the insert_user_in_smbpasswd function, the fprintf call directly uses a user-controlled string as the format string without providing additional arguments. This allows an attacker to inject format specifiers (such as %s, %x) to leak stack memory information, potentially leading to sensitive information disclosure or memory corruption. Trigger condition: When using the '-a' option to add a user, the username or password input is used to construct the string passed to fprintf. Potential attack: A logged-in non-root user can read stack memory through malicious input, potentially obtaining system information or aiding in privilege escalation. Exploitation method: The attacker controls the username or password in the command line input, inserting format specifiers.
- **Code Snippet:**
  ```
  From the decompiled code, key line: \`fprintf(iVar1, param_2);\` // param_2 directly used as format string, no additional arguments
  ```
- **Keywords:** smbpasswd, String constructed by snprintf in the main function
- **Notes:** Vulnerability based on decompilation and taint tracking evidence; user input flows from the command line through snprintf to fprintf. Attack chain is complete: input point (command line arguments) → data flow (snprintf construction) → dangerous operation (fprintf). Further testing is recommended to confirm the specific content of the leak, but evidence indicates high practical exploitability.

---
### XSS-initRuleList

- **File/Directory Path:** `webroot_ro/js/parental_control.js`
- **Location:** `parental_control.js: initRuleList function (approximately lines 200-210)`
- **Risk Score:** 7.5
- **Confidence:** 7.0
- **Description:** In the rule list display function of parental_control.js, the device name (devName) user input is not escaped when output to HTML, and is directly inserted into HTML attributes and content via string concatenation. This allows attackers to inject malicious script code. Trigger condition: An attacker sets a device name containing an XSS payload (e.g., '<script>alert(1)</script>'), then views the rule list by clicking interface elements (such as 'head_title2'), causing script execution. Potential attacks include stealing session cookies, performing arbitrary actions, or escalating privileges. The device name validation in the code relies on the external function checkDevNameValidity, which is not defined in the current file, so it cannot be confirmed if filtering is sufficient. Data flow: User inputs device name -> Saved to backend via AJAX -> Retrieved from backend and displayed in rule list -> Output without escaping.
- **Code Snippet:**
  ```
  str += "<tr class='tr-row'><td class='fixed' title='" + obj[i].devName + "'>" + obj[i].devName + "</td>" + "<td title='" + obj[i].mac + "'>" + _("MAC address:") + obj[i].mac.toUpperCase() + "</td>";
  // Subsequent use of $('#rule_list #list2').html(str) to insert HTML
  ```
- **Keywords:** devName, obj[i].devName, goform/SetOnlineDevName, goform/getParentalRuleList
- **Notes:** The device name validation functions checkDevNameValidity and clearDevNameForbidCode are not defined in the current file. Further analysis of backend code (e.g., 'goform' handlers) is required to confirm if input filtering and storage are secure. The attack chain relies on the backend returning unfiltered data, but the lack of escaping in the frontend output is conclusive evidence. It is recommended to verify if the backend performs HTML escaping or strict filtering on device names.

---
### XSS-showFinish

- **File/Directory Path:** `webroot_ro/js/index.js`
- **Location:** `index.js: Approximately line 600, showFinish function`
- **Risk Score:** 6.5
- **Confidence:** 9.0
- **Description:** A stored XSS vulnerability was discovered in the 'index.js' file. An attacker can set a malicious SSID (WiFi name) value, and when the setup completion page displays the SSID, the embedded JavaScript code will be executed. The specific trigger condition is: after an attacker logs into the device, they modify the SSID to a malicious script (e.g., `<script>alert('XSS')</script>`) on the quick setup or WiFi settings page, and then complete the setup process. When a user or attacker visits the setup completion page (for example, via the 'showFinish' function), the malicious script executes. This vulnerability allows an attacker to steal session cookies, redirect users, or modify page content, but because the attacker already possesses login credentials, the risk is partially mitigated. The root cause is the lack of HTML escaping for user input in the code.
- **Code Snippet:**
  ```
  function showFinish() {
      // ... other code ...
      $("#ssid_2g").html($("#ssid").val());
      $("#ssid_5g").html($("#ssid").val() + "_5G");
      // ... other code ...
  }
  ```
- **Keywords:** SSID input field, goform/fast_setting_wifi_set API endpoint, showFinish function
- **Notes:** This vulnerability requires the attacker to have login credentials, but once exploited, it can lead to session hijacking. It is recommended to implement strict filtering and escaping for SSID input on the backend. Furthermore, other user input points (such as LAN IP, DNS settings) should be checked for similar issues. Subsequent analysis should focus on how the backend 'goform' endpoints handle these inputs to identify potential command injection or other vulnerabilities.

---
### DoS-formSetWanErrerCheck

- **File/Directory Path:** `bin/dhttpd`
- **Location:** `dhttpd:0x00034ca0 formSetWanErrerCheck`
- **Risk Score:** 6.5
- **Confidence:** 7.5
- **Description:** The function 'formSetWanErrerCheck' contains a DoS vulnerability, allowing authenticated users to trigger the 'killall -9 dhttpd' command via the HTTP parameter 'no-notify'. Specific attack chain: 1) User sends an HTTP request (e.g., POST to /goform) containing the parameter 'no-notify=true'; 2) The function uses 'fcn.000153cc' to obtain the parameter value and compares it with a hardcoded string (inferred to be 'true'); 3) If it matches, sets the NVRAM variable 'wan.dnsredirect.flag' and executes 'doSystemCmd' to call 'killall -9 dhttpd'; 4) Causes the web server to terminate, resulting in DoS. Attack conditions: The attacker is authenticated (non-root) but does not require special privileges. The vulnerability lacks input filtering, relies on hardcoded comparison, and is easily exploitable.
- **Code Snippet:**
  ```
  0x00034d38      0310a0e1       mov r1, r3                  ; 'no-notify' parameter
  0x00034d3c      e8309fe5       ldr r3, [0x00034e2c]        ; hardcoded string address
  0x00034d40      033084e0       add r3, r4, r3              ; hardcoded string 'ture' (likely 'true')
  0x00034d44      0320a0e1       mov r2, r3                  ; compare strings
  0x00034d48      9f81ffeb       bl fcn.000153cc             ; get parameter value
  ...
  0x00034d70      14101be5       ldr r1, [s2]                ; parameter value
  0x00034d74      7d53ffeb       bl sym.imp.strcmp           ; string comparison
  0x00034d78      0030a0e1       mov r3, r0
  0x00034d7c      000053e3       cmp r3, 0                   ; check if match
  0x00034d80      0a00001a       bne 0x34db0                 ; jump if no match
  ...
  0x00034da4      033084e0       add r3, r4, r3              ; 'killall -9 dhttpd' command string
  0x00034da8      0300a0e1       mov r0, r3                  ; command parameter
  0x00034dac      3f53ffeb       bl sym.imp.doSystemCmd      ; execute dangerous command
  ```
- **Keywords:** HTTP parameter: no-notify, NVRAM variable: wan.dnsredirect.flag, Command: killall -9 dhttpd, Function: fcn.000153cc, IPC/Network interface: HTTP request processing
- **Notes:** Attack chain is complete: from HTTP input to command execution. Hardcoded string is likely 'true', inferred from context. Vulnerability requires authentication but is simple to exploit. Recommended fix: add input validation or remove hardcoded command. No privilege escalation or code execution found.

---
### XSS-onlineQueryVersion

- **File/Directory Path:** `webroot_ro/js/directupgrade.js`
- **Location:** `directupgrade.js:50-70 (onlineQueryVersion function)`
- **Risk Score:** 6.5
- **Confidence:** 7.0
- **Description:** In the onlineQueryVersion function in 'directupgrade.js', the description fields (including description, description_en, description_zh_tw) returned by the server are directly inserted into HTML without escaping, leading to a Cross-Site Scripting (XSS) vulnerability. Specific trigger condition: when a user visits the firmware upgrade page, the application retrieves version information from the server via an AJAX request and dynamically adds the description content to the DOM. If an attacker can tamper with the server response (e.g., via a man-in-the-middle attack or by controlling the server) and inject malicious JavaScript code, arbitrary scripts can be executed in the user's browser. Exploitation methods include stealing session cookies, redirecting users, or performing other malicious actions. The code logic lacks validation and filtering of input data, directly using innerHTML equivalent operations. The attack chain is complete: from untrusted input (server response) to dangerous operation (HTML insertion execution).
- **Code Snippet:**
  ```
  var description = ver_info.detail.description;
  if (language == "en") {
      description = ver_info.detail.description_en;
  } else if (language == "cn") {
      description = ver_info.detail.description;
  } else if (language == "zh") {
      description = ver_info.detail.description_zh_tw;
  }
  if (description) {
      descriptionArr = description.join("").split("\n");
  } else {
      descriptionArr = ver_info.detail.description[0].split("\n");
  }
  $("#releaseNote").html("");
  for (var i = 0; i < descriptionArr.length; i++) {
      $("#releaseNote").append("<li>" + descriptionArr[i] + "</li>");
  }
  ```
- **Keywords:** ver_info.detail.description, ver_info.detail.description_en, ver_info.detail.description_zh_tw, goform/cloudv2?module=olupgrade&opt=queryversion
- **Notes:** This vulnerability requires the attacker to control the server response or perform a man-in-the-middle attack, so exploitability depends on the network environment. It is recommended to further analyze the backend handler (e.g., 'goform/cloudv2') to confirm the data source and validation mechanisms. Additionally, the file upload function (via 'goform/SysToolSetUpgrade') might also be vulnerable, but requires backend code analysis. The attacker is a logged-in user, but exploitation might require additional conditions such as network control.

---
### heap-buffer-overflow-fcn.00010364

- **File/Directory Path:** `bin/vsftpd`
- **Location:** `vsftpd:0x1048c fcn.00010364`
- **Risk Score:** 6.5
- **Confidence:** 7.0
- **Description:** A heap buffer overflow vulnerability was discovered in function fcn.00010364. This function processes FTP command input (potentially involving path or filename operations), using 'strcpy' to copy user-controllable data into a dynamically allocated heap buffer. The allocated size is calculated based on the input string, but if the source string length exceeds the allocated size, it leads to a heap buffer overflow. An attacker, as an authenticated user, can trigger this vulnerability by sending an FTP command (such as CWD) with a specially crafted long path, potentially overwriting heap metadata or function pointers, leading to code execution. Vulnerability trigger conditions include: the user must possess valid login credentials, send a specific FTP command, and provide an overly long string. Potential exploitation methods include arbitrary code execution via heap overflow or service crash.
- **Code Snippet:**
  ```
  else {
      uVar1 = sym.imp.malloc(*(iVar4 + *0x105e8 + 8) - *(puVar5 + -8));
      *(iVar4 + *0x105f0) = uVar1;
      *(iVar4 + *0x105f0 + 4) = *(iVar4 + *0x105e8 + 4) - *(puVar5 + -8);
      *(iVar4 + *0x105f0 + 8) = *(iVar4 + *0x105e8 + 8) - *(puVar5 + -8);
      sym.imp.strcpy(*(iVar4 + *0x105f0), *(puVar5 + -0xc) + *(puVar5 + -8));
  }
  ```
- **Keywords:** NVRAM variables indirectly affect via nvram_xfr calls, FTP command channel as input point
- **Notes:** This vulnerability requires further validation of the specific FTP command trigger path and heap exploitation feasibility. It is recommended to analyze the heap manager and environment to confirm exploitability. Related functions include fcn.0000df94 (main command processing loop) and fcn.0001a0ac (command string comparison).

---
### BufferOverflow-vmstat-fcn.00009300

- **File/Directory Path:** `usr/bin/vmstat`
- **Location:** `vmstat:0x00009300 fcn.00009300 (Specific instruction address needs to be confirmed via disassembly, but the call point is in the case 0x10 branch)`
- **Risk Score:** 6.5
- **Confidence:** 7.0
- **Description:** In the 'vmstat' binary, the command-line argument processing function (fcn.00009300) uses the strcpy function to copy user-provided arguments to a fixed buffer (address *0xa1e8) without performing bounds checking. An attacker, as a non-root user, can trigger a buffer overflow by passing an excessively long command-line argument (for example, using a specific option like '-C' followed by a long string). The overflow may overwrite the return address or local variables on the stack, leading to arbitrary code execution in the user context. Trigger condition: Execute 'vmstat' with malicious command-line arguments. Potential attack method: Construct shellcode or a ROP chain, but requires bypassing ASLR and determining the exact offset. The vulnerability is due to a lack of input validation and the use of dangerous functions.
- **Code Snippet:**
  ```
  // From decompiled code snippet (fcn.00009300)
  case 0x10:
      ppcVar15 = ppcVar15 + 1;
      pcVar3 = *ppcVar15;
      if (pcVar3 == NULL) {
          uVar7 = *0xb5b4;
          uVar9 = 0x18;
          // ... Error handling
      }
      // ... Argument comparison logic
      sym.imp.strcpy(*0xa1e8, *ppcVar15);  // Vulnerability point: strcpy without bounds checking
      break;
  ```
- **Keywords:** *0xa1e8, Command-line arguments
- **Notes:** The buffer size is unknown, and the binary is stripped, increasing the exploitation difficulty. The attacker needs to execute locally but could combine with other vulnerabilities to increase impact. It is recommended to further analyze the buffer layout and test crash points. Related functions: fcn.00009300 (main command-line processing), strcpy (dangerous function). Subsequent checks could examine other input points (such as file reading) and component interactions.

---
### FilePermission-Shadow

- **File/Directory Path:** `etc_ro/shadow`
- **Location:** `shadow:1`
- **Risk Score:** 6.5
- **Confidence:** 6.0
- **Description:** Non-root users can read the 'shadow' file due to permissive file permissions (rwxrwxrwx), obtaining the root user's password hash (MD5 format). Attackers can use this hash for offline cracking (e.g., using tools like John the Ripper or Hashcat). If the password is weak, root privileges may be obtained. The trigger condition is that a non-root user has file read permission; constraints include password complexity, hash algorithm strength (MD5 is relatively weak), and availability of cracking tools. Potential attack methods include privilege escalation via su or ssh after password cracking.
- **Code Snippet:**
  ```
  root:$1$OVhtCyFa$7tISyKW1KGssHAQj1vI3i1:14319::::::
  ```
- **Keywords:** shadow
- **Notes:** File permission settings are unusually permissive, possibly indicating a configuration error. Further verification of the password hash strength is needed to confirm actual exploitability (e.g., through offline cracking tests). It is recommended to check the permissions of other sensitive files in the system and assess whether IPC or NVRAM interactions could exacerbate this risk.

---
### pptpd-command-injection-unit-ipup-ipdown

- **File/Directory Path:** `bin/pptpd244.sh`
- **Location:** `pptpd244.sh:14-15`
- **Risk Score:** 6.0
- **Confidence:** 8.0
- **Description:** The unit parameter is directly embedded into shell commands when the IPUP and IPDOWN scripts are created, lacking escaping or validation. If the unit contains shell metacharacters (such as semicolons), an attacker can inject arbitrary commands. When the IPUP/IPDOWN scripts are executed (for example, during a PPTP connection event), the injected commands may run with the script's execution privileges (possibly root). Trigger conditions: the attacker can control the unit parameter, the script runs with high privileges, and IPUP/IPDOWN is triggered. Exploitation method: set unit to a value like '0; malicious_command'.
- **Code Snippet:**
  ```
  echo "cfm Post netctrl $up &" >> $IPUP
  echo "cfm Post netctrl $down &" >> $IPDOWN
  ```
- **Keywords:** unit, pptp_server, cfm, netctrl
- **Notes:** Need to verify how the script is called (for example, via network interface or IPC) and its execution privileges. It is recommended to analyze the caller (such as the cfm or netctrl components) to confirm the entry point and data flow.

---
### pptpd-path-traversal-unit-options

- **File/Directory Path:** `bin/pptpd244.sh`
- **Location:** `pptpd244.sh:9-11`
- **Risk Score:** 5.5
- **Confidence:** 7.5
- **Description:** The unit parameter is used to construct file paths (such as /etc/ppp/options$unit.pptpd), but lacks path traversal checks. If the unit contains '../' sequences, an attacker can create or overwrite arbitrary files, leading to privilege escalation or denial of service. Trigger condition: the attacker controls the unit parameter, and the script has write permissions. Exploitation method: set unit to '../../../tmp/evil' to point to a system file.
- **Code Snippet:**
  ```
  confile=/etc/ppp/options$unit.pptpd
  IPUP=/etc/ppp/ip-up$unit
  IPDOWN=/etc/ppp/ip-down$unit
  ```
- **Keywords:** unit, /etc/ppp/options, /etc/ppp/ip-up, /etc/ppp/ip-down
- **Notes:** The file path uses an absolute directory, but the controllable unit may bypass the intended path. It is necessary to confirm the script's execution permissions and the target file system structure.

---
### DoS-sym._ctf_ipc_add

- **File/Directory Path:** `lib/modules/fastnat.ko`
- **Location:** `fastnat.ko:0x08000ea0 sym._ctf_ipc_add`
- **Risk Score:** 5.0
- **Confidence:** 8.0
- **Description:** If param_1 is 0 or param_2 is NULL, the function enters an infinite loop, causing a denial of service. An attacker can call the function by passing invalid parameters to consume CPU resources. The trigger condition is simple, but it cannot be used for code execution.
- **Code Snippet:**
  ```
  if ((param_1 == 0) || (param_2 == NULL)) {
      do { /* infinite loop */ } while(true);
  }
  ```
- **Keywords:** param_1, param_2
- **Notes:** Easy to trigger, but impact is limited. Need to confirm if the function is exposed through a user space interface.

---
### heap-buffer-overflow-fcn.0000c8c8-fcn.0000c9f8

- **File/Directory Path:** `bin/vsftpd`
- **Location:** `vsftpd:0xc9a4 fcn.0000c8c8, vsftpd:0xcad4 fcn.0000c9f8`
- **Risk Score:** 5.0
- **Confidence:** 6.0
- **Description:** A fixed-size heap buffer overflow vulnerability was discovered in functions fcn.0000c8c8 and fcn.0000c9f8. These functions use 'strcpy' to copy data returned from 'nvram_xfr' into fixed-size heap buffers (0x800 bytes). If the data returned by NVRAM exceeds 0x800 bytes, it causes a heap buffer overflow. An attacker may trigger this vulnerability by indirectly controlling NVRAM content (for example, through other services or configuration modifications), but direct exploitation may be limited as a non-root user. Vulnerability trigger conditions include: NVRAM data being maliciously modified, and vsftpd accessing that data. Potential exploitation methods include heap overflow leading to code execution or denial of service.
- **Code Snippet:**
  ```
  if (*(puVar4 + -8) == 0) {
      sym.imp.free(*(iVar3 + *0xc9e4));
      uVar1 = 0;
  } else {
      sym.imp.strcpy(*(iVar3 + *0xc9e4), *(puVar4 + -8));
      uVar1 = *(iVar3 + *0xc9e4);
  }
  ```
- **Keywords:** NVRAM variables via nvram_xfr calls, Environment variables or configuration files
- **Notes:** The exploitability of these vulnerabilities depends on the attacker's ability to control NVRAM, which may be difficult to directly exploit in non-root user scenarios. It is recommended to check NVRAM setting permissions and interactions with other components. Related functions include nvram_xfr call points.

---
### pptpd-config-injection-dns-parameters

- **File/Directory Path:** `bin/pptpd244.sh`
- **Location:** `pptpd244.sh:44-45`
- **Risk Score:** 3.0
- **Confidence:** 6.0
- **Description:** Parameters dns1 and dns2 are directly written to the configuration file, lacking input validation. If the values contain newline characters or special characters, additional configuration items may be injected, but the risk is low because the configuration file is likely parsed by pppd rather than directly executed. Trigger condition: attacker controls dns1/dns2 parameters. Exploitation method: set dns1 to '8.8.8.8\nmalicious_config' to attempt configuration injection.
- **Code Snippet:**
  ```
  echo ms-dns $dns1 >> $confile
  echo ms-dns $dns2 >> $confile
  ```
- **Keywords:** dns1, dns2, ms-dns
- **Notes:** pppd configuration parsing may ignore invalid input, but it is recommended to check if the pppd version has parsing vulnerabilities. Low risk unless interacting with other components.

---
### DoS-sym._ctf_proc_write_enable

- **File/Directory Path:** `lib/modules/fastnat.ko`
- **Location:** `fastnat.ko:0x08001304 sym._ctf_proc_write_enable`
- **Risk Score:** 2.0
- **Confidence:** 8.0
- **Description:** When the function handles write operations for the proc filesystem, if the input size exceeds 4096 bytes or memory allocation fails, it enters an infinite loop, causing a denial of service. An attacker, as an authenticated user, can consume CPU resources and render the device unavailable by writing to the /proc/enable file and triggering the error path (e.g., by providing overly large input). The trigger condition is simple, but it cannot be used for code execution or privilege escalation.
- **Code Snippet:**
  ```
  if (0x1000 < param_3) {
      do { /* infinite loop */ } while(true);
  }
  iVar1 = __kmalloc(param_3 + 1, 0x20);
  if (iVar1 == NULL) {
      do { /* infinite loop */ } while(true);
  }
  ```
- **Keywords:** proc filesystem: /proc/enable
- **Notes:** This vulnerability is easy to trigger but has limited impact. It is recommended to monitor access control for the proc filesystem. No other associated files or functions.

---
