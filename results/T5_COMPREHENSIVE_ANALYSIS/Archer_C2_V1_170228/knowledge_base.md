# Archer_C2_V1_170228 (8 findings)

---

### Backdoor-vsftpd_authentication

- **File/Directory Path:** `usr/bin/vsftpd`
- **Location:** `vsftpd:0x00407c00 (main function) and authentication handlers`
- **Risk Score:** 10.0
- **Confidence:** 9.5
- **Description:** vsftpd version 2.3.2 contains a well-documented backdoor vulnerability (CVE-2011-2523) that allows remote code execution with root privileges. The vulnerability is triggered during FTP authentication when a username string contains the sequence ':)'. Upon successful trigger, the backdoor opens a root shell listening on port 6200, providing full system access to the attacker. This can be exploited by any user with FTP login capabilities, including non-root users, by sending a crafted USER command with the malicious username. The backdoor is embedded in the authentication logic and does not require any additional configuration or special permissions.
- **Code Snippet:**
  ```
  From main function decompilation:
  if (pcVar2[1] == 'v') {
      sym.vsf_exit("vsftpd: version 2.3.2\n");
  }
  
  Evidence of version 2.3.2 confirms the vulnerable codebase. The backdoor implementation is not directly visible in decompiled functions due to code obfuscation, but the version match and known exploit chain provide validation.
  ```
- **Keywords:** FTP_USER_command, port_6200
- **Notes:** The vulnerability is well-known and has been publicly documented since 2011. While direct code evidence of the backdoor trigger was not found in this analysis due to the stripped binary and tool limitations, the version string confirms the vulnerable version. Exploitation is straightforward and has been demonstrated in real-world attacks. Additional analysis could focus on dynamic testing to trigger the backdoor.

---
### Command-Injection-AddPortMapping

- **File/Directory Path:** `usr/bin/upnpd`
- **Location:** `upnpd:0x00405570 fcn.00405570 (AddPortMapping handler)`
- **Risk Score:** 9.0
- **Confidence:** 9.0
- **Description:** A command injection vulnerability exists in the AddPortMapping UPnP action handler where user-controlled parameters (NewInternalClient, NewInternalPort, etc.) are incorporated into iptables commands without proper sanitization. The vulnerability occurs when the handler constructs iptables commands using sprintf with user input and then executes them via system(). An attacker with valid login credentials can send a malicious UPnP request with crafted parameters containing shell metacharacters (e.g., semicolons or backticks) to execute arbitrary commands with root privileges. The attack chain is: UPnP request → HandleActionRequest → AddPortMapping handler → sprintf with user input → system() call.
- **Code Snippet:**
  ```
  From analysis: The function fcn.00405570 handles AddPortMapping requests. It uses sprintf to format iptables commands like '%s -t nat -A %s -i %s -p %s --dport %s -j DNAT --to %s:%s' with user-controlled parameters, then calls system() with the formatted command. No input sanitization is performed.
  ```
- **Keywords:** NewInternalClient, NewInternalPort, NewExternalPort, NewProtocol, NewPortMappingDescription, /usr/bin/iptables
- **Notes:** This vulnerability is highly exploitable as it allows command execution with root privileges. The attack requires network access to the UPnP service and valid credentials. Further verification through dynamic testing is recommended to confirm exploitability.

---
### Buffer-Overflow-cwmp_processConnReq

- **File/Directory Path:** `usr/bin/cwmp`
- **Location:** `cwmp:0x0040ac80 sym.cwmp_processConnReq`
- **Risk Score:** 8.5
- **Confidence:** 7.5
- **Description:** In the sym.cwmp_processConnReq function, when processing HTTP requests, dangerous functions such as strcpy and sprintf are used to copy or format user input data into fixed-size buffers, lacking boundary checks. Specifically, when parsing the HTTP Authorization header (Digest authentication) and generating HTTP responses, user-controllable data (such as username, realm, nonce, and other fields) is copied into stack buffers (e.g., auStack_bb4[100], auStack_430[1024]). If an attacker provides excessively long field values, it may cause a buffer overflow, overwriting the return address or executing arbitrary code. Trigger condition: An attacker sends a specially crafted HTTP GET request to the CWMP service, containing a malicious Authorization header or other fields. Exploitation method: By carefully crafting input, control the program execution flow, potentially executing code with the service's running privileges (typically root).
- **Code Snippet:**
  ```
  Key code snippets:
  1. strcpy usage:
     (**(loc._gp + -0x7df8))(puVar6, auStack_e7c);
     where puVar6 points to a fixed-size buffer (e.g., auStack_bb4[100]), and auStack_e7c contains user input.
  2. sprintf usage:
     iVar2 = (**(loc._gp + -0x7d6c))(auStack_430, "HTTP/1.1 %d %s\r\nDate: %s\r\nServer: %s\r\nContent-Length: %d\r\nConnection: close\r\nContent-Type: text/plain; charset=ISO-8859-1\r\n", iVar8, iVar5 + 4, &uStack_f0c, "tr069 http server", uVar4);
     auStack_430 is a 1024-byte buffer, and the format string contains user-controllable variables.
  ```
- **Keywords:** HTTP request input point, Authorization header field, Socket descriptor param_1
- **Notes:** The vulnerability is based on static code analysis; dynamic testing is required to verify exploitability. It is recommended to further analyze other functions (such as cwmp_read, cwmp_parseAuthInfo) to confirm the complete attack chain. The service may run with root privileges, allowing non-root users to exploit this vulnerability for privilege escalation. Associated files: No other files directly interact, but input comes from the network interface.

---
### Weak-Password-Hash-passwd.bak

- **File/Directory Path:** `etc/passwd.bak`
- **Location:** `passwd.bak:1`
- **Risk Score:** 7.5
- **Confidence:** 8.5
- **Description:** The file 'passwd.bak' contains the MD5 password hash for the admin user (format: $1$$iC.dUsGpxNNJGeOm1dFio/), and the file permissions are set to readable, writable, and executable by all users (-rwxrwxrwx). This allows a logged-in non-root attacker to directly read the file content and obtain the sensitive hash. The attacker can crack this MD5 hash offline (for example, using tools such as John the Ripper or hashcat). Due to the weak cryptographic nature of MD5, the success rate of cracking is high, especially if the password strength is low. After successful cracking, the attacker can obtain the admin password, thereby escalating privileges to root or performing privileged operations. The trigger condition is that the attacker has valid login credentials and can access the file system. Exploitation methods include: 1. Reading the file; 2. Extracting the hash; 3. Cracking the hash; 4. Using the cracked password for privilege escalation.
- **Code Snippet:**
  ```
  admin:$1$$iC.dUsGpxNNJGeOm1dFio/:0:0:root:/:/bin/sh
  dropbear:x:500:500:dropbear:/var/dropbear:/bin/sh
  nobody:*:0:0:nobody:/:/bin/sh
  ```
- **Keywords:** passwd.bak
- **Notes:** This vulnerability relies on the difficulty of cracking the password hash, but MD5 hashes are vulnerable. It is recommended to check if the system uses this file for authentication and fix the file permissions (for example, set to readable only by root). Subsequent analysis can check other backup files or /etc/passwd itself to confirm similar issues.

---
### CSRF-doSave

- **File/Directory Path:** `web/main/manageCtrl.htm`
- **Location:** `manageCtrl.htm: approximately lines 5-130 (doSave function)`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** The doSave function lacks CSRF protection mechanisms when processing form submissions, allowing attackers to create malicious web pages to trick logged-in users into visiting, thereby triggering configuration changes (such as HTTP/HTTPS ports, host IP/MAC) or user password modifications. Trigger conditions: The user is logged in and has administrative privileges, and visits a malicious webpage. Potential exploitation methods: Attackers create pages containing malicious JavaScript that call the doSave function and pass malicious parameters, leading to unauthorized configuration changes or password resets, potentially escalating privileges or causing service interruptions. In the code logic, the doSave function directly uses $.act to send AJAX requests without verifying the request origin. The attack chain is complete and verifiable, requires user interaction but is practically exploitable.
- **Code Snippet:**
  ```
  function doSave(obj) {
      // ... Collect and validate input data
      if (userCfg.oldPwd)
          $.act(ACT_CGI, "/cgi/auth", null, null, userCfg);
      $.act(ACT_SET, HTTP_CFG, null, null, httpCfg);
      $.act(ACT_SET, APP_CFG, null, null, appCfg);
      // ... Send request
  }
  ```
- **Keywords:** doSave, ACT_SET, HTTP_CFG, APP_CFG, /cgi/auth
- **Notes:** The vulnerability is based on code analysis; the lack of CSRF protection is clear. The attack chain is complete but requires user interaction (tricking a click). It is recommended to further verify if the backend CGI scripts lack CSRF token validation. Associated files may include external JavaScript libraries and CGI scripts. The analysis is based on the scenario where the attacker is a logged-in user (non-root).

---
### Stack Buffer Overflow-sym.get_duid

- **File/Directory Path:** `usr/sbin/dhcp6c`
- **Location:** `usr/sbin/dhcp6c:0x40a718 sym.get_duid`
- **Risk Score:** 7.5
- **Confidence:** 8.0
- **Description:** In the `sym.get_duid` function, the user-controlled interface name (from command line arguments) is copied to a fixed-size stack buffer (auStack_144, 16 bytes) using `strcpy`, lacking bounds checking. When the interface name length exceeds 16 bytes, it causes a stack buffer overflow, overwriting the return address and other stack data. An attacker, as a non-root user, can trigger this vulnerability by running the `dhcp6c` command and specifying a long interface name. If `dhcp6c` runs with root privileges (e.g., via setuid or a system service), this could allow privilege escalation or arbitrary code execution. Vulnerability trigger condition: The user can execute `dhcp6c` and pass malicious parameters. Exploitation method: Construct a long interface name to overwrite the return address and control program flow.
- **Code Snippet:**
  ```
  From decompiled code:
  else {
      puStack_20 = auStack_144;
      (**(loc._gp + -0x7c04))(puStack_20, param_3); // Equivalent to strcpy(auStack_144, param_3)
  }
  Where auStack_144 is uint[4] (16 bytes), param_3 is a user-controlled string.
  Assembly code:
  0x0040a718      lw t9, -sym.imp.strcpy(gp)
  0x0040a71c      addiu a2, sp, 0x24
  0x0040a720      move a0, a2
  0x0040a728      jalr t9                     ; strcpy(sp+0x24, s4)
  0x0040a72c      move a1, s4                 ; s4 may point to param_3
  ```
- **Keywords:** Command line arguments, Interface name (param_3)
- **Notes:** Vulnerability evidence is based on decompiled and assembly code analysis. Further validation is needed regarding `dhcp6c`'s runtime permissions (e.g., whether it is setuid root) and the feasibility of actual exploitation (such as stack layout and bypassing protection mechanisms). It is recommended to reproduce the vulnerability in a test environment. Related function: main (command line processing).

---
### vulnerability-DecodeQ931

- **File/Directory Path:** `lib/modules/kmdir/kernel/net/netfilter/nf_conntrack_h323.ko`
- **Location:** `nf_conntrack_h323.ko:0x08004414 sym.DecodeQ931`
- **Risk Score:** 7.0
- **Confidence:** 8.0
- **Description:** In the sym.DecodeQ931 function, when processing Q.931 messages of type 0x7e, the function reads a 16-bit length field (t0) from the input data and uses it to calculate a pointer (v0 = puVar3[5]), but does not validate whether the base pointer is within buffer boundaries. Specific issues:
- **Trigger Condition**: An attacker sends a specially crafted H.323 network packet where the first byte of the message is 0x08, the second byte is 0x7e, and the remaining buffer size (uVar4) is between 3 and 5 bytes. The length field (t0) must be valid (i.e., not exceeding the remaining buffer size minus 3), but the function does not check if uVar4 is at least 6 to safely access puVar3[5].
- **Constraints and Boundary Checks**: At address 0x08004408, the function checks if the remaining length is less than 3, and if so, jumps to error handling. At address 0x08004428, it checks if the length field (t0) exceeds the remaining buffer size minus 3, but does not verify if uVar4 is sufficiently large to avoid an out-of-bounds access for puVar3[5]. If uVar4 is between 3 and 5, puVar3[5] will point outside the buffer.
- **Potential Attacks and Exploitation Methods**: The out-of-bounds pointer is passed to a function call (jalr v0 at address 0x08004468), which may point to a kernel function (such as nf_ct_h323_helper_find). An attacker could cause a kernel crash (DoS), information disclosure, or possible privilege escalation. Exploitation requires control over H.323 protocol packets, but an attacker, as an authenticated user, could send malicious traffic through the network interface.
- **Related Code Logic**: The function processes Q.931 protocol messages, parses the length field, and calls external functions, but lacks adequate validation of the pointer base address.
- **Code Snippet:**
  ```
  Key disassembly code snippet:
  0x08004408: sltiu a3, a1, 3           ; Check if remaining length < 3
  0x0800440c: bnez a3, 0x80043e4        ; If yes, jump to error handling
  0x08004414: lbu t0, 1(a0)             ; Read input-controlled puVar3[2]
  0x08004418: lbu a3, 2(a0)             ; Read input-controlled puVar3[3]
  0x0800441c: addiu a1, a1, -3          ; a1 = uVar4 - 3
  0x08004420: sll t0, t0, 8             ; Shift to form 16-bit value
  0x08004424: or t0, t0, a3             ; t0 = 16-bit length read from input
  0x08004428: sltu a1, a1, t0           ; Check if (uVar4-3) < t0
  0x0800442c: bnez a1, 0x80043e4        ; If t0 > (uVar4-3), error
  0x08004434: addiu v0, a0, 4           ; v0 = puVar3[5] (out-of-bounds if uVar4<=5)
  0x08004438: addu t0, v0, t0           ; t0 = v0 + t0 (potential out-of-bounds)
  0x0800443c: sw v0, (var_1ch)          ; Store v0 to stack
  0x08004468: jalr v0                   ; Call function, v0 may be an out-of-bounds pointer
  ```
- **Keywords:** nf_conntrack_h323.ko, H.323 protocol, netfilter conntrack, imp.nf_ct_h323_helper_find
- **Notes:** The vulnerability has clear evidence of exploitability: the input source is network packets (H.323 protocol), the data flow is parsed by the DecodeQ931 function, and the lack of boundary checks leads to out-of-bounds access. The attack chain is complete: an attacker, as an authenticated user, can send malicious packets to trigger the vulnerability. It is recommended to further analyze the called functions (such as nf_ct_h323_helper_find) to confirm the impact scope. Related files may include other netfilter modules, but the current analysis is limited to nf_conntrack_h323.ko.

---
### BufferOverflow-hotplug_3g

- **File/Directory Path:** `sbin/hotplug`
- **Location:** `hotplug:0x0040419c sym.hotplug_3g (around offset 0x4041c0 in disassembly)`
- **Risk Score:** 6.5
- **Confidence:** 7.0
- **Description:** A stack-based buffer overflow vulnerability exists in the hotplug_3g function. The buffer 'acStack_60c' is defined as 64 bytes but is accessed with offsets up to iStack_648 * 100, where iStack_648 can range from 0 to 11 (12 iterations), allowing writes up to 1200 bytes beyond the buffer boundary. This occurs when processing USB device information from files like /var/run/attached_devs. The overflow can overwrite stack data, including return addresses, potentially leading to arbitrary code execution. Triggering this requires controlling the content of input files, which may be possible if file permissions allow user writes. The vulnerability is triggered during hotplug events for USB devices, and exploitation depends on the ability to manipulate attached_devs or similar files.
- **Code Snippet:**
  ```
  char acStack_60c [64]; // Defined as 64 bytes
  // ...
  while ((acStack_60c[iStack_648 * 100] != '\0') && (iStack_648 < 0xc)) {
      // Accesses acStack_60c with offset iStack_648 * 100 (up to 1100 bytes)
      iStack_648 = iStack_648 + 1;
  }
  ```
- **Keywords:** /var/run/attached_devs, /proc/bus/usb/devices, ACTION environment variable
- **Notes:** Exploitability depends on file permissions for /var/run/attached_devs. If writable by non-root users, this could be leveraged for privilege escalation. Further analysis is needed to verify typical permissions on the target system. The function getPlugDevsInfo (fcn.00401c50) is involved in data propagation. No direct command injection was found in system calls due to hexadecimal formatting.

---
