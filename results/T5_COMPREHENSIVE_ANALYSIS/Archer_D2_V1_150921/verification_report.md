# Archer_D2_V1_150921 - Verification Report (3 findings)

---

## Original Information

- **File/Directory Path:** `usr/bin/upnpd`
- **Location:** `bin/upnpd:0x4032ec (fcn.00403afc) and 0x4075b4 (fcn.004075a4)`
- **Description:** A command injection vulnerability exists in the upnpd service's handling of UPnP AddPortMapping requests. The service uses unsanitized user input from the NewInternalClient parameter when constructing iptables commands via snprintf, which are then executed via system(). An attacker with valid login credentials (and thus network access) can send a malicious UPnP request with a crafted NewInternalClient value containing shell metacharacters (e.g., semicolons or backticks) to break out of the iptables command and execute arbitrary commands. The upnpd service typically runs as root, allowing privilege escalation. The vulnerability is triggered when processing message type 0x804 (AddPortMapping) in the main event loop.
- **Code Snippet:**
  ```
  // From fcn.00403afc (AddPortMapping handler)
  // Build iptables command using snprintf with user input
  snprintf(command, size, "%s -t nat -A %s -d %s -p %s --dport %s -j DNAT --to %s:%s", iptables_path, chain, external_ip, protocol, external_port, internal_client, internal_port);
  // Then call system wrapper function
  fcn.004075a4(command);
  
  // From fcn.004075a4 (system wrapper)
  system(command); // Direct execution without sanitization
  ```
- **Notes:** This vulnerability requires the upnpd service to be running and accessible to the attacker. The service is often enabled by default on routers and IoT devices. The attack can be performed remotely if the UPnP service is exposed to the network. Additional validation of the NewInternalClient parameter is needed to prevent command injection. Consider also checking other parameters like NewExternalPort and NewProtocol for similar issues.

## Verification Conclusion

- **Description Accuracy:** `accurate`
- **Is Real Vulnerability:** `True`
- **Risk Level:** `High`
- **Detailed Reason:** The vulnerability is verified through code analysis:
- fcn.004075a4 is a system wrapper that executes commands via system() without sanitization.
- A function (fcn.00407d34) constructs an iptables command using snprintf with user-controlled input from the 'NewInternalClient' parameter in AddPortMapping requests.
- The user input is not properly sanitized, allowing command injection via shell metacharacters (e.g., semicolons or backticks).
- The path is reachable: an authenticated remote attacker (with valid login credentials) can send a UPnP AddPortMapping request to trigger the vulnerability.
- The upnpd service runs as root, enabling privilege escalation.

Exploitation PoC:
An attacker can send a crafted UPnP AddPortMapping request with a NewInternalClient value like '192.168.1.100; malicious_command #'. This breaks out of the iptables command and executes arbitrary commands with root privileges. For example:
- Craft a UPnP SOAP request with NewInternalClient set to '192.168.1.100; touch /tmp/pwned #'.
- The snprintf constructs: 'iptables -t nat -A CHAIN -d EXTERNAL_IP -p PROTO --dport EXTERNAL_PORT -j DNAT --to 192.168.1.100; touch /tmp/pwned #:INTERNAL_PORT'.
- system() executes this, running the malicious command 'touch /tmp/pwned' as root.

This confirms a full attack chain from input control to command execution.

## Verification Metrics

- **Verification Duration:** 326.98 s
- **Token Usage:** 629675

---

## Original Information

- **File/Directory Path:** `usr/bin/vsftpd`
- **Location:** `Multiple locations in the binary, including command handling functions`
- **Description:** Vsftpd version 2.3.2 contains a known backdoor vulnerability that allows remote code execution. When a user sends a USER command containing the sequence ':)' followed by a specific sequence, the server opens a backdoor on port 6200/tcp. This backdoor provides root access to the system. The vulnerability is triggerable by any authenticated user, including non-root users with valid login credentials. The backdoor is hardcoded in the binary and can be exploited without additional privileges.
- **Code Snippet:**
  ```
  Evidence from strings and known exploits: The backdoor is activated by sending 'USER :)' or similar sequences. The binary contains code that listens on port 6200 when triggered.
  ```
- **Notes:** This is a well-documented backdoor in vsftpd 2.3.2. Exploitation tools and scripts are publicly available. The vulnerability allows full system compromise. Immediate patching or removal of this version is recommended.

## Verification Conclusion

- **Description Accuracy:** `inaccurate`
- **Is Real Vulnerability:** `False`
- **Risk Level:** `Low`
- **Detailed Reason:** Based on evidence-driven analysis of the usr/bin/vsftpd binary file: 1) String and hexadecimal searches found no evidence of the ':)' sequence or port 6200 (0x1838); 2) Decompiled code of the USER command handling functions (fcn.00403230 and fcn.00405d1c) shows normal authentication logic, with no backdoor trigger conditions; 3) No socket/bind/listen calls point to port 6200. The attacker model (remote attacker sending USER commands) confirms input control and path accessibility, but there is no complete propagation path or actual evidence of root access. Therefore, the alert description is inaccurate, and the vulnerability does not exist.

## Verification Metrics

- **Verification Duration:** 375.36 s
- **Token Usage:** 732724

---

## Original Information

- **File/Directory Path:** `usr/bin/dropbearmulti`
- **Location:** `File: dropbearmulti:0x41336c Function fcn.004132c4`
- **Description:** In function fcn.004132c4, at address 0x41336c, the system function is called, executing the command string passed via register a0 (set to s0). If s0 contains unvalidated user input (e.g., from an SSH session), it may lead to a command injection vulnerability. An attacker could inject arbitrary commands to achieve privilege escalation or remote code execution. The trigger condition includes a user sending crafted data via an SSH connection.
- **Code Snippet:**
  ```
  Disassembly code: 0x0041336c jal sym.imp.system ; int system(const char *string)
  0x00413370 move a0, s0
  ```
- **Notes:** Dynamic testing is recommended to verify input points; other dangerous functions (such as strcpy) may have additional vulnerabilities, but this analysis focuses on the system call.

## Verification Conclusion

- **Description Accuracy:** `inaccurate`
- **Is Real Vulnerability:** `False`
- **Risk Level:** `N/A`
- **Detailed Reason:** The security alert claims that the system function is called at address 0x41336c in function fcn.004132c4, and s0 may contain unvalidated user input, leading to command injection. However, based on evidence analysis:
- The disassembly shows that function fcn.004132c4 only contains memory initialization operations and ends with a jump to fcn.00412e1c, which is a memory cleanup function and does not call system.
- Address 0x0041336c is identified as the independent function fcn.0041336c, but the code only contains the system call and stack restoration, with no clear data flow showing s0 originates from user input.
- The call graph shows fcn.004132c4 is called by fcn.004160b4, but the network operations in fcn.004160b4 (such as accept, strlen) are not directly linked to the setting of s0.
- The attacker model is an SSH user (unauthenticated or authenticated), but the evidence cannot confirm that s0 is controllable or the path is reachable. Therefore, the vulnerability is not exploitable, and the alert description is inaccurate.

## Verification Metrics

- **Verification Duration:** 544.48 s
- **Token Usage:** 767979

---

